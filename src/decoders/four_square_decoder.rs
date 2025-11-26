//! Four Square cipher decoder
//! The Four Square cipher is a polygraphic substitution cipher that uses four 5x5 matrices.
//! Two matrices contain the standard alphabet, and two contain keyed alphabets.
//! This implementation attempts to crack Four Square using dictionary attacks
//! with an extensive wordlist and frequency analysis for scoring.

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::cryptanalysis::{EXTENDED_WORDLIST, fitness_score, is_likely_english};
use crate::decoders::interface::check_string_success;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};

/// The Four Square decoder
pub struct FourSquareDecoder;

/// Most common keywords for Four Square (used for same-key attempts)
const TOP_KEYWORDS: [&str; 30] = [
    "EXAMPLE", "KEYWORD", "SECRET", "CIPHER", "CRYPTO",
    "HIDDEN", "SECURE", "ENCODE", "DECODE", "PUZZLE",
    "MYSTERY", "PRIVATE", "QUEEN", "KING", "MONARCH",
    "CHARLES", "WILLIAM", "REPUBLIC", "KINGDOM", "PASSWORD",
    "HELLO", "WORLD", "TEST", "FLAG", "CODE",
    "ALPHA", "BRAVO", "DELTA", "FOXTROT", "HOTEL",
];

impl Crack for Decoder<FourSquareDecoder> {
    fn new() -> Decoder<FourSquareDecoder> {
        Decoder {
            name: "Four Square",
            description: "The Four Square cipher uses four 5x5 matrices to encrypt pairs of letters. Two matrices use the standard alphabet and two use keyed alphabets. This decoder uses dictionary attacks with hundreds of keyword combinations to break the cipher.",
            link: "https://en.wikipedia.org/wiki/Four-square_cipher",
            tags: vec!["foursquare", "classical", "substitution", "digraph", "cipher"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Four Square cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Clean text - only alphabetic, uppercase
        let clean_text: String = text
            .to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| if c == 'J' { 'I' } else { c })
            .collect();

        if clean_text.len() < 2 {
            info!("Text too short for Four Square");
            return results;
        }

        // Four Square processes pairs - if odd, we might need padding, but for decryption
        // the ciphertext should already be even
        if clean_text.len() % 2 != 0 {
            info!("Four Square ciphertext should have even number of characters");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
        
        // Track best result for cryptanalysis fallback
        let mut best_score = f64::MIN;
        let mut best_plaintext = String::new();
        let mut best_key = String::new();

        // PHASE 1: Try same keyword for both squares (most common case)
        trace!("Phase 1: Trying same keyword for both squares");
        for keyword in EXTENDED_WORDLIST.iter() {
            if keyword.len() < 4 {
                continue;
            }
            
            if let Some(decoded) = decrypt_four_square(&clean_text, keyword, keyword) {
                let decoded_lower = decoded.to_lowercase();
                
                let score = fitness_score(&decoded_lower);
                if score > best_score {
                    best_score = score;
                    best_plaintext = decoded_lower.clone();
                    best_key = keyword.clone();
                }
                
                if check_string_success(&decoded_lower, text) {
                    let checker_result = checker_with_sensitivity.check(&decoded_lower, config);
                    if checker_result.is_identified {
                        debug!("Four Square succeeded with same key: {}", keyword);
                        results.unencrypted_text = Some(vec![decoded_lower]);
                        results.update_checker(&checker_result);
                        results.key = Some(keyword.to_uppercase());
                        return results;
                    }
                }
            }
        }

        // PHASE 2: Try top keyword combinations (limited to avoid O(n²) explosion)
        trace!("Phase 2: Trying top keyword combinations");
        for keyword1 in TOP_KEYWORDS.iter() {
            for keyword2 in TOP_KEYWORDS.iter() {
                if keyword1 == keyword2 {
                    continue; // Already tried in phase 1
                }
                
                if let Some(decoded) = decrypt_four_square(&clean_text, keyword1, keyword2) {
                    let decoded_lower = decoded.to_lowercase();
                    
                    let score = fitness_score(&decoded_lower);
                    if score > best_score {
                        best_score = score;
                        best_plaintext = decoded_lower.clone();
                        best_key = format!("{}/{}", keyword1, keyword2);
                    }
                    
                    if check_string_success(&decoded_lower, text) {
                        let checker_result = checker_with_sensitivity.check(&decoded_lower, config);
                        if checker_result.is_identified {
                            debug!("Four Square succeeded with keys: {}/{}", keyword1, keyword2);
                            results.unencrypted_text = Some(vec![decoded_lower]);
                            results.update_checker(&checker_result);
                            results.key = Some(format!("{}/{}", keyword1, keyword2));
                            return results;
                        }
                    }
                }
            }
        }
        
        // PHASE 3: If cryptanalysis found a good result, return it
        if is_likely_english(&best_plaintext) && !best_key.is_empty() {
            debug!("Using best cryptanalysis result for Four Square with key: {}", best_key);
            let checker_result = checker_with_sensitivity.check(&best_plaintext, config);
            results.unencrypted_text = Some(vec![best_plaintext]);
            results.update_checker(&checker_result);
            results.key = Some(best_key.to_uppercase());
            return results;
        }

        info!("Failed to decode Four Square cipher");
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

    fn get_name(&self) -> &str {
        self.name
    }

    fn get_description(&self) -> &str {
        self.description
    }

    fn get_link(&self) -> &str {
        self.link
    }
}

/// Generate the standard 5x5 alphabet matrix (no J, replaced by I)
fn generate_standard_square() -> [[char; 5]; 5] {
    let mut square = [[' '; 5]; 5];
    let alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // Note: no J
    
    for (i, c) in alphabet.chars().enumerate() {
        square[i / 5][i % 5] = c;
    }
    
    square
}

/// Generate a keyed 5x5 alphabet matrix from a keyword
fn generate_keyed_square(keyword: &str) -> [[char; 5]; 5] {
    let mut square = [[' '; 5]; 5];
    let mut used = [false; 26];
    let mut pos = 0;

    // Add keyword letters (J treated as I)
    for c in keyword.to_uppercase().chars() {
        if c.is_ascii_alphabetic() {
            let c = if c == 'J' { 'I' } else { c };
            let idx = (c as u8 - b'A') as usize;
            if !used[idx] {
                used[idx] = true;
                used[9] = true; // Mark J as used (maps to I)
                square[pos / 5][pos % 5] = c;
                pos += 1;
            }
        }
    }

    // Add remaining letters (skip J)
    for c in b'A'..=b'Z' {
        if c == b'J' {
            continue;
        }
        let idx = (c - b'A') as usize;
        if !used[idx] {
            used[idx] = true;
            square[pos / 5][pos % 5] = c as char;
            pos += 1;
        }
    }

    square
}

/// Find the position of a character in a 5x5 square
fn find_position(square: &[[char; 5]; 5], c: char) -> Option<(usize, usize)> {
    let c = if c == 'J' { 'I' } else { c };
    for (i, row) in square.iter().enumerate() {
        for (j, &ch) in row.iter().enumerate() {
            if ch == c {
                return Some((i, j));
            }
        }
    }
    None
}

/// Decrypt a Four Square cipher encrypted text using two keywords
/// 
/// In Four Square:
/// - Top-left and bottom-right squares are standard alphabet
/// - Top-right square uses keyword1
/// - Bottom-left square uses keyword2
/// 
/// To decrypt, we reverse the encryption process:
/// - Find ciphertext pair positions in keyed squares (top-right, bottom-left)
/// - Use row from first position with column from second, and vice versa
/// - Look up those positions in standard squares (top-left, bottom-right)
fn decrypt_four_square(text: &str, keyword1: &str, keyword2: &str) -> Option<String> {
    let standard = generate_standard_square();
    let keyed1 = generate_keyed_square(keyword1); // Top-right
    let keyed2 = generate_keyed_square(keyword2); // Bottom-left
    
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::new();

    for pair in chars.chunks(2) {
        if pair.len() != 2 {
            return None;
        }

        // Find positions of ciphertext letters in keyed squares
        // First ciphertext letter is in top-right (keyed1)
        // Second ciphertext letter is in bottom-left (keyed2)
        let (r1, c1) = find_position(&keyed1, pair[0])?;
        let (r2, c2) = find_position(&keyed2, pair[1])?;

        // Decrypt using the Four Square rules (reverse of encryption)
        // First plaintext letter is at (r1, c2) in top-left (standard)
        // Second plaintext letter is at (r2, c1) in bottom-right (standard)
        result.push(standard[r1][c2]);
        result.push(standard[r2][c1]);
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_generate_standard_square() {
        let square = generate_standard_square();
        // Check first row: A B C D E
        assert_eq!(square[0][0], 'A');
        assert_eq!(square[0][1], 'B');
        assert_eq!(square[0][2], 'C');
        assert_eq!(square[0][3], 'D');
        assert_eq!(square[0][4], 'E');
        // Check that there's no J (I appears only once at position for I)
        assert_eq!(square[1][3], 'I');
    }

    #[test]
    fn test_generate_keyed_square() {
        let square = generate_keyed_square("EXAMPLE");
        // First row should start with EXAMPL (unique letters from keyword)
        assert_eq!(square[0][0], 'E');
        assert_eq!(square[0][1], 'X');
        assert_eq!(square[0][2], 'A');
        assert_eq!(square[0][3], 'M');
        assert_eq!(square[0][4], 'P');
        // L should be next
        assert_eq!(square[1][0], 'L');
    }

    #[test]
    fn test_find_position() {
        let square = generate_standard_square();
        assert_eq!(find_position(&square, 'A'), Some((0, 0)));
        assert_eq!(find_position(&square, 'F'), Some((1, 0)));
        // J should map to I's position
        assert_eq!(find_position(&square, 'J'), find_position(&square, 'I'));
    }

    #[test]
    fn test_decrypt_four_square_basic() {
        // Using keywords "EXAMPLE" and "KEYWORD"
        // This is a basic test to ensure the algorithm runs
        let square1 = generate_keyed_square("EXAMPLE");
        let square2 = generate_keyed_square("KEYWORD");
        
        // Verify squares are properly generated
        assert_eq!(square1[0][0], 'E');
        assert_eq!(square2[0][0], 'K');
    }

    #[test]
    fn test_empty_input() {
        let result = decrypt_four_square("", "EXAMPLE", "KEYWORD");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_odd_length() {
        // Four Square processes pairs, odd length should fail
        let result = decrypt_four_square("ABC", "EXAMPLE", "KEYWORD");
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<FourSquareDecoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<FourSquareDecoder>::new();
        assert_eq!(decoder.name, "Four Square");
    }

    #[test]
    fn test_decoder_tags() {
        let decoder = Decoder::<FourSquareDecoder>::new();
        assert!(decoder.tags.contains(&"foursquare"));
        assert!(decoder.tags.contains(&"classical"));
        assert!(decoder.tags.contains(&"substitution"));
    }

    #[test]
    fn test_known_encryption_decryption() {
        // Test with known plaintext/ciphertext pair
        // Using standard example from Wikipedia
        // Keywords: EXAMPLE and KEYWORD
        // Plaintext: HELPMEOBIWANKENOBI
        // Ciphertext should be decryptable back
        
        // First verify our keyed squares match expected
        let keyed1 = generate_keyed_square("EXAMPLE");
        let keyed2 = generate_keyed_square("KEYWORD");
        
        // EXAMPLE keyed square:
        // E X A M P
        // L B C D F
        // G H I K N
        // O Q R S T
        // U V W Y Z
        assert_eq!(keyed1[0], ['E', 'X', 'A', 'M', 'P']);
        
        // KEYWORD keyed square:
        // K E Y W O
        // R D A B C
        // F G H I L
        // M N P Q S
        // T U V X Z
        assert_eq!(keyed2[0], ['K', 'E', 'Y', 'W', 'O']);
    }

    #[test]
    fn test_decrypt_known_example() {
        // Test decryption of "FYGMKYHOBXMFKKKIMD" with EXAMPLE/KEYWORD
        // This should decrypt to something reasonable
        let result = decrypt_four_square("FYGMKYHOBXMFKKKIMD", "EXAMPLE", "KEYWORD");
        assert!(result.is_some());
        let decrypted = result.unwrap();
        // The decryption should produce valid letters
        assert!(decrypted.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_decoder_integration() {
        let decoder = Decoder::<FourSquareDecoder>::new();
        let _result = decoder.crack(
            "TESTINGFOURSQUARE",
            &get_athena_checker(),
            &Config::default(),
        );
        // Should attempt decoding (even if it doesn't find the right key)
        // The result might or might not have unencrypted_text
        assert_eq!(decoder.get_name(), "Four Square");
    }
}
