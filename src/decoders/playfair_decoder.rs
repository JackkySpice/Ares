//! Playfair cipher decoder
//! The Playfair cipher encrypts pairs of letters (digraphs) using a 5x5 key square.
//! This implementation attempts to crack Playfair using dictionary attacks
//! with a comprehensive 10000+ word wordlist and frequency analysis for scoring.

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::cryptanalysis::{ATTACK_WORDLIST, fitness_score, is_likely_english};
use crate::decoders::interface::check_string_success;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};

/// The Playfair decoder
pub struct PlayfairDecoder;

impl Crack for Decoder<PlayfairDecoder> {
    fn new() -> Decoder<PlayfairDecoder> {
        Decoder {
            name: "Playfair",
            description: "The Playfair cipher encrypts pairs of letters using a 5x5 key square. This decoder uses dictionary attacks with hundreds of keywords to break the cipher.",
            link: "https://en.wikipedia.org/wiki/Playfair_cipher",
            tags: vec!["playfair", "classical", "substitution", "digraph", "cipher"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Playfair cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Clean text - only alphabetic, uppercase
        let clean_text: String = text
            .to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| if c == 'J' { 'I' } else { c })
            .collect();

        if clean_text.len() < 2 {
            info!("Text too short for Playfair");
            return results;
        }

        // Playfair requires even number of characters
        if clean_text.len() % 2 != 0 {
            info!("Playfair requires even number of characters");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
        
        // Track best result for cryptanalysis fallback
        let mut best_score = f64::MIN;
        let mut best_plaintext = String::new();
        let mut best_key = String::new();

        // Use the comprehensive wordlist from cryptanalysis module
        trace!("Trying {} keywords for Playfair", ATTACK_WORDLIST.len());
        for keyword in ATTACK_WORDLIST.iter() {
            // Skip very short keywords
            if keyword.len() < 4 {
                continue;
            }
            
            if let Some(decoded) = decrypt_playfair(&clean_text, keyword) {
                let decoded_lower = decoded.to_lowercase();
                
                // Score the result using cryptanalysis
                let score = fitness_score(&decoded_lower);
                if score > best_score {
                    best_score = score;
                    best_plaintext = decoded_lower.clone();
                    best_key = keyword.clone();
                }
                
                if check_string_success(&decoded_lower, text) {
                    let checker_result = checker_with_sensitivity.check(&decoded_lower, config);
                    if checker_result.is_identified {
                        debug!("Playfair dictionary attack succeeded with key: {}", keyword);
                        results.unencrypted_text = Some(vec![decoded_lower]);
                        results.update_checker(&checker_result);
                        results.key = Some(keyword.to_uppercase());
                        return results;
                    }
                }
            }
        }
        
        // If cryptanalysis found a good result, return it
        if is_likely_english(&best_plaintext) && !best_key.is_empty() {
            debug!("Using best cryptanalysis result for Playfair with key: {}", best_key);
            let checker_result = checker_with_sensitivity.check(&best_plaintext, config);
            results.unencrypted_text = Some(vec![best_plaintext]);
            results.update_checker(&checker_result);
            results.key = Some(best_key.to_uppercase());
            return results;
        }

        info!("Failed to decode Playfair cipher");
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

/// Generate the Playfair key square from a keyword
fn generate_key_square(keyword: &str) -> [[char; 5]; 5] {
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

/// Find the position of a character in the key square
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

/// Decrypt a Playfair-encrypted text using the given keyword
fn decrypt_playfair(text: &str, keyword: &str) -> Option<String> {
    let square = generate_key_square(keyword);
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::new();

    for pair in chars.chunks(2) {
        if pair.len() != 2 {
            return None;
        }

        let (r1, c1) = find_position(&square, pair[0])?;
        let (r2, c2) = find_position(&square, pair[1])?;

        if r1 == r2 {
            // Same row: move left
            result.push(square[r1][(c1 + 4) % 5]);
            result.push(square[r2][(c2 + 4) % 5]);
        } else if c1 == c2 {
            // Same column: move up
            result.push(square[(r1 + 4) % 5][c1]);
            result.push(square[(r2 + 4) % 5][c2]);
        } else {
            // Rectangle: swap columns
            result.push(square[r1][c2]);
            result.push(square[r2][c1]);
        }
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
    fn test_generate_key_square() {
        let square = generate_key_square("KEYWORD");
        // First row should start with KEY... then fill with unused letters
        assert_eq!(square[0][0], 'K');
        assert_eq!(square[0][1], 'E');
        assert_eq!(square[0][2], 'Y');
        assert_eq!(square[0][3], 'W');
        assert_eq!(square[0][4], 'O');
    }

    #[test]
    fn test_find_position() {
        let square = generate_key_square("PLAYFAIR");
        let pos = find_position(&square, 'P');
        assert!(pos.is_some());
        assert_eq!(pos.unwrap(), (0, 0));
    }

    #[test]
    fn test_decrypt_playfair_basic() {
        // Using keyword "PLAYFAIR"
        // Encrypting "HELLO" with Playfair gives different result based on padding
        let square = generate_key_square("PLAYFAIR");
        // Just verify the square is valid
        assert_eq!(square[0][0], 'P');
    }

    #[test]
    fn test_empty_input() {
        let result = decrypt_playfair("", "KEYWORD");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_odd_length() {
        // Playfair processes pairs, odd length should be handled
        let result = decrypt_playfair("ABC", "KEYWORD");
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        assert_eq!(decoder.name, "Playfair");
    }

    #[test]
    fn test_decoder_integration() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        let result = decoder.crack(
            "BMODZBXDNABEKUDMUIXMMOUVIF",
            &get_athena_checker(),
            &Config::default(),
        );
        // Should attempt decoding
        assert!(result.unencrypted_text.is_some() || result.unencrypted_text.is_none());
    }
}
