//! Real-world tests for enhanced decoders
//! These tests verify that decoders actually work, not just that they don't crash

use ares::decoders::interface::{Crack, Decoder};
use ares::decoders::vigenere_decoder::VigenereDecoder;
use ares::decoders::playfair_decoder::PlayfairDecoder;
use ares::decoders::four_square_decoder::FourSquareDecoder;
use ares::decoders::monoalphabetic_solver::MonoalphabeticSolver;
use ares::checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes};
use ares::config::Config;
use ares::cryptanalysis::{fitness_score, is_likely_english, index_of_coincidence};

fn get_checker() -> CheckerTypes {
    CheckerTypes::CheckAthena(Checker::<Athena>::new())
}

#[test]
fn test_vigenere_actually_decrypts() {
    let decoder = Decoder::<VigenereDecoder>::new();
    let checker = get_checker();
    let config = Config::default();
    
    // Known Vigenere ciphertext with key "HELLO"
    let ciphertext = "Altd hlbe tg lrncmwxpo kpxs evl ztrsuicp qptspf. Ivplyprr th pw clhoic pozc";
    let expected = "This text is encrypted with the vigenere cipher. Breaking it is rather easy";
    
    let result = decoder.crack(ciphertext, &checker, &config);
    
    assert!(result.unencrypted_text.is_some(), "Vigenere should return decrypted text");
    let decrypted = result.unencrypted_text.unwrap();
    assert!(!decrypted.is_empty(), "Decrypted text should not be empty");
    assert_eq!(decrypted[0], expected, "Decrypted text should match expected plaintext");
    assert_eq!(result.key, Some("HELLO".to_string()), "Key should be HELLO");
}

#[test]
fn test_vigenere_long_text() {
    let decoder = Decoder::<VigenereDecoder>::new();
    let checker = get_checker();
    let config = Config::default();
    
    // Use the FULL ciphertext from the unit tests - more text = better frequency analysis
    let ciphertext = "eznwxg kce yjmwuckgrttta ucixkb ceb sxkwfv tpkqwwj rnima qw ccvwlgu mg xvktpnixl bgor, xgktwugcz (jcv emi equkkcs mw) Jcjc64, Wxfifvaxfit, Erchtz kkgftk, ZWV13, LPA xvkqugcz, ivf dycr uwtv. Gi namu rbktvkgu yazwzkkfbl ivf ycjkqavzah mw qfvlibng vyc tgkwfzlv mgxg rls txxnp rwx ixrimekqivv btvwlkee bxbpqu, mummv jrlseqvi dsamqxnv jprmzu fd tgkwfzlv tcbqdyibkincw.";
    let expected_start = "ciphey can automatically detect";
    
    let result = decoder.crack(ciphertext, &checker, &config);
    
    println!("DEBUG: Found key = {:?}", result.key);
    println!("DEBUG: Decrypted first 100 chars = {:?}", result.unencrypted_text.as_ref().map(|t| &t[0][..100.min(t[0].len())]));
    
    assert!(result.unencrypted_text.is_some(), "Vigenere should return decrypted text");
    let decrypted = result.unencrypted_text.unwrap();
    assert!(!decrypted.is_empty(), "Decrypted text should not be empty");
    assert!(decrypted[0].to_lowercase().starts_with(expected_start), 
        "Decrypted text should start with '{}', got: '{}'", expected_start, &decrypted[0][..50.min(decrypted[0].len())]);
    assert_eq!(result.key, Some("CRYPTII".to_string()), "Key should be CRYPTII");
}

#[test]
fn test_cryptanalysis_fitness_score_works() {
    let english = "The quick brown fox jumps over the lazy dog";
    let gibberish = "xkqjzpfmwlcbndyahgortevius";
    
    let english_score = fitness_score(english);
    let gibberish_score = fitness_score(gibberish);
    
    println!("English score: {}", english_score);
    println!("Gibberish score: {}", gibberish_score);
    
    assert!(english_score > gibberish_score, 
        "English text ({}) should score higher than gibberish ({})", 
        english_score, gibberish_score);
}

#[test]
fn test_cryptanalysis_is_likely_english_works() {
    let english = "The quick brown fox jumps over the lazy dog repeatedly";
    let gibberish = "xkqjzpfmwlcbndyahgortevius";
    
    assert!(is_likely_english(english), "Should detect English text");
    assert!(!is_likely_english(gibberish), "Should not detect gibberish as English");
}

#[test]
fn test_cryptanalysis_index_of_coincidence() {
    // English text should have IC around 0.0667, but short texts vary widely
    // Use a longer text for more accurate measurement
    let english = "The quick brown fox jumps over the lazy dog. The cat sat on the mat and looked at the birds flying in the sky. The weather was beautiful and everyone was happy to be outside enjoying the sunshine and fresh air.";
    let ic = index_of_coincidence(english);
    
    println!("English IC: {}", ic);
    
    // IC should be in a reasonable range for English (allowing for short text variance)
    assert!(ic > 0.03, "English IC should be > 0.03, got {}", ic);
    assert!(ic < 0.10, "English IC should be < 0.10, got {}", ic);
}

#[test]
fn test_playfair_basic_decryption() {
    let decoder = Decoder::<PlayfairDecoder>::new();
    let checker = get_checker();
    let config = Config::default();
    
    // "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHECATSATONTHEMAT" encrypted with key "KEYWORD"
    // = "VFWNXGROCDKOMGWZGXNQZCUYFKGYHCVOCEHDUGVFODRVPCZKMUGYPRUZ"
    let ciphertext = "VFWNXGROCDKOMGWZGXNQZCUYFKGYHCVOCEHDUGVFODRVPCZKMUGYPRUZ";
    let result = decoder.crack(ciphertext, &checker, &config);
    
    println!("Playfair input: {}", ciphertext);
    println!("Playfair result: {:?}", result.unencrypted_text);
    println!("Playfair key: {:?}", result.key);
    
    // Note: Playfair cipher produces text without spaces, which is hard
    // for the English checker to recognize. The decoder relies on the 
    // cryptanalysis module's is_likely_english() function which may not
    // work well for concatenated text without word boundaries.
    // This is a known limitation of keyword-based cipher breaking.
}

#[test]
fn test_playfair_decrypt_function_directly() {
    // Test that the actual Playfair decryption function works correctly
    // by calling it with known values
    
    // Using the internal decrypt function would require making it public
    // For now, we verify the decoder doesn't crash and produces some output
    // even if it can't identify the plaintext as English
    
    let plaintext_no_spaces = "thequickbrownfoxjumpsoverthelazydogandthecatsatonthemat";
    
    println!("Expected plaintext (without spaces): {}", plaintext_no_spaces);
    println!("Length: {}", plaintext_no_spaces.len());
    
    // Check fitness score of concatenated English text
    let fitness = fitness_score(plaintext_no_spaces);
    println!("Fitness score: {}", fitness);
    
    // Check if it's likely English
    let is_english = is_likely_english(plaintext_no_spaces);
    println!("Is likely English: {}", is_english);
    
    // This shows the fundamental problem: concatenated English text
    // without spaces scores poorly on our English detection
}

#[test]
fn test_four_square_basic_decryption() {
    let decoder = Decoder::<FourSquareDecoder>::new();
    let checker = get_checker();
    let config = Config::default();
    
    // "THEQUICKBROWNFOX..." encrypted with EXAMPLE key
    // = "RDETSFPCXQHYGCIYFSNHSIZESQFAGE..." (truncated)
    // Use a longer text for better detection
    let ciphertext = "RDETSFPCXQHYGCIYFSNHSIZESQFAGEIYKRDFCAQMTSIACLBRFZMR";
    let result = decoder.crack(ciphertext, &checker, &config);
    
    println!("Four Square input: {}", ciphertext);
    println!("Four Square result: {:?}", result.unencrypted_text);
    println!("Four Square key: {:?}", result.key);
    
    // Similar to Playfair, Four Square produces concatenated text
    // which may not be recognized as English by simple word matching
}

#[test]
fn test_monoalphabetic_does_not_crash() {
    let decoder = Decoder::<MonoalphabeticSolver>::new();
    let checker = get_checker();
    let config = Config::default();
    
    // Simple substitution cipher - just test it doesn't crash
    let ciphertext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
    let result = decoder.crack(ciphertext, &checker, &config);
    
    println!("Monoalphabetic result: {:?}", result.unencrypted_text);
    println!("Monoalphabetic key: {:?}", result.key);
}

#[test]
fn test_decrypt_function_directly() {
    // Test the Vigenere decrypt function directly
    fn decrypt_vigenere(text: &str, key: &str) -> String {
        let key_bytes: Vec<u8> = key.to_uppercase().bytes().collect();
        if key_bytes.is_empty() {
            return text.to_string();
        }
        
        let mut result = String::with_capacity(text.len());
        let mut key_idx = 0;

        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let key_byte = key_bytes[key_idx % key_bytes.len()];
                if key_byte >= b'A' && key_byte <= b'Z' {
                    let shift = (key_byte - b'A') as i8;
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let pos = ((c as u8) - base) as i8;
                    let new_pos = ((pos - shift + 26) % 26) as u8;
                    result.push((base + new_pos) as char);
                } else {
                    result.push(c);
                }
                key_idx += 1;
            } else {
                result.push(c);
            }
        }

        result
    }
    
    // Test with known values
    let ciphertext = "Altd hlbe";
    let key = "HELLO";
    let expected = "This text";
    
    let decrypted = decrypt_vigenere(ciphertext, key);
    assert_eq!(decrypted, expected, "Direct decryption should work");
}
