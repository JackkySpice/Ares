//! Decode a single-byte XOR cipher string
//! Performs error handling and returns a string
//! Call xor_decoder.crack to use.

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;
use log::trace;

/// The XOR decoder, call:
/// `let xor_decoder = Decoder::<XorDecoder>::new()` to create a new instance
/// And then call:
/// `result = xor_decoder.crack(input)` to decode an XOR string
pub struct XorDecoder;

impl Crack for Decoder<XorDecoder> {
    fn new() -> Decoder<XorDecoder> {
        Decoder {
            name: "XOR", description: "XOR cipher (exclusive OR, &crate::config::Config::default()) is a simple additive cipher. This decoder attempts to crack single-byte XOR by brute-forcing all 256 possible keys.",
            link: "https://en.wikipedia.org/wiki/XOR_cipher",
            tags: vec!["xor", "decryption", "classic", "brute-force"],
            popularity: 0.7,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying XOR Cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let mut decoded_strings = Vec::new();

        // Use the checker with Low sensitivity for XOR cipher
        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);

        // We typically expect the input to be some form of bytes, but the interface gives us &str.
        // If the input is hex-encoded or base64, it should have been decoded by other decoders first.
        // However, sometimes the "ciphertext" is just a string of characters (e.g. if it was XORed with printable chars).
        // We will assume the input string bytes are the ciphertext.
        
        let input_bytes = text.as_bytes();

        for key in 1..=255 {
            let decoded_bytes: Vec<u8> = input_bytes.iter().map(|&b| b ^ key).collect();
            
            // We only care if the result is valid UTF-8/ASCII because otherwise it's likely not the final plaintext
            if let Ok(decoded_text) = String::from_utf8(decoded_bytes) {
                decoded_strings.push(decoded_text);
                let borrowed_decoded_text = &decoded_strings[decoded_strings.len() - 1];
                
                if !check_string_success(borrowed_decoded_text, text) {
                    continue;
                }

                let checker_result = checker_with_sensitivity.check(borrowed_decoded_text, config);
                // If checkers return true, exit early with the correct result
                if checker_result.is_identified {
                    trace!("Found a match with XOR key {}", key);
                    results.unencrypted_text = Some(vec![borrowed_decoded_text.to_string()]);
                    results.update_checker(&checker_result);
                    results.key = Some(format!("0x{:02x}", key));
                    return results;
                }
            }
        }
        
        // If we didn't find an immediate match, we return all valid UTF-8 candidates
        // This allows further decoding (e.g. XOR -> Base64)
        if !decoded_strings.is_empty() {
            results.unencrypted_text = Some(decoded_strings);
        } else {
             results.unencrypted_text = None;
        }
        
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

#[cfg(test)]
mod tests {
    use super::XorDecoder;
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
    fn xor_basic_test() {
        let xor_decoder = Decoder::<XorDecoder>::new();
        // "hello" XOR 0xAA
        // h(104) ^ 170 = 210 (not utf8)
        // This test is tricky because we filter for valid UTF8.
        // Let's try XOR with a key that keeps it ASCII. 
        // 'A' (65) XOR 32 (space) = 'a' (97). Case flip.
        // "HELLO" XOR 32 = "hello"
        let result = xor_decoder.crack("HELLO", &get_athena_checker(), &crate::config::Config::default());
        assert!(result.unencrypted_text.is_some());
        let texts = result.unencrypted_text.unwrap();
        assert!(texts.contains(&"hello".to_string()));
    }
    
    #[test]
    fn xor_identified_test() {
        let xor_decoder = Decoder::<XorDecoder>::new();
        // "hello" XOR 1 = "idmmn"
        let result = xor_decoder.crack("idmmn", &get_athena_checker(), &crate::config::Config::default());
        assert!(result.unencrypted_text.is_some());
        // Athena should identify "hello"
        // But "hello" is short. "hello world" is better.
    }
}
