//! ROT18 decoder - Combines ROT13 (letters) and ROT5 (digits)
//! ROT18 applies ROT13 to letters and ROT5 to digits simultaneously
//! It is a reciprocal cipher (applying it twice gives back the original)

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// The ROT18 decoder
pub struct Rot18Decoder;

impl Crack for Decoder<Rot18Decoder> {
    fn new() -> Decoder<Rot18Decoder> {
        Decoder {
            name: "ROT18",
            description: "ROT18 combines ROT13 (for letters) and ROT5 (for digits). It rotates letters by 13 positions and digits by 5 positions. It is a reciprocal cipher.",
            link: "https://en.wikipedia.org/wiki/ROT13#Variants",
            tags: vec!["rot18", "rot", "classical", "cipher", "reciprocal"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying ROT18 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Check if text contains letters or digits
        if !text.chars().any(|c| c.is_ascii_alphanumeric()) {
            info!("No alphanumeric characters found for ROT18");
            return results;
        }

        // ROT18 needs both letters and digits to be meaningful
        // Otherwise it's just ROT13 or ROT5
        let has_letters = text.chars().any(|c| c.is_ascii_alphabetic());
        let has_digits = text.chars().any(|c| c.is_ascii_digit());

        if !has_letters || !has_digits {
            info!("ROT18 requires both letters and digits");
            return results;
        }

        let decoded_text = rot18(text);

        trace!("Decoded text for ROT18: {:?}", decoded_text);

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode ROT18 because check_string_success returned false on string {}",
                decoded_text
            );
            return results;
        }

        let checker_result = checker.check(&decoded_text, config);
        results.unencrypted_text = Some(vec![decoded_text]);
        results.update_checker(&checker_result);

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

/// Apply ROT18 transformation (ROT13 for letters, ROT5 for digits)
fn rot18(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                // ROT13 for letters
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let rotated = ((c as u8 - base + 13) % 26) + base;
                rotated as char
            } else if c.is_ascii_digit() {
                // ROT5 for digits
                let digit = c as u8 - b'0';
                let rotated = (digit + 5) % 10;
                (rotated + b'0') as char
            } else {
                c
            }
        })
        .collect()
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
    fn test_rot18_letters() {
        assert_eq!(rot18("hello"), "uryyb");
    }

    #[test]
    fn test_rot18_digits() {
        assert_eq!(rot18("12345"), "67890");
    }

    #[test]
    fn test_rot18_mixed() {
        assert_eq!(rot18("hello123"), "uryyb678");
    }

    #[test]
    fn test_rot18_symmetric() {
        // ROT18 applied twice should give back the original
        let original = "Hello123World456";
        let result = rot18(&rot18(original));
        assert_eq!(result, original);
    }

    #[test]
    fn test_rot18_preserves_special() {
        assert_eq!(rot18("abc-123!xyz"), "nop-678!klm");
    }

    #[test]
    fn test_rot18_uppercase() {
        assert_eq!(rot18("ABC123"), "NOP678");
    }

    #[test]
    fn test_rot18_empty() {
        assert_eq!(rot18(""), "");
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<Rot18Decoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_only_letters() {
        let decoder = Decoder::<Rot18Decoder>::new();
        let result = decoder
            .crack("hello", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        // Should fail because ROT18 requires both letters and digits
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_only_digits() {
        let decoder = Decoder::<Rot18Decoder>::new();
        let result = decoder
            .crack("12345", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        // Should fail because ROT18 requires both letters and digits
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_with_both() {
        let decoder = Decoder::<Rot18Decoder>::new();
        let result = decoder
            .crack("uryyb678", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        // This should work
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], "hello123");
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<Rot18Decoder>::new();
        assert_eq!(decoder.name, "ROT18");
    }
}
