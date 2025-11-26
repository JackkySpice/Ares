//! ROT5 decoder - Rotates digits by 5
//! Similar to ROT13 but for digits only (0-9)
//! 0 -> 5, 1 -> 6, ..., 5 -> 0, ..., 9 -> 4

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// The ROT5 decoder
pub struct Rot5Decoder;

impl Crack for Decoder<Rot5Decoder> {
    fn new() -> Decoder<Rot5Decoder> {
        Decoder {
            name: "ROT5",
            description: "ROT5 is a simple substitution cipher for digits. Each digit is replaced by the digit 5 positions after it (wrapping around). 0->5, 1->6, ..., 5->0, etc.",
            link: "https://en.wikipedia.org/wiki/ROT13#Variants",
            tags: vec!["rot5", "rot", "classical", "cipher", "reciprocal"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying ROT5 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Check if text contains any digits
        if !text.chars().any(|c| c.is_ascii_digit()) {
            info!("No digits found for ROT5");
            return results;
        }

        let decoded_text = rot5(text);

        trace!("Decoded text for ROT5: {:?}", decoded_text);

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode ROT5 because check_string_success returned false on string {}",
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

/// Apply ROT5 transformation to a string (only affects digits)
fn rot5(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_digit() {
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
    fn test_rot5_basic() {
        assert_eq!(rot5("0123456789"), "5678901234");
    }

    #[test]
    fn test_rot5_symmetric() {
        // ROT5 applied twice should give back the original
        let original = "0123456789";
        let result = rot5(&rot5(original));
        assert_eq!(result, original);
    }

    #[test]
    fn test_rot5_with_letters() {
        assert_eq!(rot5("abc123xyz"), "abc678xyz");
    }

    #[test]
    fn test_rot5_preserves_non_digits() {
        assert_eq!(rot5("hello world!"), "hello world!");
    }

    #[test]
    fn test_rot5_mixed() {
        assert_eq!(rot5("phone: 555-1234"), "phone: 000-6789");
    }

    #[test]
    fn test_rot5_empty() {
        assert_eq!(rot5(""), "");
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<Rot5Decoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_no_digits() {
        let decoder = Decoder::<Rot5Decoder>::new();
        let result = decoder
            .crack("hello world", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_with_digits() {
        let decoder = Decoder::<Rot5Decoder>::new();
        let result = decoder
            .crack("5678901234", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], "0123456789");
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<Rot5Decoder>::new();
        assert_eq!(decoder.name, "ROT5");
    }
}
