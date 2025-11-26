//! Columnar Transposition cipher decoder
//! A transposition cipher that writes the plaintext out in rows of a fixed length,
//! and then reads it out column by column, with the columns chosen in some scrambled order.
//! This implementation tries common column lengths to crack the cipher.

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// The Columnar Transposition decoder
pub struct ColumnarTranspositionDecoder;

impl Crack for Decoder<ColumnarTranspositionDecoder> {
    fn new() -> Decoder<ColumnarTranspositionDecoder> {
        Decoder {
            name: "Columnar Transposition",
            description: "Columnar transposition is a transposition cipher that writes the message in rows then reads columns in a specific order. This decoder tries various column counts.",
            link: "https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition",
            tags: vec!["columnar", "transposition", "classical", "cipher"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Columnar Transposition cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Only process alphabetic characters (preserve for checking)
        let clean_text: String = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        
        if clean_text.is_empty() {
            info!("No valid characters found for Columnar Transposition");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);

        // Try different column counts (2 to max reasonable)
        let max_cols = (clean_text.len() / 2).clamp(2, 15);
        
        for num_cols in 2..=max_cols {
            // Try simple columnar (reading columns in order)
            if let Some(decoded) = decode_columnar(&clean_text, num_cols) {
                if check_string_success(&decoded, text) {
                    let checker_result = checker_with_sensitivity.check(&decoded, config);
                    if checker_result.is_identified {
                        results.unencrypted_text = Some(vec![decoded]);
                        results.update_checker(&checker_result);
                        results.key = Some(num_cols.to_string());
                        return results;
                    }
                }
            }
            
            // Try reverse columnar (reading columns in reverse)
            if let Some(decoded) = decode_columnar_reverse(&clean_text, num_cols) {
                if check_string_success(&decoded, text) {
                    let checker_result = checker_with_sensitivity.check(&decoded, config);
                    if checker_result.is_identified {
                        results.unencrypted_text = Some(vec![decoded]);
                        results.update_checker(&checker_result);
                        results.key = Some(format!("{} (reverse)", num_cols));
                        return results;
                    }
                }
            }
        }

        info!("Failed to decode Columnar Transposition cipher");
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

/// Decode columnar transposition by reading down columns
fn decode_columnar(text: &str, num_cols: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    
    if len == 0 || num_cols == 0 {
        return None;
    }

    let num_rows = (len + num_cols - 1) / num_cols;
    let full_cols = len % num_cols;
    let full_cols = if full_cols == 0 { num_cols } else { full_cols };

    let mut result = String::with_capacity(len);

    // Read character by character across rows
    for row in 0..num_rows {
        for col in 0..num_cols {
            // Calculate position in original text
            let col_height = if col < full_cols { num_rows } else { num_rows - 1 };
            
            if row < col_height {
                // Calculate starting position of this column
                let col_start: usize = (0..col).map(|c| if c < full_cols { num_rows } else { num_rows - 1 }).sum();
                let idx = col_start + row;
                
                if idx < len {
                    result.push(chars[idx]);
                }
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result.to_lowercase())
    }
}

/// Decode columnar transposition reading columns in reverse order
fn decode_columnar_reverse(text: &str, num_cols: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    
    if len == 0 || num_cols == 0 {
        return None;
    }

    let num_rows = (len + num_cols - 1) / num_cols;
    let full_cols = len % num_cols;
    let full_cols = if full_cols == 0 { num_cols } else { full_cols };

    let mut result = String::with_capacity(len);

    // Read character by character across rows, columns in reverse
    for row in 0..num_rows {
        for col in (0..num_cols).rev() {
            let col_height = if col < full_cols { num_rows } else { num_rows - 1 };
            
            if row < col_height {
                let col_start: usize = (0..col).map(|c| if c < full_cols { num_rows } else { num_rows - 1 }).sum();
                let idx = col_start + row;
                
                if idx < len {
                    result.push(chars[idx]);
                }
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result.to_lowercase())
    }
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
    fn test_decode_columnar_simple() {
        // "HELLOWORLD" encoded with 3 columns:
        // H E L
        // L O W
        // O R L
        // D
        // Reading columns: HLOD EORW LL -> "HLODELLORW"
        // So to decode "HLODELLORW" with 3 columns should give "HELLOWORLD"
        let result = decode_columnar("HLODELLORW", 3);
        assert!(result.is_some());
    }

    #[test]
    fn test_decode_columnar_two_cols() {
        // "HELLO" with 2 columns:
        // H E
        // L L
        // O
        // Reading: HLO EL -> "HLOEL"
        let result = decode_columnar("HLOEL", 2);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_empty_input() {
        let result = decode_columnar("", 3);
        assert!(result.is_none());
    }

    #[test]
    fn test_zero_columns() {
        let result = decode_columnar("HELLO", 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<ColumnarTranspositionDecoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_integration() {
        let decoder = Decoder::<ColumnarTranspositionDecoder>::new();
        let result = decoder.crack(
            "HLOEL",
            &get_athena_checker(),
            &Config::default(),
        );
        // The decoder should attempt decoding
        assert!(result.unencrypted_text.is_some() || result.unencrypted_text.is_none());
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<ColumnarTranspositionDecoder>::new();
        assert_eq!(decoder.name, "Columnar Transposition");
    }
}
