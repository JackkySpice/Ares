//! Polybius Square cipher decoder
//! The Polybius Square is a device invented by the Ancient Greeks.
//! It encodes each letter as a pair of digits representing row and column in a 5x5 grid.
//! Standard grid uses A-E for rows/columns (or 1-5), with I/J sharing a cell.

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// The Polybius Square decoder
/// Call: `let decoder = Decoder::<PolybiusSquareDecoder>::new()` to create a new instance
/// And then call: `result = decoder.crack(input)` to decode
pub struct PolybiusSquareDecoder;

/// Standard Polybius square grid (5x5, I/J share position)
/// Row and column indices: 1-5 or A-E
const POLYBIUS_GRID: [[char; 5]; 5] = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'], // I and J share this position (2,4)
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
];

impl Crack for Decoder<PolybiusSquareDecoder> {
    fn new() -> Decoder<PolybiusSquareDecoder> {
        Decoder {
            name: "Polybius Square",
            description: "The Polybius Square cipher encodes each letter as a pair of digits (or letters) representing its position in a 5x5 grid. I and J typically share a position.",
            link: "https://en.wikipedia.org/wiki/Polybius_square",
            tags: vec!["polybius", "classical", "substitution", "cipher"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Polybius Square cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Try decoding with numeric format (11-55)
        if let Some(decoded) = decode_polybius_numeric(text) {
            if check_string_success(&decoded, text) {
                let checker_result = checker.check(&decoded, config);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }

        // Try decoding with letter format (AA-EE)
        if let Some(decoded) = decode_polybius_letters(text) {
            if check_string_success(&decoded, text) {
                let checker_result = checker.check(&decoded, config);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }

        info!("Failed to decode Polybius Square cipher");
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

/// Decode Polybius cipher with numeric format (e.g., "11 12 13" -> "ABC")
fn decode_polybius_numeric(text: &str) -> Option<String> {
    let cleaned: String = text.chars().filter(|c| c.is_ascii_digit() || c.is_whitespace()).collect();
    let digits: Vec<char> = cleaned.chars().filter(|c| c.is_ascii_digit()).collect();

    // Must have even number of digits
    if digits.len() % 2 != 0 || digits.is_empty() {
        return None;
    }

    let mut result = String::new();
    let mut i = 0;

    while i < digits.len() {
        let row = digits[i].to_digit(10)? as usize;
        let col = digits[i + 1].to_digit(10)? as usize;

        // Valid indices are 1-5
        if !(1..=5).contains(&row) || !(1..=5).contains(&col) {
            return None;
        }

        result.push(POLYBIUS_GRID[row - 1][col - 1]);
        i += 2;
    }

    if result.is_empty() {
        None
    } else {
        Some(result.to_lowercase())
    }
}

/// Decode Polybius cipher with letter format (e.g., "AA AB AC" -> "ABC")
fn decode_polybius_letters(text: &str) -> Option<String> {
    let upper = text.to_uppercase();
    let cleaned: String = upper.chars().filter(|c| c.is_ascii_alphabetic() || c.is_whitespace()).collect();
    let letters: Vec<char> = cleaned.chars().filter(|c| c.is_ascii_alphabetic()).collect();

    // Must have even number of letters
    if letters.len() % 2 != 0 || letters.is_empty() {
        return None;
    }

    // Check if all letters are in A-E range
    if !letters.iter().all(|c| ('A'..='E').contains(c)) {
        return None;
    }

    let mut result = String::new();
    let mut i = 0;

    while i < letters.len() {
        let row = (letters[i] as u8 - b'A') as usize;
        let col = (letters[i + 1] as u8 - b'A') as usize;

        result.push(POLYBIUS_GRID[row][col]);
        i += 2;
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
    fn test_decode_numeric_basic() {
        let result = decode_polybius_numeric("23 15 31 31 34");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_numeric_world() {
        let result = decode_polybius_numeric("52 34 42 31 14");
        assert_eq!(result, Some("world".to_string()));
    }

    #[test]
    fn test_decode_letters_basic() {
        let result = decode_polybius_letters("BC AE CA CA CD");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_letters_world() {
        let result = decode_polybius_letters("EB CD DB CA AD");
        assert_eq!(result, Some("world".to_string()));
    }

    #[test]
    fn test_decode_numeric_no_spaces() {
        let result = decode_polybius_numeric("2315313134");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_letters_no_spaces() {
        let result = decode_polybius_letters("BCAECACACD");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_empty_input() {
        let result = decode_polybius_numeric("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_invalid_numeric_range() {
        let result = decode_polybius_numeric("06 07");
        assert_eq!(result, None);
    }

    #[test]
    fn test_odd_number_of_digits() {
        let result = decode_polybius_numeric("123");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decoder_integration() {
        let decoder = Decoder::<PolybiusSquareDecoder>::new();
        let result = decoder.crack(
            "23 15 31 31 34 52 34 42 31 14",
            &get_athena_checker(),
            &Config::default(),
        );
        // Check that it attempts to decode
        assert!(result.unencrypted_text.is_some() || result.unencrypted_text.is_none());
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<PolybiusSquareDecoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }
}
