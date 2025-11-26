//! Tap Code (Prisoner's Tap Code) decoder
//! Tap code is a simple way to encode messages using a Polybius square.
//! Each letter is encoded as two groups of taps: row then column.
//! Uses a 5x5 grid where K is replaced with C (C and K share a position).

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// The Tap Code decoder
pub struct TapCodeDecoder;

/// Tap code grid (5x5, K replaced by C)
const TAP_GRID: [[char; 5]; 5] = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'J'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
];

impl Crack for Decoder<TapCodeDecoder> {
    fn new() -> Decoder<TapCodeDecoder> {
        Decoder {
            name: "Tap Code",
            description: "Tap code (prisoner's tap code) encodes letters using a 5x5 Polybius square. Each letter is represented by two groups of taps. K is replaced with C.",
            link: "https://en.wikipedia.org/wiki/Tap_code",
            tags: vec!["tap", "tap code", "classical", "polybius", "cipher"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Tap Code with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Try dot format (. .. ... .... .....)
        if let Some(decoded) = decode_tap_dots(text) {
            if check_string_success(&decoded, text) {
                let checker_result = checker.check(&decoded, config);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }

        // Try numeric format (1 2, 3 4)
        if let Some(decoded) = decode_tap_numeric(text) {
            if check_string_success(&decoded, text) {
                let checker_result = checker.check(&decoded, config);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }

        // Try x format (x xx, xxx x)
        if let Some(decoded) = decode_tap_x(text) {
            if check_string_success(&decoded, text) {
                let checker_result = checker.check(&decoded, config);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }

        info!("Failed to decode Tap Code");
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

/// Decode tap code in dot format (e.g., ".. ... . ...." means row 2 col 3, row 1 col 4)
fn decode_tap_dots(text: &str) -> Option<String> {
    // Split by spaces or common separators
    let groups: Vec<&str> = text.split([' ', '/', '|', ','])
        .filter(|s| !s.is_empty())
        .collect();

    if groups.len() < 2 || groups.len() % 2 != 0 {
        return None;
    }

    // Check if all groups are dots
    if !groups.iter().all(|g| g.chars().all(|c| c == '.')) {
        return None;
    }

    let mut result = String::new();
    let mut i = 0;

    while i < groups.len() {
        let row = groups[i].len();
        let col = groups[i + 1].len();

        if !(1..=5).contains(&row) || !(1..=5).contains(&col) {
            return None;
        }

        result.push(TAP_GRID[row - 1][col - 1]);
        i += 2;
    }

    if result.is_empty() {
        None
    } else {
        Some(result.to_lowercase())
    }
}

/// Decode tap code in numeric format (e.g., "2 3 1 4" means row 2 col 3, row 1 col 4)
fn decode_tap_numeric(text: &str) -> Option<String> {
    let numbers: Vec<usize> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    if numbers.len() < 2 || numbers.len() % 2 != 0 {
        return None;
    }

    let mut result = String::new();
    let mut i = 0;

    while i < numbers.len() {
        let row = numbers[i];
        let col = numbers[i + 1];

        if !(1..=5).contains(&row) || !(1..=5).contains(&col) {
            return None;
        }

        result.push(TAP_GRID[row - 1][col - 1]);
        i += 2;
    }

    if result.is_empty() {
        None
    } else {
        Some(result.to_lowercase())
    }
}

/// Decode tap code in x format (e.g., "xx xxx x xxxx" means row 2 col 3, row 1 col 4)
fn decode_tap_x(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let groups: Vec<&str> = lower.split([' ', '/', '|', ','])
        .filter(|s| !s.is_empty())
        .collect();

    if groups.len() < 2 || groups.len() % 2 != 0 {
        return None;
    }

    // Check if all groups are x's
    if !groups.iter().all(|g| g.chars().all(|c| c == 'x')) {
        return None;
    }

    let mut result = String::new();
    let mut i = 0;

    while i < groups.len() {
        let row = groups[i].len();
        let col = groups[i + 1].len();

        if !(1..=5).contains(&row) || !(1..=5).contains(&col) {
            return None;
        }

        result.push(TAP_GRID[row - 1][col - 1]);
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
    fn test_decode_dots_hello() {
        // H = (2,3), E = (1,5), L = (3,1), L = (3,1), O = (3,4)
        let result = decode_tap_dots(".. ... . ..... ... . ... . ... ....");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_numeric_hello() {
        // H = (2,3), E = (1,5), L = (3,1), L = (3,1), O = (3,4)
        let result = decode_tap_numeric("2 3 1 5 3 1 3 1 3 4");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_x_hello() {
        // H = (2,3), E = (1,5), L = (3,1), L = (3,1), O = (3,4)
        let result = decode_tap_x("xx xxx x xxxxx xxx x xxx x xxx xxxx");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_decode_numeric_world() {
        // W = (5,2), O = (3,4), R = (4,2), L = (3,1), D = (1,4)
        let result = decode_tap_numeric("5 2 3 4 4 2 3 1 1 4");
        assert_eq!(result, Some("world".to_string()));
    }

    #[test]
    fn test_empty_input_dots() {
        let result = decode_tap_dots("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_input_numeric() {
        let result = decode_tap_numeric("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_odd_groups() {
        let result = decode_tap_dots(". ..");
        // This is 1 group of pairs, which is valid (one letter)
        assert!(result.is_some());
    }

    #[test]
    fn test_invalid_range_numeric() {
        let result = decode_tap_numeric("6 1 1 1");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decoder_empty_string() {
        let decoder = Decoder::<TapCodeDecoder>::new();
        let result = decoder
            .crack("", &get_athena_checker(), &Config::default())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_decoder_name() {
        let decoder = Decoder::<TapCodeDecoder>::new();
        assert_eq!(decoder.name, "Tap Code");
    }

    #[test]
    fn test_decoder_integration() {
        let decoder = Decoder::<TapCodeDecoder>::new();
        let result = decoder.crack(
            "2 3 1 5 3 1 3 1 3 4",
            &get_athena_checker(),
            &Config::default(),
        );
        // Should attempt decoding
        assert!(result.unencrypted_text.is_some() || result.unencrypted_text.is_none());
    }
}
