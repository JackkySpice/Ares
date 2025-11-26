use crate::checkers::checker_result::CheckResult;
use crate::cryptanalysis::{fitness_score, word_score, index_of_coincidence};
use gibberish_or_not::{is_gibberish, Sensitivity};
use lemmeknow::Identifier;
use log::trace;

use crate::checkers::checker_type::{Check, Checker};
use crate::config::Config;

/// Checks English plaintext.
/// Enhanced with cryptanalysis-based detection as a secondary check.
pub struct EnglishChecker;

/// given an input, check every item in the array and return true if any of them match
impl Check for Checker<EnglishChecker> {
    fn new() -> Self {
        Checker {
            name: "English Checker",
            description: "Uses gibberish detection to check if text is meaningful English",
            link: "https://crates.io/crates/gibberish-or-not",
            tags: vec!["english", "nlp"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            enhanced_detector: None,
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str, config: &Config) -> CheckResult {
        // Normalize before checking
        let normalized = normalise_string(text);

        // Get config to check if enhanced detection is enabled
        let is_enhanced = config.enhanced_detection;
        
        // Primary check: gibberish-or-not library
        let is_gibberish_result = if is_enhanced {
            !is_gibberish(&normalized, Sensitivity::High)
        } else {
            !is_gibberish(&normalized, self.sensitivity)
        };
        
        // Secondary check: cryptanalysis-based detection
        // This helps catch cases where gibberish-or-not misses valid plaintext
        // Only triggers for longer texts with strong English indicators
        let cryptanalysis_check = if normalized.len() >= 30 {
            let fitness = fitness_score(&normalized);
            let word_pct = word_score(&normalized);
            let ic = index_of_coincidence(&normalized);
            
            // Check if text has English-like characteristics
            // Use stricter thresholds to avoid false positives
            let has_good_ic = ic > 0.055 && ic < 0.075;
            let has_words = word_pct > 40.0;  // Require more recognized words
            let has_decent_fitness = fitness > -150.0;  // Stricter fitness threshold
            
            trace!("EnglishChecker crypto: fitness={:.2}, word_pct={:.2}, ic={:.4}", 
                fitness, word_pct, ic);
            
            // Require ALL conditions for cryptanalysis-only detection
            // This is a fallback, so we need to be sure
            has_good_ic && has_words && has_decent_fitness
        } else {
            false
        };
        
        // Combine both checks - if either passes, consider it English
        let is_identified = is_gibberish_result || cryptanalysis_check;

        trace!("EnglishChecker: Checking '{}'. Normalized: '{}'. Sensitivity: {:?}. Gibberish: {}, Crypto: {}, Final: {}", 
            text, normalized, self.sensitivity, is_gibberish_result, cryptanalysis_check, is_identified);

        let mut result = CheckResult {
            is_identified,
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: "Words".to_string(),
            link: self.link,
        };

        // Handle edge case of very short strings after normalization
        if normalized.len() < 2 {
            // Reduced from 3 since normalization may remove punctuation
            result.is_identified = false;
        }

        result
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// Strings look funny, they might have commas, be uppercase etc
/// This normalises the string so English checker can work on it
/// In particular it:
/// Removes punctuation from the string
/// Lowercases the string
fn normalise_string(input: &str) -> String {
    // The replace function supports patterns https://doc.rust-lang.org/std/str/pattern/trait.Pattern.html#impl-Pattern%3C%27a%3E-3
    // TODO add more punctuation
    input
        .to_ascii_lowercase()
        .chars()
        .filter(|x| !x.is_ascii_punctuation())
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::checkers::english::normalise_string;
    use crate::checkers::{
        checker_type::{Check, Checker},
        english::EnglishChecker,
    };
    // Import Sensitivity directly
    use gibberish_or_not::Sensitivity;

    #[test]
    fn test_check_basic() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(checker.check("preinterview", &config).is_identified);
    }

    #[test]
    fn test_check_basic2() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(checker.check("exuberant", &config).is_identified);
    }

    #[test]
    fn test_check_multiple_words() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(
            checker
                .check("this is a valid english sentence", &config)
                .is_identified
        );
    }

    #[test]
    fn test_check_non_dictionary_word() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(
            !checker
                .check("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBabyShark", &config)
                .is_identified
        );
    }

    #[test]
    fn test_check_multiple_words2() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(checker.check("preinterview hello dog", &config).is_identified);
    }
    #[test]
    fn test_check_normalise_string_works_with_lowercasing() {
        let x = normalise_string("Hello Dear");
        assert_eq!(x, "hello dear")
    }
    #[test]
    fn test_check_normalise_string_works_with_puncuation() {
        let x = normalise_string("Hello, Dear");
        assert_eq!(x, "hello dear")
    }
    #[test]
    fn test_check_normalise_string_works_with_messy_puncuation() {
        let x = normalise_string(".He/ll?O, Dea!r");
        assert_eq!(x, "hello dear")
    }

    #[test]
    fn test_checker_works_with_puncuation_and_lowercase() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(checker.check("Prei?nterview He!llo Dog?", &config).is_identified);
    }

    #[test]
    fn test_check_fail_single_puncuation_char() {
        let checker = Checker::<EnglishChecker>::new();
        let config = crate::config::Config::default();
        assert!(!checker.check("#", &config).is_identified);
    }

    #[test]
    fn test_default_sensitivity_is_medium() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Medium));
    }

    #[test]
    fn test_with_sensitivity_changes_sensitivity() {
        let checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Low));

        let checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::High);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::High));
    }

    #[test]
    fn test_sensitivity_affects_gibberish_detection() {
        // This text has one English word "iron" but is otherwise gibberish
        let text = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
        let config = crate::config::Config::default();

        // With Low sensitivity, it should be classified as gibberish
        let low_checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low);
        assert!(!low_checker.check(text, &config).is_identified);

        // With High sensitivity, it should be classified as English
        let high_checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::High);
        assert!(high_checker.check(text, &config).is_identified);
    }
}
