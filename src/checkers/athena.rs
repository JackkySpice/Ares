/// Athena checker runs all other checkers and returns immediately when a plaintext is found.
/// This is the standard checker that exits early when a plaintext is found.
/// For a version that continues checking and collects all plaintexts, see WaitAthena.
use crate::{checkers::checker_result::CheckResult, config::Config};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;
use once_cell::sync::Lazy;

use super::{
    checker_type::{Check, Checker},
    english::EnglishChecker,
    human_checker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

// Static instances for Low sensitivity (default for Athena) to avoid repeated instantiation
static REGEX_LOW: Lazy<Checker<RegexChecker>> = Lazy::new(|| {
    Checker::<RegexChecker>::new().with_sensitivity(Sensitivity::Low)
});

static WORDLIST_LOW: Lazy<Checker<WordlistChecker>> = Lazy::new(|| {
    Checker::<WordlistChecker>::new().with_sensitivity(Sensitivity::Low)
});

static LEMMEKNOW_LOW: Lazy<Checker<LemmeKnow>> = Lazy::new(|| {
    Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low)
});

static PASSWORD_LOW: Lazy<Checker<PasswordChecker>> = Lazy::new(|| {
    Checker::<PasswordChecker>::new().with_sensitivity(Sensitivity::Low)
});

static ENGLISH_LOW: Lazy<Checker<EnglishChecker>> = Lazy::new(|| {
    Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low)
});

/// Athena checker runs all other checkers
pub struct Athena;

impl Check for Checker<Athena> {
    fn new() -> Self {
        Checker {
            // TODO: Update fields with proper values
            name: "Athena Checker",
            description: "Runs all available checkers",
            link: "",
            tags: vec!["athena", "all"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Low, // Default to Low sensitivity to reduce false positives
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str, config: &Config) -> CheckResult {
        trace!("Athena checker running on text: {}", text);
        
        let is_low = matches!(self.sensitivity, Sensitivity::Low);

        // If regex is specified, only run the regex checker
        if config.regex.is_some() {
            trace!("running regex");
            
            let regex_checker_temp;
            let regex_checker_ref: &Checker<RegexChecker> = if is_low {
                &*REGEX_LOW
            } else {
                regex_checker_temp = Checker::<RegexChecker>::new().with_sensitivity(self.sensitivity);
                &regex_checker_temp
            };

            let regex_result = regex_checker_ref.check(text, config);
            if regex_result.is_identified {
                let mut check_res = CheckResult::new(regex_checker_ref);
                trace!("DEBUG: Athena - About to run human checker for regex result");
                let human_result = human_checker::human_checker(&regex_result, config);
                trace!(
                    "Human checker called from regex checker with result: {}",
                    human_result
                );
                check_res.is_identified = human_result;
                check_res.text = regex_result.text;
                check_res.description = regex_result.description;
                return check_res;
            }
        } else {
            // Run wordlist checker first if a wordlist is provided
            if config.wordlist.is_some() {
                trace!("running wordlist checker");
                
                let wordlist_checker_temp;
                let wordlist_checker_ref: &Checker<WordlistChecker> = if is_low {
                    &*WORDLIST_LOW
                } else {
                    wordlist_checker_temp = Checker::<WordlistChecker>::new().with_sensitivity(self.sensitivity);
                    &wordlist_checker_temp
                };

                let wordlist_result = wordlist_checker_ref.check(text, config);
                if wordlist_result.is_identified {
                    let mut check_res = CheckResult::new(wordlist_checker_ref);
                    let human_result = human_checker::human_checker(&wordlist_result, config);
                    trace!(
                        "Human checker called from wordlist checker with result: {}",
                        human_result
                    );
                    check_res.is_identified = human_result;
                    check_res.text = wordlist_result.text;
                    check_res.description = wordlist_result.description;
                    log::debug!(
                        "DEBUG: Athena wordlist checker - human_result: {}, check_res.is_identified: {}",
                        human_result, check_res.is_identified
                    );
                    return check_res;
                }
            }

            // In Ciphey if the user uses the regex checker all the other checkers turn off
            // This is because they are looking for one specific bit of information so will not want the other checkers
            
            // LemmeKnow Checker
            let lemmeknow_temp;
            let lemmeknow_ref: &Checker<LemmeKnow> = if is_low {
                &*LEMMEKNOW_LOW
            } else {
                lemmeknow_temp = Checker::<LemmeKnow>::new().with_sensitivity(self.sensitivity);
                &lemmeknow_temp
            };

            let lemmeknow_result = lemmeknow_ref.check(text, config);
            //println!("Text is {}", text);
            if lemmeknow_result.is_identified {
                let mut check_res = CheckResult::new(lemmeknow_ref);
                let human_result = human_checker::human_checker(&lemmeknow_result, config);
                trace!(
                    "Human checker called from lemmeknow checker with result: {}",
                    human_result
                );
                check_res.is_identified = human_result;
                check_res.text = lemmeknow_result.text;
                check_res.description = lemmeknow_result.description;
                log::debug!("DEBUG: Athena lemmeknow checker - human_result: {}, check_res.is_identified: {}", human_result, check_res.is_identified);
                return check_res;
            }

            // Password Checker
            let password_temp;
            let password_ref: &Checker<PasswordChecker> = if is_low {
                &*PASSWORD_LOW
            } else {
                password_temp = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
                &password_temp
            };

            let password_result = password_ref.check(text, config);
            if password_result.is_identified {
                let mut check_res = CheckResult::new(password_ref);
                let human_result = human_checker::human_checker(&password_result, config);
                trace!(
                    "Human checker called from password checker with result: {}",
                    human_result
                );
                check_res.is_identified = human_result;
                check_res.text = password_result.text;
                check_res.description = password_result.description;
                log::debug!("DEBUG: Athena password checker - human_result: {}, check_res.is_identified: {}", human_result, check_res.is_identified);
                return check_res;
            }

            // English Checker
            let english_temp;
            let english_ref: &Checker<EnglishChecker> = if is_low {
                &*ENGLISH_LOW
            } else {
                english_temp = Checker::<EnglishChecker>::new().with_sensitivity(self.sensitivity);
                &english_temp
            };

            let english_result = english_ref.check(text, config);
            if english_result.is_identified {
                let mut check_res = CheckResult::new(english_ref);
                let human_result = human_checker::human_checker(&english_result, config);
                trace!(
                    "Human checker called from english checker with result: {}",
                    human_result
                );
                check_res.is_identified = human_result;
                check_res.text = english_result.text;
                check_res.description = english_result.description;
                log::debug!(
                    "DEBUG: Athena english checker - human_result: {}, check_res.is_identified: {}",
                    human_result, check_res.is_identified
                );
                return check_res;
            }
        }

        CheckResult::new(self)
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}
