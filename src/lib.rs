//! Ares is an automatic decoding and cracking tool. https://github.com/JackkySpice/Ares
// Warns in case we forget to include documentation
#![warn(
    missing_docs,
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

/// The main crate for the Ares project.
/// This provides the library API interface for ares.
mod api_library_input_struct;
/// Checkers is a module that contains the functions that check if the input is plaintext
pub mod checkers;
/// CLI Arg Parsing library
pub mod cli;
/// CLI Input Parser parses the input from the CLI and returns a struct.
mod cli_input_parser;
/// CLI Pretty Printing module for consistent output formatting
///
/// # Examples
/// ```
/// use ares::cli_pretty_printing::{success, warning};
///
/// // Print a success message
/// let success_msg = success("Operation completed successfully", &ares::config::Config::default());
/// assert!(!success_msg.is_empty());
///
/// // Print a warning message
/// let warning_msg = warning("Please check your input", &ares::config::Config::default());
/// assert!(!warning_msg.is_empty());
/// ```
pub mod cli_pretty_printing;
/// The Config module enables a configuration module
/// Like a global API to access config details
pub mod config;
/// Decoders are the functions that actually perform the decodings.
pub mod decoders;
/// The filtration system builds what decoders to use at runtime
/// By default it will use them all.
pub mod filtration_system;
/// The searcher is the thing which searches for the plaintext
/// It is the core of the program.
mod searchers;
/// Storage module for dictionaries and invisible characters
pub mod storage;
/// Timer for internal use
mod timer;

use checkers::{
    athena::Athena,
    checker_result::CheckResult,
    checker_type::{Check, Checker},
    wait_athena::WaitAthena,
};
use log::debug;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{
    config::Config,
    decoders::interface::Decoder,
};

use self::decoders::crack_results::CrackResult;

/// The main function to call which performs the cracking.
/// ```rust
/// use ares::perform_cracking;
/// use ares::config::Config;
/// let mut config = Config::default();
/// # let _test_db = ares::TestDatabase::default();
/// # ares::set_test_db_path();
/// // You can set the config to your liking using the Config struct
/// // Just edit the data like below if you want:
/// config.timeout = 5;
/// config.human_checker_on = false;
/// config.verbose = 0;
/// let result = perform_cracking("VGhlIG1haW4gZnVuY3Rpb24gdG8gY2FsbCB3aGljaCBwZXJmb3JtcyB0aGUgY3JhY2tpbmcu", config);
/// assert!(true);
/// // The result is an Option<DecoderResult> so we need to unwrap it
/// // The DecoderResult contains the text and the path
/// // The path is a vector of CrackResults which contains the decoder used and the keys used
/// // The text is a vector of strings because some decoders return more than 1 text (Caesar)
/// // Becuase the program has returned True, the first result is the plaintext (and it will only have 1 result).
/// // This is some tech debt we need to clean up https://github.com/bee-san/ciphey/issues/130
/// assert!(result.unwrap().text[0] == "The main function to call which performs the cracking.");
/// ```
/// The human checker defaults to off in the config, but it returns the first thing it finds currently.
/// We have an issue for that here https://github.com/bee-san/ciphey/issues/129
/// ```rust
/// use ares::perform_cracking;
/// use ares::config::Config;
/// let mut config = Config::default();
/// # let _test_db = ares::TestDatabase::default();
/// # ares::set_test_db_path();
/// // You can set the config to your liking using the Config struct
/// // Just edit the data like below if you want:
/// config.timeout = 0;
/// let result = perform_cracking("VGhlIG1haW4gZnVuY3Rpb24gdG8gY2FsbCB3aGljaCBwZXJmb3JtcyB0aGUgY3JhY2tpbmcu", config);
/// assert!(true);
/// // If the program times out, or it cannot decode the text it will return None.
/// assert!(result.is_none());
/// ```
pub fn perform_cracking(text: &str, config: Config) -> Option<DecoderResult> {
    let start_time = SystemTime::now();
    let mut config = config;
    // If top_results...


    // If top_results is enabled, ensure human_checker_on is disabled
    if config.top_results {
        config.human_checker_on = false;
        // Clear any previous results when starting a new cracking session
        storage::wait_athena_storage::clear_plaintext_results();
    }
    let config = Arc::new(config);

    let text = text.to_string();

    /* Initializing database */
    let db_result = storage::database::setup_database(&config);
    match db_result {
        Ok(_) => (),
        Err(e) => {
            cli_pretty_printing::warning(&format!(
                "DEBUG: lib.rs - SQLite database failed to initialize. Encountered error: {}",
                e
            ), &config);
        }
    };

    /*  Checks to see if the encoded text already exists in the cache
     *  returns cached result if so
     */
    let cache_result = storage::database::read_cache(&text);
    match cache_result {
        Ok(cache_row) => match cache_row {
            Some(row) => {
                log::debug!("Cache hit for text: {}", text);
                log::debug!("Cache hit for text: {}", text);
                let path_result: Result<Vec<CrackResult>, serde_json::Error> = row
                    .path
                    .iter()
                    .map(|crack_json| {
                        let json_result = serde_json::from_str(crack_json);
                        match json_result {
                            Ok(crack_result) => Ok(crack_result),
                            Err(e) => {
                                log::warn!("Error deserializing cache result: {}", e);
                                Err(e)
                            }
                        }
                    })
                    .collect();
                if let Ok(path) = path_result {
                    return Some(DecoderResult {
                        text: vec![row.decoded_text],
                        path,
                    });
                }
            }
            None => {
                log::debug!("Did not find text \"{}\" in cache", text.clone());
            }
        },
        Err(e) => {
            log::warn!("Error trying to read from cache: {}", e);
        }
    }

    let initial_check_for_plaintext = check_if_input_text_is_plaintext(&text, &config);
    if initial_check_for_plaintext.is_identified {
        debug!(
            "The input text provided to the program {} is the plaintext. Returning early.",
            text
        );
        cli_pretty_printing::return_early_because_input_text_is_plaintext(&config);

        let mut crack_result = CrackResult::new(&Decoder::default(), text.to_string());
        crack_result.checker_name = initial_check_for_plaintext.checker_name;

        let output = DecoderResult {
            text: vec![text.clone()],
            path: vec![crack_result],
        };

        let cache_result = success_result_to_cache(&text, start_time, &output, &config);
        match cache_result {
            Ok(_) => (),
            Err(e) => {
                log::warn!("Error inserting decoder result into cache table: {}", e);
            }
        };

        return Some(output);
    }

    // Build a new search tree
    // This starts us with a node with no parents
    // let search_tree = searchers::Tree::new(text.to_string());
    log::debug!("Calling search_for_plaintext with text: {}", text);
    // Perform the search algorithm
    // It will either return a failure or success.
    let result = searchers::search_for_plaintext(text.clone(), config.clone());
    log::debug!("Result from search_for_plaintext: {:?}", result.is_some());
    if let Some(ref res) = result {
        log::debug!("Result has {} decoders in path", res.path.len());
    }

    if let Some(output) = &result {
        let cache_result = success_result_to_cache(&text, start_time, output, &config);
        match cache_result {
            Ok(_) => (),
            Err(e) => {
                log::warn!("Error inserting decoder result into cache table: {}", e);
            }
        };
    }

    result
}

/// Checks if the given input is plaintext or not
/// Used at the start of the program to not waste CPU cycles
fn check_if_input_text_is_plaintext(text: &str, config: &Config) -> CheckResult {
    if config.top_results {
        let wait_athena_checker = Checker::<WaitAthena>::new();
        wait_athena_checker.check(text, &crate::config::Config::default())
    } else {
        let athena_checker = Checker::<Athena>::new();
        athena_checker.check(text, &crate::config::Config::default())
    }
}

/// Stores a successful DecoderResult into the cache table
fn success_result_to_cache(
    text: &String,
    start_time: SystemTime,
    result: &DecoderResult,
    config: &Config,
) -> Result<usize, rusqlite::Error> {
    let stop_time = SystemTime::now();
    let execution_time_ms: i64 = match stop_time.duration_since(start_time) {
        Ok(duration) => duration.as_millis().try_into().unwrap_or(-2),
        Err(_) => {
            cli_pretty_printing::warning(
                "Stop time is less than start time. Clock may have gone backwards.",
            config);
            -1
        }
    };
    let cache_entry = storage::database::CacheEntry {
        uuid: uuid::Uuid::new_v4(),
        encoded_text: String::from(text),
        decoded_text: match result.text.last() {
            Some(d_text) => String::from(d_text),
            None => String::new(),
        },
        path: result.path.clone(),
        execution_time_ms,
    };
    storage::database::insert_cache(&cache_entry)
}

/// DecoderResult is the result of decoders
#[derive(Debug, Clone)]
pub struct DecoderResult {
    /// The text we have from the decoder, as a vector
    /// because the decoder might return more than 1 text (caesar)
    pub text: Vec<String>,
    /// The list of decoders we have so far
    /// The CrackResult contains more than just each decoder, such as the keys used
    /// or the checkers used.
    pub path: Vec<CrackResult>,
}

/// Creates a default DecoderResult with Default as the text / path
impl Default for DecoderResult {
    fn default() -> Self {
        DecoderResult {
            text: vec!["Default".to_string()],
            path: vec![CrackResult::new(&Decoder::default(), "Default".to_string())],
        }
    }
}

/// Lets us create a new decoderResult with given text
impl DecoderResult {
    /// It's only used in tests so it thinks its dead code
    fn _new(text: &str) -> Self {
        DecoderResult {
            text: vec![text.to_string()],
            path: vec![CrackResult::new(&Decoder::default(), "Default".to_string())],
        }
    }
}

/// Gets the test directory path
#[doc(hidden)]
pub fn get_test_dir_path() -> std::path::PathBuf {
    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".ares");
    path.push("test");
    path
}

/// Sets the global database path
#[doc(hidden)]
pub fn set_test_db_path() {
    let mut path = get_test_dir_path();
    std::fs::create_dir_all(&path).expect("Could not create .ares directory");
    path.push("database.sqlite");
    let _ = crate::storage::database::DB_PATH.set(Some(path));
}

/// Helper struct for testing database
#[doc(hidden)]
pub struct TestDatabase {
    /// PathBuf to database file
    pub path: std::path::PathBuf,
}

#[doc(hidden)]
impl Default for TestDatabase {
    fn default() -> Self {
        TestDatabase {
            path: get_test_dir_path(),
        }
    }
}

#[doc(hidden)]
impl Drop for TestDatabase {
    fn drop(&mut self) {
        let mut db_file_path = self.path.as_path().to_path_buf();
        db_file_path.push("database.sqlite");
        let _ = std::fs::remove_file(&db_file_path);
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
#[serial_test::parallel]
mod tests {
    use super::perform_cracking;
    use crate::config::Config;
    use crate::{set_test_db_path, TestDatabase};

    #[test]
    fn test_perform_cracking_returns() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        perform_cracking("SGVscCBJIG5lZWQgc29tZWJvZHkh", crate::config::Config::default());
    }

    #[test]
    fn test_perform_cracking_returns_failure() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        let result = perform_cracking("", crate::config::Config::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_perform_cracking_returns_successful_base64_reverse() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        let result = perform_cracking("aGVsbG8gdGhlcmUgZ2VuZXJhbA==", crate::config::Config::default());
        assert!(result.is_some());
        assert!(result.unwrap().text[0] == "hello there general")
    }

    #[test]
    fn test_perform_cracking_early_exit_if_input_is_plaintext() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        let result = perform_cracking("192.168.0.1", crate::config::Config::default());
        // Since we are exiting early the path should be of length 1, which is 1 check (the Athena check)
        assert!(result.unwrap().path.len() == 1);
    }

    #[ignore]
    #[test]
    // Previously this would decode to `Fchohs as 13 dzoqsg!` because the English checker wasn't that good
    // This test makes sure we can decode it okay
    // TODO: Skipping this test because the English checker still isn't good.
    fn test_perform_cracking_successfully_decode_caesar() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        let result = perform_cracking("Ebgngr zr 13 cynprf!", crate::config::Config::default());
        // We return None since the input is the plaintext
        assert!(result.unwrap().text[0] == "Rotate me 13 places!");
    }

    #[test]
    fn test_perform_cracking_successfully_inputted_plaintext() {
        let _test_db = TestDatabase::default();
        set_test_db_path();

        let _config = Config::default();
        let result = perform_cracking("Hello, World!", crate::config::Config::default());
        // We return None since the input is the plaintext
        let res_unwrapped = result.unwrap();
        assert!(&res_unwrapped.text[0] == "Hello, World!");
        // Since our input is the plaintext we did not decode it
        // Therefore we return with the default decoder
        assert!(res_unwrapped.path[0].decoder == "Default decoder");
    }

}
