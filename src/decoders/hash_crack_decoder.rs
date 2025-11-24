//! Decode hashes (MD5, SHA1, SHA256) using a dictionary attack.
//! Performs error handling and returns a string
//! Call hash_crack_decoder.crack to use.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;
use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};
use digest::Digest;
// use md5::Md5; // Removed due to import issues
use sha1::Sha1;
use sha2::Sha256;

/// The Hash Crack decoder, call:
/// `let hash_crack_decoder = Decoder::<HashCrackDecoder>::new()` to create a new instance
/// And then call:
/// `result = hash_crack_decoder.crack(input)` to decode a hash
pub struct HashCrackDecoder;

impl Crack for Decoder<HashCrackDecoder> {
    fn new() -> Decoder<HashCrackDecoder> {
        Decoder {
            name: "HashCrack",
            description: "Cracks hashes (MD5, SHA1, SHA256) using a dictionary attack.",
            link: "https://en.wikipedia.org/wiki/Password_cracking",
            tags: vec!["hash", "md5", "sha1", "sha256", "cracker", "dictionary", "decoder"],
            popularity: 0.1, // Run last usually, or if detected
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying HashCrack with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        
        // Clean input
        let text = text.trim().to_lowercase();
        
        // Basic length check for common hashes (in hex)
        let hash_type = match text.len() {
            32 => "MD5",
            40 => "SHA1",
            64 => "SHA256",
            _ => {
                // Not a common hash length
                return results;
            }
        };

        // If not hex, return
        if !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return results;
        }

        debug!("Detected potential {} hash", hash_type);

        // Common passwords list (top 100 for now, could be expanded)
        // In a real tool, this would read from a file or include a larger compressed list
        let common_passwords = vec![
            "password", "123456", "12345678", "123456789", "12345", "1234567", "qwerty", 
            "111111", "123123", "password123", "admin", "welcome", "google", "unknown", 
            "123321", "aaaaaa", "1234567890", "monkey", "letmein", "sunshine", "login", 
            "master", "football", "baseball", "princess", "dragon", "shadow", "pass",
            "computer", "system", "network", "access", "hunter2", "charlie", "mustang",
            "superman", "batman", "iloveyou", "nothing", "secret", "number1", "server",
        ];

        for password in common_passwords {
             let cracked = match hash_type {
                "MD5" => {
                    let result = md5::compute(password.as_bytes());
                    format!("{:x}", result) == text
                },
                "SHA1" => {
                    let mut hasher = Sha1::new();
                    hasher.update(password.as_bytes());
                    let result = hasher.finalize();
                    hex::encode(result) == text
                },
                "SHA256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(password.as_bytes());
                    let result = hasher.finalize();
                    hex::encode(result) == text
                },
                _ => false,
            };

            if cracked {
                debug!("Hash cracked! Password is: {}", password);
                
                if !check_string_success(password, &text) {
                     continue;
                }
                
                let mut checker_result = checker.check(password);
                // Force success since we found the password in our dictionary
                checker_result.is_identified = true;
                results.unencrypted_text = Some(vec![password.to_string()]);
                results.update_checker(&checker_result);
                return results;
            }
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

    fn get_popularity(&self) -> f32 {
        self.popularity
    }
}

#[cfg(test)]
mod tests {
    use super::HashCrackDecoder;
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
    fn test_md5_crack() {
        let decoder = Decoder::<HashCrackDecoder>::new();
        // MD5 of "password"
        let input = "5f4dcc3b5aa765d61d8327deb882cf99";
        let result = decoder.crack(input, &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "password");
    }

    #[test]
    fn test_sha1_crack() {
        let decoder = Decoder::<HashCrackDecoder>::new();
        // SHA1 of "password"
        let input = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        let result = decoder.crack(input, &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "password");
    }

    #[test]
    fn test_sha256_crack() {
        let decoder = Decoder::<HashCrackDecoder>::new();
        // SHA256 of "password"
        let input = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        let result = decoder.crack(input, &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "password");
    }
}
