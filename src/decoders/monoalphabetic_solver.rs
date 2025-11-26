//! Monoalphabetic substitution cipher solver using hill climbing
//! This decoder attempts to break simple monoalphabetic substitution ciphers
//! by using frequency analysis and hill climbing optimization.
//!
//! A monoalphabetic cipher replaces each letter with another letter consistently
//! throughout the message. This solver uses statistical analysis to find the
//! correct key mapping.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::cryptanalysis::{fitness_score, is_likely_english};
use gibberish_or_not::Sensitivity;
use log::{debug, trace};

/// Monoalphabetic substitution cipher solver
pub struct MonoalphabeticSolver;

impl Crack for Decoder<MonoalphabeticSolver> {
    fn new() -> Decoder<MonoalphabeticSolver> {
        Decoder {
            name: "Monoalphabetic",
            description: "Solves monoalphabetic substitution ciphers using frequency analysis and hill climbing. Each letter in the ciphertext maps to exactly one letter in the plaintext.",
            link: "https://en.wikipedia.org/wiki/Substitution_cipher#Simple_substitution",
            tags: vec!["substitution", "classical", "cipher", "monoalphabetic"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Monoalphabetic solver with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Clean text - only alphabetic
        let clean_text: String = text.to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect();

        // Need enough text for statistical analysis
        if clean_text.len() < 30 {
            debug!("Text too short for monoalphabetic analysis (need at least 30 chars)");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Medium);

        // PHASE 1: Try frequency analysis first
        trace!("Phase 1: Frequency analysis");
        if let Some((key, _decoded)) = frequency_analysis_solve(&clean_text) {
            let decoded_with_case = apply_key_preserve_case(text, &key);
            let decoded_lower = decoded_with_case.to_lowercase();
            
            let checker_result = checker_with_sensitivity.check(&decoded_lower, config);
            if checker_result.is_identified {
                debug!("Frequency analysis succeeded");
                results.unencrypted_text = Some(vec![decoded_lower]);
                results.update_checker(&checker_result);
                results.key = Some(key);
                return results;
            }
        }

        // PHASE 2: Hill climbing optimization
        trace!("Phase 2: Hill climbing optimization");
        if let Some((key, _decoded)) = hill_climb_solve(&clean_text, 5000, 5) {
            let decoded_with_case = apply_key_preserve_case(text, &key);
            let decoded_lower = decoded_with_case.to_lowercase();
            
            if is_likely_english(&decoded_lower) {
                let checker_result = checker_with_sensitivity.check(&decoded_lower, config);
                if checker_result.is_identified {
                    debug!("Hill climbing succeeded with key: {}", key);
                    results.unencrypted_text = Some(vec![decoded_lower]);
                    results.update_checker(&checker_result);
                    results.key = Some(key);
                    return results;
                }
            }
        }

        debug!("Failed to decode monoalphabetic cipher");
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

/// Solve using frequency analysis
/// Returns the key and decoded text if successful
fn frequency_analysis_solve(ciphertext: &str) -> Option<(String, String)> {
    // Count letter frequencies in ciphertext
    let mut freq = [0u32; 26];
    for c in ciphertext.chars() {
        if c.is_ascii_uppercase() {
            let idx = (c as u8 - b'A') as usize;
            freq[idx] += 1;
        }
    }
    
    // Sort ciphertext letters by frequency (highest first)
    let mut cipher_order: Vec<(usize, u32)> = freq.iter()
        .enumerate()
        .map(|(i, &f)| (i, f))
        .collect();
    cipher_order.sort_by(|a, b| b.1.cmp(&a.1));
    
    // Standard English letter frequency order (E, T, A, O, I, N, S, H, R, ...)
    let english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    let english_chars: Vec<char> = english_order.chars().collect();
    
    // Create initial key mapping based on frequency
    let mut key = ['A'; 26];
    for (i, (cipher_idx, _)) in cipher_order.iter().enumerate() {
        key[*cipher_idx] = english_chars[i];
    }
    
    let key_str: String = key.iter().collect();
    let decoded = apply_key(ciphertext, &key_str);
    
    Some((key_str, decoded))
}

/// Solve using hill climbing optimization
fn hill_climb_solve(ciphertext: &str, max_iterations: usize, restarts: usize) -> Option<(String, String)> {
    let mut best_key = String::new();
    let mut best_score = f64::MIN;
    let mut best_decoded = String::new();
    
    // Get seed for pseudo-random
    let base_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345);
    
    for restart in 0..restarts {
        let mut rng = base_seed.wrapping_add(restart as u64);
        
        // Start with frequency analysis key
        let mut current_key: Vec<char> = if restart == 0 {
            if let Some((key, _)) = frequency_analysis_solve(ciphertext) {
                key.chars().collect()
            } else {
                ('A'..='Z').collect()
            }
        } else {
            // Random key for other restarts
            let mut key: Vec<char> = ('A'..='Z').collect();
            for i in (1..26).rev() {
                rng = lcg_next(rng);
                let j = (rng as usize) % (i + 1);
                key.swap(i, j);
            }
            key
        };
        
        let mut current_decoded = apply_key_vec(ciphertext, &current_key);
        let mut current_score = fitness_score(&current_decoded);
        
        let mut plateau_count = 0;
        
        for _ in 0..max_iterations {
            // Try swapping two random letters in the key
            rng = lcg_next(rng);
            let i = (rng as usize) % 26;
            rng = lcg_next(rng);
            let j = (rng as usize) % 26;
            
            if i == j {
                continue;
            }
            
            // Swap
            current_key.swap(i, j);
            let new_decoded = apply_key_vec(ciphertext, &current_key);
            let new_score = fitness_score(&new_decoded);
            
            if new_score > current_score {
                current_decoded = new_decoded;
                current_score = new_score;
                plateau_count = 0;
            } else {
                // Undo swap
                current_key.swap(i, j);
                plateau_count += 1;
            }
            
            // Early exit on plateau
            if plateau_count > 500 {
                break;
            }
        }
        
        if current_score > best_score {
            best_score = current_score;
            best_key = current_key.iter().collect();
            best_decoded = current_decoded;
        }
    }
    
    if best_key.is_empty() {
        None
    } else {
        Some((best_key, best_decoded))
    }
}

/// Simple LCG for pseudo-random numbers
fn lcg_next(state: u64) -> u64 {
    state.wrapping_mul(6364136223846793005).wrapping_add(1)
}

/// Apply a substitution key to ciphertext (uppercase only)
fn apply_key(ciphertext: &str, key: &str) -> String {
    let key_chars: Vec<char> = key.chars().collect();
    ciphertext.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                let idx = (c as u8 - b'A') as usize;
                key_chars[idx]
            } else {
                c
            }
        })
        .collect()
}

/// Apply a substitution key (vector version)
fn apply_key_vec(ciphertext: &str, key: &[char]) -> String {
    ciphertext.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                let idx = (c as u8 - b'A') as usize;
                key[idx]
            } else {
                c
            }
        })
        .collect()
}

/// Apply key while preserving original case
fn apply_key_preserve_case(original: &str, key: &str) -> String {
    let key_chars: Vec<char> = key.chars().collect();
    original.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let idx = (c.to_ascii_uppercase() as u8 - b'A') as usize;
                let new_char = key_chars[idx];
                if c.is_ascii_lowercase() {
                    new_char.to_ascii_lowercase()
                } else {
                    new_char
                }
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_monoalphabetic_solver_creation() {
        let decoder = Decoder::<MonoalphabeticSolver>::new();
        assert_eq!(decoder.name, "Monoalphabetic");
    }

    #[test]
    fn test_apply_key() {
        // Simple test: key that maps A->B, B->C, etc.
        let key = "BCDEFGHIJKLMNOPQRSTUVWXYZA";
        let ciphertext = "ABC";
        let result = apply_key(ciphertext, key);
        assert_eq!(result, "BCD");
    }

    #[test]
    fn test_apply_key_preserve_case() {
        let key = "BCDEFGHIJKLMNOPQRSTUVWXYZA";
        let original = "Abc XYZ";
        let result = apply_key_preserve_case(original, key);
        assert_eq!(result, "Bcd YZA");
    }

    #[test]
    fn test_frequency_analysis_returns_key() {
        let text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
        if let Some((key, _decoded)) = frequency_analysis_solve(text) {
            assert_eq!(key.len(), 26);
        } else {
            panic!("Frequency analysis should return a key");
        }
    }

    #[test]
    fn test_short_text_rejected() {
        let decoder = Decoder::<MonoalphabeticSolver>::new();
        let result = decoder.crack("SHORT", &get_athena_checker(), &Config::default());
        assert!(result.unencrypted_text.is_none());
    }
}
