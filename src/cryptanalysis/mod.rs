//! Cryptanalysis module for advanced cipher breaking
//! 
//! This module provides tools for:
//! - Text scoring and fitness functions
//! - Dictionary/wordlist management for key attacks
//! - Frequency analysis utilities
//! - Hill climbing and optimization algorithms
//! - Index of Coincidence calculations

use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};

/// Common English words for dictionary attacks (embedded)
/// This is a curated list of common passwords, words, and cipher keys
pub static COMMON_WORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        // Common passwords and keys
        "password", "secret", "key", "cipher", "crypto", "code", "hidden",
        "mystery", "puzzle", "enigma", "secure", "private", "public",
        // Common English words used as keys
        "the", "and", "for", "are", "but", "not", "you", "all", "can", "her",
        "was", "one", "our", "out", "day", "get", "has", "him", "his", "how",
        "its", "may", "new", "now", "old", "see", "two", "way", "who", "boy",
        "did", "own", "say", "she", "too", "use", "hello", "world", "test",
        // Names commonly used as keys
        "alice", "bob", "charlie", "david", "edward", "frank", "george",
        "henry", "ivan", "jack", "kevin", "larry", "mary", "nancy", "oscar",
        "peter", "queen", "robert", "steve", "thomas", "uncle", "victor",
        "william", "xavier", "young", "zebra", "james", "john", "michael",
        // CTF common keys
        "flag", "ctf", "hack", "admin", "root", "user", "pass", "login",
        "security", "network", "system", "computer", "program", "software",
        // Classical cipher keywords
        "keyword", "example", "playfair", "vigenere", "caesar", "atbash",
        "monarch", "kingdom", "republic", "empire", "palace", "castle",
        "knight", "dragon", "wizard", "magic", "spell", "potion",
        // Military/Historical
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
        "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
        "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
        "victor", "whiskey", "xray", "yankee", "zulu",
        // Numbers as words
        "zero", "one", "two", "three", "four", "five", "six", "seven",
        "eight", "nine", "ten", "hundred", "thousand", "million",
        // Colors
        "red", "blue", "green", "yellow", "orange", "purple", "black",
        "white", "pink", "brown", "gray", "gold", "silver",
        // Animals
        "cat", "dog", "bird", "fish", "lion", "tiger", "bear", "wolf",
        "fox", "eagle", "snake", "horse", "deer", "rabbit", "mouse",
        // Time-related
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
        "sunday", "january", "february", "march", "april", "june", "july",
        "august", "september", "october", "november", "december",
        // Tech terms
        "linux", "windows", "apple", "google", "amazon", "facebook",
        "twitter", "github", "python", "java", "rust", "code",
        // More common words
        "love", "hate", "life", "death", "time", "space", "fire", "water",
        "earth", "wind", "light", "dark", "good", "evil", "truth", "lies",
        "hope", "fear", "peace", "war", "friend", "enemy", "home", "work",
        // Uppercase versions will be generated programmatically
    ]
});

/// Extended wordlist with variations (uppercase, title case)
pub static EXTENDED_WORDLIST: Lazy<Vec<String>> = Lazy::new(|| {
    let mut words = Vec::new();
    for word in COMMON_WORDS.iter() {
        // Original lowercase
        words.push(word.to_string());
        // Uppercase
        words.push(word.to_uppercase());
        // Title case
        let mut chars: Vec<char> = word.chars().collect();
        if !chars.is_empty() {
            chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
            words.push(chars.into_iter().collect());
        }
    }
    words
});

/// English letter frequencies (A-Z) as percentages
pub const ENGLISH_LETTER_FREQ: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,  // A-G
    6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749,   // H-N
    7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,   // O-U
    0.978, 2.360, 0.150, 1.974, 0.074,                  // V-Z
];

/// English bigram log probabilities (precomputed for speed)
pub static ENGLISH_BIGRAM_SCORES: Lazy<HashMap<(char, char), f64>> = Lazy::new(|| {
    let mut scores = HashMap::new();
    // Common English bigrams with their approximate log probabilities
    let bigrams = [
        ("TH", -2.0), ("HE", -2.1), ("IN", -2.3), ("ER", -2.4), ("AN", -2.5),
        ("RE", -2.6), ("ON", -2.7), ("AT", -2.8), ("EN", -2.8), ("ND", -2.9),
        ("TI", -3.0), ("ES", -3.0), ("OR", -3.1), ("TE", -3.1), ("OF", -3.2),
        ("ED", -3.2), ("IS", -3.3), ("IT", -3.3), ("AL", -3.4), ("AR", -3.4),
        ("ST", -3.5), ("TO", -3.5), ("NT", -3.6), ("NG", -3.6), ("SE", -3.7),
        ("HA", -3.7), ("AS", -3.8), ("OU", -3.8), ("IO", -3.9), ("LE", -3.9),
        ("VE", -4.0), ("CO", -4.0), ("ME", -4.1), ("DE", -4.1), ("HI", -4.2),
        ("RI", -4.2), ("RO", -4.3), ("IC", -4.3), ("NE", -4.4), ("EA", -4.4),
        ("RA", -4.5), ("CE", -4.5), ("LI", -4.6), ("CH", -4.6), ("LL", -4.7),
        ("BE", -4.7), ("MA", -4.8), ("SI", -4.8), ("OM", -4.9), ("UR", -4.9),
    ];
    
    for (bigram, score) in bigrams.iter() {
        let chars: Vec<char> = bigram.chars().collect();
        if chars.len() == 2 {
            scores.insert((chars[0], chars[1]), *score);
        }
    }
    
    scores
});

/// Common English words set for fast lookup
pub static COMMON_ENGLISH_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let words = [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
        "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
        "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
        "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
        "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
        "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
        "people", "into", "year", "your", "good", "some", "could", "them", "see", "other",
        "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
        "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
        "even", "new", "want", "because", "any", "these", "give", "day", "most", "us",
        "is", "was", "are", "been", "has", "had", "were", "said", "each", "here",
        "hello", "world", "test", "flag", "password", "secret", "key", "code", "cipher",
    ];
    words.iter().cloned().collect()
});

/// Calculate the Index of Coincidence for a text
/// IC ≈ 0.0667 for English, ≈ 0.0385 for random text
pub fn index_of_coincidence(text: &str) -> f64 {
    let text: String = text.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    if text.len() < 2 {
        return 0.0;
    }
    
    let mut freq = [0u64; 26];
    for c in text.chars() {
        let idx = (c as u8 - b'A') as usize;
        freq[idx] += 1;
    }
    
    let n = text.len() as f64;
    let sum: f64 = freq.iter()
        .map(|&f| (f as f64) * (f as f64 - 1.0))
        .sum();
    
    sum / (n * (n - 1.0))
}

/// Calculate chi-squared statistic comparing text frequencies to English
/// Lower values indicate closer match to English
pub fn chi_squared_score(text: &str) -> f64 {
    let text: String = text.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    if text.is_empty() {
        return f64::MAX;
    }
    
    let n = text.len() as f64;
    let mut freq = [0u64; 26];
    
    for c in text.chars() {
        let idx = (c as u8 - b'A') as usize;
        freq[idx] += 1;
    }
    
    let mut chi_sq = 0.0;
    for i in 0..26 {
        let observed = freq[i] as f64;
        let expected = n * (ENGLISH_LETTER_FREQ[i] / 100.0);
        if expected > 0.0 {
            chi_sq += (observed - expected).powi(2) / expected;
        }
    }
    
    chi_sq
}

/// Score text using quadgram statistics (simplified)
/// Higher scores indicate more English-like text
pub fn quadgram_score(text: &str) -> f64 {
    let text: String = text.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    if text.len() < 4 {
        return f64::MIN;
    }
    
    let chars: Vec<char> = text.chars().collect();
    let mut score = 0.0;
    
    // Use bigrams as approximation (quadgrams would require large lookup table)
    for window in chars.windows(2) {
        let bigram = (window[0], window[1]);
        score += ENGLISH_BIGRAM_SCORES.get(&bigram).unwrap_or(&-10.0);
    }
    
    score
}

/// Score text based on English word detection
/// Returns percentage of text that consists of recognized words
pub fn word_score(text: &str) -> f64 {
    let text_lower = text.to_lowercase();
    let words: Vec<&str> = text_lower
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| w.len() >= 2)
        .collect();
    
    if words.is_empty() {
        return 0.0;
    }
    
    let recognized: usize = words.iter()
        .filter(|w| COMMON_ENGLISH_WORDS.contains(*w))
        .map(|w| w.len())
        .sum();
    
    let total: usize = words.iter().map(|w| w.len()).sum();
    
    if total == 0 {
        0.0
    } else {
        (recognized as f64 / total as f64) * 100.0
    }
}

/// Combined fitness score for plaintext detection
/// Higher scores indicate more likely plaintext
pub fn fitness_score(text: &str) -> f64 {
    if text.is_empty() {
        return f64::MIN;
    }
    
    let ic = index_of_coincidence(text);
    let chi_sq = chi_squared_score(text);
    let word_pct = word_score(text);
    let bigram = quadgram_score(text);
    
    // Combine scores with weights
    // IC close to 0.0667 is good (English)
    let ic_score = -((ic - 0.0667).abs() * 1000.0);
    
    // Lower chi-squared is better
    let chi_score = -chi_sq;
    
    // Higher word percentage is better
    let word_bonus = word_pct * 10.0;
    
    // Combine all scores
    ic_score + chi_score + word_bonus + bigram
}

/// Check if text is likely English plaintext
/// Handles both spaced text and concatenated text (like from Playfair cipher)
pub fn is_likely_english(text: &str) -> bool {
    if text.len() < 10 {
        return false;
    }
    
    let ic = index_of_coincidence(text);
    let chi_sq = chi_squared_score(text);
    let word_pct = word_score(text);
    let bigram = quadgram_score(text);
    
    // IC should be close to English (0.0667)
    // Allow wider range for short texts
    let ic_ok = ic > 0.04 && ic < 0.09;
    
    // Chi-squared should be relatively low
    let chi_ok = chi_sq < 100.0;
    
    // Should contain some recognizable words
    let words_ok = word_pct > 15.0;
    
    // Bigram score should be reasonable (not too negative)
    // This helps with concatenated text that has no word boundaries
    let bigram_ok = bigram > -300.0;
    
    // At least 2 of 4 conditions should pass
    // This allows concatenated text (no spaces) to pass via IC + chi_sq + bigram
    let score = (ic_ok as u8) + (chi_ok as u8) + (words_ok as u8) + (bigram_ok as u8);
    score >= 2
}

/// Estimate key length for polyalphabetic ciphers using IC
pub fn estimate_key_length(ciphertext: &str, max_length: usize) -> Vec<(usize, f64)> {
    let text: String = ciphertext.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    let mut results = Vec::new();
    
    for key_len in 1..=max_length.min(text.len() / 3) {
        let mut total_ic = 0.0;
        
        for offset in 0..key_len {
            let column: String = text.chars()
                .skip(offset)
                .step_by(key_len)
                .collect();
            
            total_ic += index_of_coincidence(&column);
        }
        
        let avg_ic = total_ic / key_len as f64;
        results.push((key_len, avg_ic));
    }
    
    // Sort by IC (higher is better for English)
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

/// Get the frequency distribution of a text
pub fn get_frequency_distribution(text: &str) -> [f64; 26] {
    let text: String = text.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    let mut freq = [0u64; 26];
    for c in text.chars() {
        let idx = (c as u8 - b'A') as usize;
        freq[idx] += 1;
    }
    
    let total = text.len() as f64;
    let mut dist = [0.0; 26];
    
    if total > 0.0 {
        for i in 0..26 {
            dist[i] = (freq[i] as f64 / total) * 100.0;
        }
    }
    
    dist
}

/// Hill climbing optimizer for key search
pub struct HillClimber {
    /// Maximum iterations
    pub max_iterations: usize,
    /// Whether to restart on local maximum
    pub restart_on_plateau: bool,
    /// Number of restarts allowed
    pub max_restarts: usize,
}

impl Default for HillClimber {
    fn default() -> Self {
        HillClimber {
            max_iterations: 10000,
            restart_on_plateau: true,
            max_restarts: 5,
        }
    }
}

impl HillClimber {
    /// Create a new hill climber with custom settings
    pub fn new(max_iterations: usize, max_restarts: usize) -> Self {
        HillClimber {
            max_iterations,
            restart_on_plateau: true,
            max_restarts,
        }
    }
    
    /// Optimize a substitution cipher key using hill climbing
    /// Returns (best_key, best_score)
    pub fn optimize_substitution<F>(
        &self,
        ciphertext: &str,
        decrypt_fn: F,
    ) -> (String, f64)
    where
        F: Fn(&str, &str) -> String,
    {
        let mut best_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();
        let mut best_score = fitness_score(&decrypt_fn(ciphertext, &best_key));
        
        for _restart in 0..self.max_restarts {
            // Random starting key
            let mut current_key = random_alphabet();
            let mut current_score = fitness_score(&decrypt_fn(ciphertext, &current_key));
            
            let mut plateau_count = 0;
            
            for _iter in 0..self.max_iterations {
                // Try swapping two random letters
                let new_key = swap_two_letters(&current_key);
                let new_score = fitness_score(&decrypt_fn(ciphertext, &new_key));
                
                if new_score > current_score {
                    current_key = new_key;
                    current_score = new_score;
                    plateau_count = 0;
                } else {
                    plateau_count += 1;
                }
                
                if plateau_count > 1000 && self.restart_on_plateau {
                    break;
                }
            }
            
            if current_score > best_score {
                best_key = current_key;
                best_score = current_score;
            }
        }
        
        (best_key, best_score)
    }
}

/// Generate a random alphabet permutation
fn random_alphabet() -> String {
    let mut chars: Vec<char> = ('A'..='Z').collect();
    
    // Fisher-Yates shuffle using simple pseudo-random
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345);
    
    let mut rng = seed;
    for i in (1..chars.len()).rev() {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (rng as usize) % (i + 1);
        chars.swap(i, j);
    }
    
    chars.into_iter().collect()
}

/// Swap two random letters in a key
fn swap_two_letters(key: &str) -> String {
    let mut chars: Vec<char> = key.chars().collect();
    if chars.len() < 2 {
        return key.to_string();
    }
    
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345);
    
    let mut rng = seed;
    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
    let i = (rng as usize) % chars.len();
    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
    let j = (rng as usize) % chars.len();
    
    chars.swap(i, j);
    chars.into_iter().collect()
}

/// Dictionary attack helper - try all words in wordlist as keys
pub fn dictionary_attack<F>(
    ciphertext: &str,
    decrypt_fn: F,
    min_score: f64,
) -> Vec<(String, String, f64)>
where
    F: Fn(&str, &str) -> String,
{
    let mut results = Vec::new();
    
    for word in EXTENDED_WORDLIST.iter() {
        let plaintext = decrypt_fn(ciphertext, word);
        let score = fitness_score(&plaintext);
        
        if score > min_score {
            results.push((word.clone(), plaintext, score));
        }
    }
    
    // Sort by score (highest first)
    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    results
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_of_coincidence_english() {
        let english_text = "The quick brown fox jumps over the lazy dog. This is a sample English text that should have a normal index of coincidence.";
        let ic = index_of_coincidence(english_text);
        // English IC should be around 0.0667, but short texts may vary
        // Allow a wider range for short texts
        assert!(ic > 0.03 && ic < 0.09, "IC was {}", ic);
    }

    #[test]
    fn test_index_of_coincidence_random() {
        let random_text = "XKJQZPFMWLCBNDYAHGORTEVIUS";
        let ic = index_of_coincidence(random_text);
        // Random text IC should be around 0.0385
        assert!(ic < 0.06, "IC was {}", ic);
    }

    #[test]
    fn test_chi_squared_english() {
        let english_text = "The quick brown fox jumps over the lazy dog and runs through the forest";
        let chi_sq = chi_squared_score(english_text);
        // English should have relatively low chi-squared
        assert!(chi_sq < 100.0, "Chi-squared was {}", chi_sq);
    }

    #[test]
    fn test_word_score() {
        let text = "the quick brown fox jumps over the lazy dog";
        let score = word_score(text);
        // Should recognize some words (our dictionary is limited)
        assert!(score > 20.0, "Word score was {}", score);
    }

    #[test]
    fn test_fitness_score_english() {
        let english = "Hello world this is a test of the fitness scoring function";
        let gibberish = "xkqjzpfmwlcbndyahgortevius";
        
        let english_score = fitness_score(english);
        let gibberish_score = fitness_score(gibberish);
        
        assert!(english_score > gibberish_score, 
            "English score {} should be higher than gibberish score {}", 
            english_score, gibberish_score);
    }

    #[test]
    fn test_is_likely_english() {
        let english = "The quick brown fox jumps over the lazy dog repeatedly";
        let gibberish = "xkqjzpfmwlcbndyahgortevius";
        
        assert!(is_likely_english(english), "Should detect English");
        assert!(!is_likely_english(gibberish), "Should not detect gibberish as English");
    }

    #[test]
    fn test_estimate_key_length() {
        // Simple test with known key length
        let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let results = estimate_key_length(text, 10);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_common_words_not_empty() {
        assert!(!COMMON_WORDS.is_empty());
        assert!(COMMON_WORDS.len() > 100);
    }

    #[test]
    fn test_extended_wordlist() {
        assert!(!EXTENDED_WORDLIST.is_empty());
        // Should have 3x original (lowercase, uppercase, title case)
        assert!(EXTENDED_WORDLIST.len() >= COMMON_WORDS.len() * 3);
    }

    #[test]
    fn test_hill_climber_creation() {
        let climber = HillClimber::default();
        assert_eq!(climber.max_iterations, 10000);
        assert_eq!(climber.max_restarts, 5);
    }
}
