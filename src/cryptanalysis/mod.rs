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

/// Load the 10000 most common English words
static ENGLISH_WORDS_10K: Lazy<Vec<&'static str>> = Lazy::new(|| {
    include_str!("../storage/wordlists/english_10000.txt")
        .lines()
        .filter(|line| !line.is_empty() && line.len() >= 3)
        .collect()
});

/// Load cipher-specific keywords
static CIPHER_KEYWORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    include_str!("../storage/wordlists/cipher_keywords.txt")
        .lines()
        .filter(|line| !line.is_empty() && line.len() >= 3)
        .collect()
});

/// Combined wordlist for cipher key attacks (lowercase)
pub static ATTACK_WORDLIST: Lazy<Vec<String>> = Lazy::new(|| {
    let mut words: Vec<String> = Vec::new();
    
    // Add cipher keywords first (higher priority)
    for word in CIPHER_KEYWORDS.iter() {
        words.push(word.to_lowercase());
        words.push(word.to_uppercase());
    }
    
    // Add common English words (only those 4-15 chars - typical key length)
    for word in ENGLISH_WORDS_10K.iter() {
        if word.len() >= 4 && word.len() <= 15 {
            words.push(word.to_lowercase());
            words.push(word.to_uppercase());
        }
    }
    
    // Remove duplicates while preserving order
    let mut seen = HashSet::new();
    words.retain(|w| seen.insert(w.clone()));
    
    words
});

/// Common English words for word detection (fast lookup)
pub static COMMON_ENGLISH_SET: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ENGLISH_WORDS_10K.iter().cloned().collect()
});

/// English letter frequencies (A-Z) as percentages
pub const ENGLISH_LETTER_FREQ: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,  // A-G
    6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749,   // H-N
    7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,   // O-U
    0.978, 2.360, 0.150, 1.974, 0.074,                  // V-Z
];

/// English bigram frequencies (log probabilities)
pub static ENGLISH_BIGRAM_SCORES: Lazy<HashMap<(char, char), f64>> = Lazy::new(|| {
    let mut scores = HashMap::new();
    // Common English bigrams with their approximate log probabilities
    let bigrams = [
        ("TH", -1.8), ("HE", -1.9), ("IN", -2.1), ("ER", -2.2), ("AN", -2.3),
        ("RE", -2.4), ("ON", -2.5), ("AT", -2.5), ("EN", -2.6), ("ND", -2.6),
        ("TI", -2.7), ("ES", -2.7), ("OR", -2.8), ("TE", -2.8), ("OF", -2.9),
        ("ED", -2.9), ("IS", -3.0), ("IT", -3.0), ("AL", -3.1), ("AR", -3.1),
        ("ST", -3.2), ("TO", -3.2), ("NT", -3.3), ("NG", -3.3), ("SE", -3.4),
        ("HA", -3.4), ("AS", -3.5), ("OU", -3.5), ("IO", -3.6), ("LE", -3.6),
        ("VE", -3.7), ("CO", -3.7), ("ME", -3.8), ("DE", -3.8), ("HI", -3.9),
        ("RI", -3.9), ("RO", -4.0), ("IC", -4.0), ("NE", -4.1), ("EA", -4.1),
        ("RA", -4.2), ("CE", -4.2), ("LI", -4.3), ("CH", -4.3), ("LL", -4.4),
        ("BE", -4.4), ("MA", -4.5), ("SI", -4.5), ("OM", -4.6), ("UR", -4.6),
        ("CA", -4.7), ("EL", -4.7), ("TA", -4.8), ("LA", -4.8), ("NS", -4.9),
        ("DI", -4.9), ("FO", -5.0), ("HO", -5.0), ("PE", -5.1), ("EC", -5.1),
        ("PR", -5.2), ("NO", -5.2), ("CT", -5.3), ("US", -5.3), ("AC", -5.4),
        ("OT", -5.4), ("IL", -5.5), ("TR", -5.5), ("LY", -5.6), ("NC", -5.6),
        ("ET", -5.7), ("UT", -5.7), ("SS", -5.8), ("SO", -5.8), ("RS", -5.9),
        ("UN", -5.9), ("LO", -6.0), ("WA", -6.0), ("GE", -6.1), ("IE", -6.1),
        ("WH", -6.2), ("EE", -6.2), ("WI", -6.3), ("EM", -6.3), ("AD", -6.4),
        ("OL", -6.4), ("RT", -6.5), ("PO", -6.5), ("WE", -6.6), ("NA", -6.6),
        ("UL", -6.7), ("NI", -6.7), ("TS", -6.8), ("MO", -6.8), ("OW", -6.9),
        ("PA", -6.9), ("IM", -7.0), ("MI", -7.0), ("AI", -7.1), ("SH", -7.1),
    ];
    
    for (bigram, score) in bigrams.iter() {
        let chars: Vec<char> = bigram.chars().collect();
        if chars.len() == 2 {
            scores.insert((chars[0], chars[1]), *score);
        }
    }
    
    scores
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

/// Score text using bigram statistics
/// Higher scores indicate more English-like text
pub fn bigram_score(text: &str) -> f64 {
    let text: String = text.to_uppercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    
    if text.len() < 2 {
        return f64::MIN;
    }
    
    let chars: Vec<char> = text.chars().collect();
    let mut score = 0.0;
    let mut count = 0;
    
    for window in chars.windows(2) {
        let bigram = (window[0], window[1]);
        score += ENGLISH_BIGRAM_SCORES.get(&bigram).unwrap_or(&-10.0);
        count += 1;
    }
    
    if count > 0 {
        score / count as f64  // Normalize by bigram count
    } else {
        f64::MIN
    }
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
        .filter(|w| COMMON_ENGLISH_SET.contains(*w))
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
    let bigram = bigram_score(text);
    
    // IC close to 0.0667 is good (English)
    let ic_score = -((ic - 0.0667).abs() * 500.0);
    
    // Lower chi-squared is better (max penalty -100)
    let chi_score = -(chi_sq.min(100.0));
    
    // Higher word percentage is better
    let word_bonus = word_pct * 5.0;
    
    // Bigram score (already normalized)
    let bigram_bonus = bigram * 20.0;
    
    // Combine all scores
    ic_score + chi_score + word_bonus + bigram_bonus
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
    let bigram = bigram_score(text);
    
    // IC should be close to English (0.0667)
    let ic_ok = ic > 0.045 && ic < 0.085;
    
    // Chi-squared should be relatively low
    let chi_ok = chi_sq < 80.0;
    
    // Should contain some recognizable words (if spaced)
    let words_ok = word_pct > 10.0;
    
    // Bigram score should be reasonable (for concatenated text)
    // Good English bigram score is around -4 to -6
    let bigram_ok = bigram > -7.0;
    
    // For text with spaces, prioritize word detection
    let has_spaces = text.contains(' ');
    
    if has_spaces {
        // Spaced text: require word detection OR (IC + chi_sq + bigram)
        words_ok || ((ic_ok as u8) + (chi_ok as u8) + (bigram_ok as u8) >= 2)
    } else {
        // Concatenated text: require IC + chi_sq + bigram (at least 2 of 3)
        (ic_ok as u8) + (chi_ok as u8) + (bigram_ok as u8) >= 2
    }
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
    pub max_iterations: usize,
    pub max_restarts: usize,
}

impl Default for HillClimber {
    fn default() -> Self {
        HillClimber {
            max_iterations: 10000,
            max_restarts: 10,
        }
    }
}

impl HillClimber {
    pub fn new(max_iterations: usize, max_restarts: usize) -> Self {
        HillClimber {
            max_iterations,
            max_restarts,
        }
    }
}

/// Simple LCG for pseudo-random numbers
pub fn lcg_next(state: u64) -> u64 {
    state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)
}

/// Get current time as seed
pub fn time_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_loaded() {
        assert!(ATTACK_WORDLIST.len() > 1000, "Wordlist should have >1000 words");
        assert!(COMMON_ENGLISH_SET.len() > 5000, "English set should have >5000 words");
    }

    #[test]
    fn test_index_of_coincidence_english() {
        let english_text = "The quick brown fox jumps over the lazy dog. The cat sat on the mat and looked at the birds flying in the sky.";
        let ic = index_of_coincidence(english_text);
        assert!(ic > 0.04 && ic < 0.09, "IC was {}", ic);
    }

    #[test]
    fn test_chi_squared_english() {
        let english_text = "The quick brown fox jumps over the lazy dog and runs through the forest";
        let chi_sq = chi_squared_score(english_text);
        assert!(chi_sq < 100.0, "Chi-squared was {}", chi_sq);
    }

    #[test]
    fn test_word_score() {
        let text = "the quick brown fox jumps over the lazy dog";
        let score = word_score(text);
        assert!(score > 30.0, "Word score was {}", score);
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
    fn test_is_likely_english_spaced() {
        let english = "The quick brown fox jumps over the lazy dog repeatedly";
        let gibberish = "xkqjzpfmwlcbndyahgortevius";
        
        assert!(is_likely_english(english), "Should detect English text");
        assert!(!is_likely_english(gibberish), "Should not detect gibberish as English");
    }

    #[test]
    fn test_is_likely_english_concatenated() {
        // Concatenated English text (like from Playfair)
        let concat_english = "thequickbrownfoxjumpsoverthelazydogandthecatsatonthemat";
        assert!(is_likely_english(concat_english), 
            "Should detect concatenated English text");
    }

    #[test]
    fn test_bigram_score() {
        let english = "THE QUICK BROWN FOX";
        let gibberish = "XZQJKPFMWL";
        
        let english_score = bigram_score(english);
        let gibberish_score = bigram_score(gibberish);
        
        assert!(english_score > gibberish_score,
            "English bigram score {} should be higher than gibberish {}", 
            english_score, gibberish_score);
    }
}
