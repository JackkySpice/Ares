//! Proposal: https://broadleaf-angora-7db.notion.site/Filtration-System-7143b36a42f1466faea3077bfc7e859e
//! Given a filter object, return an array of decoders/crackers which have been filtered

use std::sync::mpsc::channel;

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::crack_results::CrackResult;
use crate::decoders::interface::Crack;
use crate::decoders::DECODER_MAP;
use crate::DecoderResult;

use log::trace;
use rayon::prelude::*;

/// The struct which contains all of the decoders
/// Where decoders is crackers, decryptors, etc.
/// This contains a public attribute Components
/// Which contains all of them. See `pub fn run` which is impl'd on
/// the Decoders for the Crack trait in action.
/// Relevant docs: https://doc.rust-lang.org/book/ch17-02-trait-objects.html
pub struct Decoders {
    /// Components is a vector of decoders.
    /// Uses references to static decoders to avoid recreation.
    pub components: Vec<&'static (dyn Crack + Sync + Send)>,
}

impl Decoders {
    /// Iterate over all of the decoders and run .crack(text) on them
    /// Then if the checker succeed, we short-circuit the iterator
    /// and stop all processing as soon as possible.
    /// We are using Trait Objects
    /// https://doc.rust-lang.org/book/ch17-02-trait-objects.html
    /// Which allows us to have multiple different structs in the same vector
    /// But each struct shares the same `.crack()` method, so it's fine.
    ///
    /// # Panics
    /// Panics if the channel sender fails to send a result, which should not happen in normal operation.
    pub fn run(&self, text: &str, checker: &CheckerTypes, config: &Config) -> MyResults {
        trace!("Running .crack() on all decoders");
        let (sender, receiver) = channel();
        self.components
            .par_iter()
            .try_for_each_with(sender, |s, i| {
                let results = i.crack(text, checker, config);
                if results.success {
                    log::debug!(
                        "DEBUG: filtration_system - Decoder {} succeeded, short-circuiting",
                        results.decoder
                    );
                    s.send(results.clone()).expect("expected no send error!");
                    // returning None short-circuits the iterator
                    // we don't process any further as we got success
                    return None;
                }
                log::debug!(
                    "DEBUG: filtration_system - Decoder {} failed, continuing",
                    results.decoder
                );
                s.send(results.clone()).expect("expected no send error!");
                // return Some(()) to indicate that continue processing
                Some(())
            });

        let mut all_results: Vec<CrackResult> = Vec::new();

        while let Ok(result) = receiver.recv() {
            // if we recv success, break.
            if result.success {
                log::debug!(
                    "DEBUG: filtration_system - Received successful result from {}, returning Break",
                    result.decoder
                );
                return MyResults::Break(result);
            }
            all_results.push(result)
        }

        log::debug!(
            "DEBUG: filtration_system - No successful results, returning Continue with {} results",
            all_results.len()
        );
        MyResults::Continue(all_results)
    }
}

/// [`Enum`] for our custom results.
/// if our checker succeed, we return `Break` variant contining [`CrackResult`]
/// else we return `Continue` with the decoded results.
pub enum MyResults {
    /// Variant containing successful [`CrackResult`]
    Break(CrackResult),
    /// Contains [`Vec`] of [`CrackResult`] for further processing
    Continue(Vec<CrackResult>),
}

impl MyResults {
    /// named with _ to pass dead_code warning
    /// as we aren't using it, it's just used in tests
    pub fn _break_value(self) -> Option<CrackResult> {
        match self {
            MyResults::Break(val) => Some(val),
            MyResults::Continue(_) => None,
        }
    }
}

/// Filter struct for decoder filtering
pub struct DecoderFilter {
    /// Tags to include in the filter - decoders must have at least one of these tags
    include_tags: Vec<String>,
    /// Tags to exclude from the filter - decoders must not have any of these tags
    exclude_tags: Vec<String>,
}

impl Default for DecoderFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        DecoderFilter {
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
        }
    }

    /// Add a tag to include
    pub fn include_tag(mut self, tag: &str) -> Self {
        self.include_tags.push(tag.to_string());
        self
    }

    /// Add a tag to exclude
    pub fn exclude_tag(mut self, tag: &str) -> Self {
        self.exclude_tags.push(tag.to_string());
        self
    }

    /// Check if a decoder matches the filter
    pub fn matches(&self, decoder: &(dyn Crack + Sync + Send)) -> bool {
        let tags = decoder.get_tags();

        // If include_tags is not empty, at least one tag must match
        if !self.include_tags.is_empty() {
            let has_included_tag = self
                .include_tags
                .iter()
                .any(|include_tag| tags.iter().any(|tag| *tag == include_tag));

            if !has_included_tag {
                return false;
            }
        }

        // If exclude_tags is not empty, no tag must match
        if !self.exclude_tags.is_empty() {
            let has_excluded_tag = self
                .exclude_tags
                .iter()
                .any(|exclude_tag| tags.iter().any(|tag| *tag == exclude_tag));

            if has_excluded_tag {
                return false;
            }
        }

        true
    }
}

/// Get decoders with the "decoder" tag
pub fn get_decoder_tagged_decoders(text_struct: &DecoderResult) -> Decoders {
    trace!("Getting decoder-tagged decoders");
    let filter = DecoderFilter::new().include_tag("decoder");
    filter_decoders_by_tags(text_struct, &filter)
}

/// Get decoders without the "decoder" tag
pub fn get_non_decoder_tagged_decoders(text_struct: &DecoderResult) -> Decoders {
    trace!("Getting non-decoder-tagged decoders");
    let filter = DecoderFilter::new().exclude_tag("decoder");
    filter_decoders_by_tags(text_struct, &filter)
}

/// Filter decoders based on custom tags
pub fn filter_decoders_by_tags(_text_struct: &DecoderResult, filter: &DecoderFilter) -> Decoders {
    trace!("Filtering decoders by tags");

    // Get all decoders
    let all_decoders = get_all_decoders();

    // Filter decoders based on tags
    let filtered_components = all_decoders
        .components
        .into_iter()
        .filter(|decoder| filter.matches(*decoder))
        .collect();

    Decoders {
        components: filtered_components,
    }
}

/// Get all available decoders
pub fn get_all_decoders() -> Decoders {
    trace!("Getting all decoders");
    filter_and_get_decoders(&DecoderResult::default())
}

/// Uses the DECODER_MAP to get all decoders without re-instantiating them
pub fn filter_and_get_decoders(_text_struct: &DecoderResult) -> Decoders {
    trace!("Getting all decoders from DECODER_MAP");
    
    // Iterate over DECODER_MAP and collect references
    let components = DECODER_MAP.values()
        .map(|decoder_box| decoder_box.get::<()>())
        .collect();

    Decoders {
        components,
    }
}

/// Get a specific decoder by name
pub fn get_decoder_by_name(decoder_name: &str) -> Decoders {
    trace!("Getting decoder by name: {}", decoder_name);
    let all_decoders = get_all_decoders();

    let filtered_components = all_decoders
        .components
        .into_iter()
        .filter(|d| d.get_name() == decoder_name)
        .collect();

    Decoders {
        components: filtered_components,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        DecoderResult,
    };

    use super::{
        filter_and_get_decoders, filter_decoders_by_tags, get_decoder_by_name,
        get_decoder_tagged_decoders, get_non_decoder_tagged_decoders, DecoderFilter,
    };

    #[test]
    fn it_works() {
        let _decoders = filter_and_get_decoders(&DecoderResult::default());
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn decoders_can_call_dot_run() {
        let decoders = filter_and_get_decoders(&DecoderResult::default());
        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        let config = crate::config::Config::default();
        decoders.run("TXIgUm9ib3QgaXMgZ3JlYXQ=", &checker, &config);
        assert_eq!(true, true);
    }

    #[test]
    fn test_decoder_filter_include_tag() {
        let filter = DecoderFilter::new().include_tag("base");
        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify all returned decoders have the "base" tag or a tag starting with "base"
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            let has_base_tag = tags
                .iter()
                .any(|tag| *tag == "base" || tag.starts_with("base"));
            assert!(
                has_base_tag,
                "Decoder {} should have 'base' tag or tag starting with 'base', but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }

        // Ensure we have at least one decoder with the "base" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have at least one decoder with 'base' tag"
        );
    }

    #[test]
    fn test_decoder_filter_exclude_tag() {
        let filter = DecoderFilter::new().exclude_tag("base64");
        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify none of the returned decoders have the "base64" tag
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            assert!(
                !tags.contains(&"base64"),
                "Decoder {} should not have 'base64' tag, but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }

        // Ensure we have some decoders without the "base64" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have some decoders without 'base64' tag"
        );
    }

    #[test]
    fn test_decoder_filter_combined() {
        let filter = DecoderFilter::new()
            .include_tag("base")
            .exclude_tag("base64");

        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify all returned decoders have the "base" tag but not the "base64" tag
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            let has_base_tag = tags
                .iter()
                .any(|tag| *tag == "base" || tag.starts_with("base"));
            assert!(
                has_base_tag,
                "Decoder {} should have 'base' tag or tag starting with 'base', but has tags: {:?}",
                decoder.get_name(),
                tags
            );
            assert!(
                !tags.contains(&"base64"),
                "Decoder {} should not have 'base64' tag, but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }
    }

    #[test]
    fn test_get_decoder_tagged_decoders() {
        let decoders = get_decoder_tagged_decoders(&DecoderResult::default());

        // Check if we have any decoders with the "decoder" tag
        let has_decoder_tag = decoders
            .components
            .iter()
            .any(|decoder| decoder.get_tags().contains(&"decoder"));

        // This test might pass or fail depending on whether any decoders have the "decoder" tag
        // If none have it, we should at least get an empty list
        if !has_decoder_tag {
            assert!(
                decoders.components.is_empty(),
                "If no decoders have the 'decoder' tag, the result should be empty"
            );
        }
    }

    #[test]
    fn test_get_non_decoder_tagged_decoders() {
        let decoders = get_non_decoder_tagged_decoders(&DecoderResult::default());

        // Verify none of the returned decoders have the "decoder" tag
        for decoder in decoders.components.iter() {
            assert!(
                !decoder.get_tags().contains(&"decoder"),
                "Decoder {} should not have 'decoder' tag, but has tags: {:?}",
                decoder.get_name(),
                decoder.get_tags()
            );
        }

        // We should have at least some decoders without the "decoder" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have some decoders without 'decoder' tag"
        );
    }

    #[test]
    fn test_get_decoder_by_name() {
        let decoder_name = "Base64";
        let decoders = get_decoder_by_name(decoder_name);

        assert_eq!(
            decoders.components.len(),
            1,
            "Should return exactly one decoder"
        );
        assert_eq!(
            decoders.components[0].get_name(),
            decoder_name,
            "Should return the requested decoder"
        );
    }

    #[test]
    fn test_get_decoder_by_name_nonexistent() {
        let decoders = get_decoder_by_name("nonexistent_decoder");
        assert!(
            decoders.components.is_empty(),
            "Should return empty decoders for nonexistent name"
        );
    }
}
