//! Decode Base45
//! Performs error handling and returns a string

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;
use crate::decoders::crack_results::CrackResult;
use crate::decoders::interface::Crack;
use crate::decoders::interface::Decoder;
use log::trace;

/// The Base45 decoder, call:
/// `let base45_decoder = Decoder::<Base45Decoder>::new()` to create a new instance
/// And then call:
/// `result = base45_decoder.crack(input)` to decode a Base45 string
pub struct Base45Decoder;

impl Crack for Decoder<Base45Decoder> {
    fn new() -> Decoder<Base45Decoder> {
        Decoder {
            name: "Base45",
            description: "Base45 is a binary-to-text encoding used in QR codes, specifically for Green Passes (EU Digital COVID Certificate).",
            link: "https://datatracker.ietf.org/doc/draft-faltstrom-base45/",
            tags: vec!["base45", "qr", "decoder", "covid"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Base45 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        if let Ok(bytes) = base45::decode(text) {
             if let Ok(decoded) = String::from_utf8(bytes) {
                 if check_string_success(&decoded, text) {
                    let checker_result = checker.check(&decoded);
                    results.unencrypted_text = Some(vec![decoded]);
                    results.update_checker(&checker_result);
                 }
             }
        }

        results
    }

    fn get_tags(&self) -> &Vec<&str> { &self.tags }
    fn get_name(&self) -> &str { self.name }
    fn get_popularity(&self) -> f32 { self.popularity }
    fn get_description(&self) -> &str { self.description }
    fn get_link(&self) -> &str { self.link }
}

#[cfg(test)]
mod tests {
    use super::Base45Decoder;
    use crate::{
        checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes},
        decoders::interface::{Crack, Decoder},
    };

    fn get_checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    #[test]
    fn base45_ietf_example() {
        // "ietf!" -> QED8WEX0
        let decoder = Decoder::<Base45Decoder>::new();
        let result = decoder.crack("QED8WEX0", &get_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "ietf!");
    }
}
