//! Decode Quoted-Printable
//! Performs error handling and returns a string

use crate::checkers::CheckerTypes;
use crate::config::Config;
use crate::decoders::interface::check_string_success;
use crate::decoders::crack_results::CrackResult;
use crate::decoders::interface::Crack;
use crate::decoders::interface::Decoder;
use log::trace;

/// The Quoted-Printable decoder, call:
/// `let quoted_printable_decoder = Decoder::<QuotedPrintableDecoder>::new()` to create a new instance
/// And then call:
/// `result = quoted_printable_decoder.crack(input)` to decode a Quoted-Printable string
pub struct QuotedPrintableDecoder;

impl Crack for Decoder<QuotedPrintableDecoder> {
    fn new() -> Decoder<QuotedPrintableDecoder> {
        Decoder {
            name: "Quoted-Printable", description: "Quoted-printable is an encoding used for email that uses printable ASCII characters.",
            link: "https://en.wikipedia.org/wiki/Quoted-printable",
            tags: vec!["quoted-printable", "email", "decoder", "mime"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes, config: &Config) -> CrackResult {
        trace!("Trying Quoted-Printable with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // quoted_printable crate expects ParseMode.
        // We can use decode(input, mode)
        if let Ok(bytes) = quoted_printable::decode(text, quoted_printable::ParseMode::Robust) {
            if let Ok(decoded_text) = String::from_utf8(bytes) {
                 if check_string_success(&decoded_text, text) {
                    let checker_result = checker.check(&decoded_text, config);
                    results.unencrypted_text = Some(vec![decoded_text]);
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
    use super::QuotedPrintableDecoder;
    use crate::{
        checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes},
        decoders::interface::{Crack, Decoder},
    };

    fn get_checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    #[test]
    fn qp_basic() {
        let decoder = Decoder::<QuotedPrintableDecoder>::new();
        // =3D is =
        let result = decoder.crack("Hello=3DWorld", &get_checker(), &crate::config::Config::default());
        assert_eq!(result.unencrypted_text.unwrap()[0], "Hello=World");
    }

    #[test]
    fn qp_utf8() {
        let decoder = Decoder::<QuotedPrintableDecoder>::new();
        // =C3=A9 -> é
        let result = decoder.crack("Caf=C3=A9", &get_checker(), &crate::config::Config::default());
        assert_eq!(result.unencrypted_text.unwrap()[0], "Café");
    }
}
