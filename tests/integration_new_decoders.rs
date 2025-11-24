use ares::decoders::interface::Crack;
use ares::decoders::interface::Decoder;
use ares::checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes};

use ares::decoders::base62_decoder::Base62Decoder;
use ares::decoders::ascii85_decoder::Ascii85Decoder;
use ares::decoders::octal_decoder::OctalDecoder;
use ares::decoders::decimal_decoder::DecimalDecoder;
use ares::decoders::html_entity_decoder::HtmlEntityDecoder;
use ares::decoders::punycode_decoder::PunycodeDecoder;
use ares::decoders::quoted_printable_decoder::QuotedPrintableDecoder;
use ares::decoders::uuencode_decoder::UUEncodeDecoder;
use ares::decoders::base45_decoder::Base45Decoder;
use ares::decoders::bacon_cipher_decoder::BaconCipherDecoder;
use ares::decoders::base32hex_decoder::Base32HexDecoder;
use ares::decoders::affine_cipher::AffineCipherDecoder;
use ares::decoders::xor_decoder::XorDecoder;

fn get_athena_checker() -> CheckerTypes {
    let athena_checker = Checker::<Athena>::new();
    CheckerTypes::CheckAthena(athena_checker)
}

#[test]
fn test_base62_decoding() {
    let decoder = Decoder::<Base62Decoder>::new();
    // 7Dq -> lv (using base-x GMP alphabet)
    let result = decoder.crack("7Dq", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "lv");
}

#[test]
fn test_ascii85_decoding() {
    let decoder = Decoder::<Ascii85Decoder>::new();
    // "Hello World" -> 87cURD]i,"Ebo7
    let result = decoder.crack("87cURD]i,\"Ebo7", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Hello World");
}

#[test]
fn test_octal_decoding() {
    let decoder = Decoder::<OctalDecoder>::new();
    // Hello -> 110 145 154 154 157
    let result = decoder.crack("110 145 154 154 157", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Hello");
}

#[test]
fn test_decimal_decoding() {
    let decoder = Decoder::<DecimalDecoder>::new();
    // Hello -> 72 101 108 108 111
    let result = decoder.crack("72 101 108 108 111", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Hello");
}

#[test]
fn test_html_entity_decoding() {
    let decoder = Decoder::<HtmlEntityDecoder>::new();
    // &lt;Hello&gt; -> <Hello>
    let result = decoder.crack("&lt;Hello&gt;", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "<Hello>");
}

#[test]
fn test_punycode_decoding() {
    let decoder = Decoder::<PunycodeDecoder>::new();
    // Mnchen-3ya -> München
    let result = decoder.crack("Mnchen-3ya", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "München");
}

#[test]
fn test_quoted_printable_decoding() {
    let decoder = Decoder::<QuotedPrintableDecoder>::new();
    // Hello=3DWorld -> Hello=World
    let result = decoder.crack("Hello=3DWorld", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Hello=World");
}

#[test]
fn test_uuencode_decoding() {
    let decoder = Decoder::<UUEncodeDecoder>::new();
    // #0V%T -> Cat
    let result = decoder.crack("#0V%T", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Cat");
}

#[test]
fn test_base45_decoding() {
    let decoder = Decoder::<Base45Decoder>::new();
    // QED8WEX0 -> ietf!
    let result = decoder.crack("QED8WEX0", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "ietf!");
}

#[test]
fn test_bacon_cipher_decoding() {
    let decoder = Decoder::<BaconCipherDecoder>::new();
    // AAAAA -> A
    let result = decoder.crack("AAAAA", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "A");
}

#[test]
fn test_base32hex_decoding() {
    let decoder = Decoder::<Base32HexDecoder>::new();
    // 91IMOR3F -> Hello
    let result = decoder.crack("91IMOR3F", &get_athena_checker(), &ares::config::Config::default());
    assert_eq!(result.unencrypted_text.unwrap()[0], "Hello");
}

#[test]
fn test_affine_cipher_decoding() {
    let decoder = Decoder::<AffineCipherDecoder>::new();
    // IHHWVC SWFRCP -> AFFINE CIPHER (a=5, b=8)
    let result = decoder.crack("IHHWVC SWFRCP", &get_athena_checker(), &ares::config::Config::default());
    let results = result.unencrypted_text.unwrap();
    assert!(results.contains(&"AFFINE CIPHER".to_string()));
}

#[test]
fn test_xor_decoding() {
    let decoder = Decoder::<XorDecoder>::new();
    // "HELLO" XOR 32 = "hello"
    let result = decoder.crack("HELLO", &get_athena_checker(), &ares::config::Config::default());
    let results = result.unencrypted_text.unwrap();
    assert!(results.contains(&"hello".to_string()));
}
