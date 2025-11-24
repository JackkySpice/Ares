//! Decode JWT (JSON Web Tokens)
//! Performs error handling and returns a string
//! Call jwt_decoder.crack to use.

use crate::checkers::CheckerTypes;
use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use base64::{engine::general_purpose, Engine as _};
use log::{debug, trace};
use serde_json::Value;

/// The JWT decoder, call:
/// `let jwt_decoder = Decoder::<JwtDecoder>::new()` to create a new instance
/// And then call:
/// `result = jwt_decoder.crack(input)` to decode a JWT
pub struct JwtDecoder;

impl Crack for Decoder<JwtDecoder> {
    fn new() -> Decoder<JwtDecoder> {
        Decoder {
            name: "JWT",
            description: "Decodes JSON Web Tokens (header and payload).",
            link: "https://jwt.io/",
            tags: vec!["jwt", "token", "json", "web", "decoder"],
            popularity: 0.8,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying JWT with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() != 3 {
            return results;
        }

        // Try to decode header and payload
        let header_decoded = decode_part(parts[0]);
        let payload_decoded = decode_part(parts[1]);

        if let (Some(header), Some(payload)) = (header_decoded, payload_decoded) {
            // Check if they are valid JSON
            let header_json: Option<Value> = serde_json::from_str(&header).ok();
            let payload_json: Option<Value> = serde_json::from_str(&payload).ok();

            if header_json.is_some() && payload_json.is_some() {
                debug!("JWT decoded successfully");
                let decoded = format!("Header: {}\nPayload: {}", header, payload);
                
                // We don't check string success strictly because JSON might not be "human readable" 
                // in the sense of a sentence, but it is structured. 
                // However, we should check if the checker accepts it or if we just force it.
                // Usually JWT content is interesting enough to return.
                
                let checker_result = checker.check(&decoded);
                results.unencrypted_text = Some(vec![decoded]);
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

fn decode_part(part: &str) -> Option<String> {
    // JWT uses URL-safe base64, sometimes with no padding
    // We try to decode it
    // Padding might be missing, so we might need to add it?
    // base64 crate's URL_SAFE_NO_PAD should handle it if it's no pad.
    // But if it HAS padding, it might fail with NO_PAD?
    // Let's try flexible decoding.
    
    let decoded_bytes = general_purpose::URL_SAFE_NO_PAD.decode(part).ok()
        .or_else(|| general_purpose::URL_SAFE.decode(part).ok())
        .or_else(|| general_purpose::STANDARD_NO_PAD.decode(part).ok())
        .or_else(|| general_purpose::STANDARD.decode(part).ok());

    match decoded_bytes {
        Some(bytes) => String::from_utf8(bytes).ok(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::JwtDecoder;
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
    fn test_jwt_decode() {
        let decoder = Decoder::<JwtDecoder>::new();
        // Example JWT
        // Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022} -> eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
        // Signature: SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        
        let result = decoder.crack(jwt, &get_athena_checker());
        assert!(result.unencrypted_text.is_some());
        let text = &result.unencrypted_text.unwrap()[0];
        assert!(text.contains("John Doe"));
        assert!(text.contains("HS256"));
    }
}
