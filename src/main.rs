use ares::cli::parse_cli_args;
use ares::cli_pretty_printing::{program_exiting_successful_decoding, success};
use ares::perform_cracking;

fn main() {
    // Turn CLI arguments into a library object
    let (text, config) = parse_cli_args();
    let result = perform_cracking(&text, config.clone());
    success(
        &format!(
            "DEBUG: main.rs - Result from perform_cracking: {:?}",
            result.is_some()
        ),
        &config,
    );
    match result {
        // TODO: As result have array of CrackResult used,
        // we can print in better way with more info
        Some(result) => {
            success(
                &format!(
                    "DEBUG: main.rs - Got successful result with {} decoders in path",
                    result.path.len()
                ),
                &config,
            );
            program_exiting_successful_decoding(result, &config);
        }
        None => {
            success(
                "DEBUG: main.rs - Got None result, calling failed_to_decode",
                &config,
            );
            ares::cli_pretty_printing::failed_to_decode(&config)
        }
    }
}
