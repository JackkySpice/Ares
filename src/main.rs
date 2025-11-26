use ares::cli::parse_cli_args;
use ares::cli_pretty_printing::program_exiting_successful_decoding;
use ares::perform_cracking;
use log::debug;

fn main() {
    // Turn CLI arguments into a library object
    let (text, config) = parse_cli_args();
    let result = perform_cracking(&text, config.clone());
    
    debug!("Result from perform_cracking: {:?}", result.is_some());
    
    match result {
        Some(result) => {
            debug!("Got successful result with {} decoders in path", result.path.len());
            program_exiting_successful_decoding(result, &config);
        }
        None => {
            debug!("Got None result, calling failed_to_decode");
            ares::cli_pretty_printing::failed_to_decode(&config)
        }
    }
}
