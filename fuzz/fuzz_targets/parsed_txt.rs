#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mhost::resources::rdata::parsed_txt::ParsedTxt;
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ParsedTxt::from_str(s);
    }
});
