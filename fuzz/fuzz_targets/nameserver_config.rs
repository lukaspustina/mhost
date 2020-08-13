#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mhost::nameserver::NameServerConfig;
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = NameServerConfig::from_str(s);
    }
});
