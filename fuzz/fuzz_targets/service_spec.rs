#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mhost::app::modules::lookup::service_spec::ServiceSpec;
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ServiceSpec::from_str(s);
    }
});
