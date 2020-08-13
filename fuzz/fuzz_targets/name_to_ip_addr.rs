#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mhost::IntoName;
    use mhost::resources::NameToIpAddr;
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(name) = s.into_name() {
            let _ = name.to_ip_addr();
        }
    }
});
