#[macro_use]
extern crate afl;

fn main() {
    use mhost::nameserver::NameServerConfig;
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = NameServerConfig::from_str(s);
        }
    });
}