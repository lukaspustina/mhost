#[macro_use]
extern crate afl;

fn main() {
    use mhost::IntoName;
    use mhost::resources::NameToIpAddr;
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Ok(name) = s.into_name() {
                let _ = name.to_ip_addr();
            }
        }
    });
}