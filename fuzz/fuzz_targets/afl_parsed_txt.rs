#[macro_use]
extern crate afl;

fn main() {
    use mhost::resources::rdata::parsed_txt::ParsedTxt;
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = ParsedTxt::from_str(s);
        }
    });
}