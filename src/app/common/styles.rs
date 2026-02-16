use yansi::{Color, Style};

use crate::RecordType;

pub const fn record_type_color(rt: RecordType) -> Color {
    match rt {
        RecordType::A | RecordType::AAAA | RecordType::NULL => Color::White,
        RecordType::ANAME | RecordType::CNAME | RecordType::NS | RecordType::PTR => Color::Blue,
        RecordType::CAA => Color::Cyan,
        RecordType::DNSKEY
        | RecordType::DS
        | RecordType::RRSIG
        | RecordType::NSEC
        | RecordType::NSEC3
        | RecordType::NSEC3PARAM => Color::Green,
        RecordType::HINFO => Color::Yellow,
        RecordType::HTTPS | RecordType::SVCB | RecordType::TLSA => Color::Cyan,
        RecordType::MX => Color::Yellow,
        RecordType::SOA => Color::Green,
        RecordType::NAPTR | RecordType::SRV => Color::Red,
        RecordType::OPENPGPKEY | RecordType::TXT => Color::Magenta,
        RecordType::SSHFP => Color::Blue,
        _ => Color::White,
    }
}

pub const fn record_type_is_bold(rt: RecordType) -> bool {
    matches!(
        rt,
        RecordType::A
            | RecordType::AAAA
            | RecordType::NULL
            | RecordType::HINFO
            | RecordType::HTTPS
            | RecordType::SVCB
            | RecordType::TLSA
            | RecordType::NAPTR
            | RecordType::OPENPGPKEY
            | RecordType::SSHFP
    )
}

pub const fn record_type_style(rt: RecordType) -> Style {
    let s = Style::new().fg(record_type_color(rt));
    if record_type_is_bold(rt) {
        s.bold()
    } else {
        s
    }
}

pub static A: Style = record_type_style(RecordType::A);
pub static AAAA: Style = record_type_style(RecordType::AAAA);
pub static CAA: Style = record_type_style(RecordType::CAA);
pub static DNSSEC: Style = record_type_style(RecordType::DNSKEY);
pub static HINFO: Style = record_type_style(RecordType::HINFO);
pub static MX: Style = record_type_style(RecordType::MX);
pub static NAME: Style = record_type_style(RecordType::CNAME);
pub static NAPTR: Style = record_type_style(RecordType::NAPTR);
pub static OPENPGPKEY: Style = record_type_style(RecordType::OPENPGPKEY);
pub static SOA: Style = record_type_style(RecordType::SOA);
pub static SRV: Style = record_type_style(RecordType::SRV);
pub static SSHFP: Style = record_type_style(RecordType::SSHFP);
pub static SVCB: Style = record_type_style(RecordType::SVCB);
pub static TLSA: Style = record_type_style(RecordType::TLSA);
pub static TXT: Style = record_type_style(RecordType::TXT);
