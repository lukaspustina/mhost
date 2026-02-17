// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! BIND zone file parser.
//!
//! Parses BIND-format zone files into mhost [`Record`] types using
//! `hickory-proto`'s text-parsing support.

use std::path::Path;

use hickory_proto::rr::Name;
use hickory_proto::serialize::txt::Parser;

use crate::resources::{Record, RecordType};

/// A parsed DNS zone containing an origin and a set of records.
#[derive(Debug)]
pub struct Zone {
    origin: Name,
    records: Vec<Record>,
    wildcard_records: Vec<Record>,
    soa: Option<Record>,
}

impl Zone {
    pub fn origin(&self) -> &Name {
        &self.origin
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn wildcard_records(&self) -> &[Record] {
        &self.wildcard_records
    }

    pub fn soa(&self) -> Option<&Record> {
        self.soa.as_ref()
    }

    pub fn into_records(self) -> Vec<Record> {
        self.records
    }
}

/// Record types that are skipped by default during zone verification:
/// SOA, DNSSEC types (RRSIG, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM).
fn is_default_skipped(record_type: RecordType) -> bool {
    matches!(
        record_type,
        RecordType::SOA
            | RecordType::RRSIG
            | RecordType::DNSKEY
            | RecordType::DS
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
    )
}

/// Returns true if the record is an apex NS record (NS at the zone origin).
fn is_apex_ns(record: &Record, origin: &Name) -> bool {
    record.record_type() == RecordType::NS && record.name() == origin
}

/// Parse a BIND zone file from disk.
///
/// Reads the file at `path`, parses it with the given `origin` (or the
/// `$ORIGIN` directive inside the file), and returns a [`Zone`] with all
/// records except SOA, DNSSEC types, and apex NS.
pub fn parse<P: AsRef<Path>>(path: P, origin: Option<Name>) -> crate::Result<Zone> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| crate::Error::ZoneFileError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    parse_str(&content, Some(path), origin)
}

/// Parse a BIND zone file from a string.
pub fn parse_str(content: &str, path: Option<&Path>, origin: Option<Name>) -> crate::Result<Zone> {
    let path_buf = path.map(|p| p.to_path_buf());
    let parser = Parser::new(content, path_buf, origin);
    let (zone_origin, record_sets) = parser.parse().map_err(|e| crate::Error::ZoneFileError {
        path: path.map(|p| p.display().to_string()).unwrap_or_default(),
        reason: e.to_string(),
    })?;

    let mut records = Vec::new();
    let mut wildcard_records = Vec::new();
    let mut soa = None;
    for (_rr_key, record_set) in record_sets {
        for proto_record in record_set.records_without_rrsigs() {
            let record = Record::from(proto_record);
            // Capture the first SOA record before filtering
            if record.record_type() == RecordType::SOA && soa.is_none() {
                soa = Some(record.clone());
            }
            if is_default_skipped(record.record_type()) {
                continue;
            }
            if is_apex_ns(&record, &zone_origin) {
                continue;
            }
            if record.name().is_wildcard() {
                wildcard_records.push(record);
                continue;
            }
            records.push(record);
        }
    }

    Ok(Zone {
        origin: zone_origin,
        records,
        wildcard_records,
        soa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MINIMAL_ZONE: &str = r#"
$ORIGIN example.com.
$TTL 3600
@  IN SOA ns1.example.com. admin.example.com. (
            2024010101 3600 1800 604800 86400 )
@       IN NS   ns1.example.com.
@       IN NS   ns2.example.com.
@       IN A    93.184.216.34
@       IN AAAA 2606:2800:220:1:248:1893:25c8:1946
@       IN MX   10 mail.example.com.
@       IN TXT  "v=spf1 include:example.com ~all"
www     IN A    93.184.216.34
mail    IN A    93.184.216.35
"#;

    #[test]
    fn parse_minimal_zone_file() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        assert_eq!(zone.origin().to_string(), "example.com.");
        // We should have: A(@), AAAA(@), MX(@), TXT(@), A(www), A(mail) = 6
        // SOA, NS(@) are filtered out
        assert_eq!(zone.records().len(), 6);
    }

    #[test]
    fn parse_filters_soa() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        assert!(
            !zone
                .records()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA),
            "SOA records should be filtered out of records()"
        );
    }

    #[test]
    fn parse_captures_soa() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        let soa = zone.soa().expect("SOA should be captured");
        assert_eq!(soa.record_type(), RecordType::SOA);
        let soa_data = soa.data().soa().expect("should have SOA rdata");
        assert_eq!(soa_data.serial(), 2024010101);
    }

    #[test]
    fn parse_no_soa_returns_none() {
        // A zone without SOA (unusual but possible for partial zone files)
        let zone_text = r#"
$ORIGIN example.com.
$TTL 3600
www     IN A    1.2.3.4
"#;
        let zone = parse_str(zone_text, None, None).unwrap();
        assert!(zone.soa().is_none());
    }

    #[test]
    fn parse_filters_apex_ns() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        assert!(
            !zone.records().iter().any(|r| r.record_type() == RecordType::NS
                && r.name() == zone.origin()),
            "Apex NS records should be filtered out"
        );
    }

    #[test]
    fn parse_filters_dnssec() {
        // DNSSEC record types (DNSKEY, DS, etc.) are typically generated dynamically
        // and rejected by the hickory-proto text parser. Verify that the is_default_skipped
        // function correctly identifies them.
        assert!(is_default_skipped(RecordType::RRSIG));
        assert!(is_default_skipped(RecordType::DNSKEY));
        assert!(is_default_skipped(RecordType::DS));
        assert!(is_default_skipped(RecordType::NSEC));
        assert!(is_default_skipped(RecordType::NSEC3));
        assert!(is_default_skipped(RecordType::NSEC3PARAM));
        assert!(is_default_skipped(RecordType::SOA));
        // Regular types should not be skipped
        assert!(!is_default_skipped(RecordType::A));
        assert!(!is_default_skipped(RecordType::AAAA));
        assert!(!is_default_skipped(RecordType::MX));
        assert!(!is_default_skipped(RecordType::TXT));
        assert!(!is_default_skipped(RecordType::NS));
    }

    #[test]
    fn parse_resolves_relative_names() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        let www_records: Vec<_> = zone
            .records()
            .iter()
            .filter(|r| r.name().to_string() == "www.example.com.")
            .collect();
        assert_eq!(www_records.len(), 1, "relative 'www' should resolve to www.example.com.");
    }

    #[test]
    fn parse_correct_record_data() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();

        // Check A record at apex
        let a_records: Vec<_> = zone
            .records()
            .iter()
            .filter(|r| r.record_type() == RecordType::A && r.name().to_string() == "example.com.")
            .collect();
        assert_eq!(a_records.len(), 1);
        assert_eq!(a_records[0].data().a(), Some(&Ipv4Addr::new(93, 184, 216, 34)));

        // Check AAAA at apex
        let aaaa_records: Vec<_> = zone
            .records()
            .iter()
            .filter(|r| r.record_type() == RecordType::AAAA)
            .collect();
        assert_eq!(aaaa_records.len(), 1);
        assert_eq!(
            aaaa_records[0].data().aaaa(),
            Some(&"2606:2800:220:1:248:1893:25c8:1946".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn parse_origin_override() {
        let zone_no_origin = r#"
$TTL 3600
@  IN SOA ns1.test.com. admin.test.com. (
            2024010101 3600 1800 604800 86400 )
@  IN A 1.2.3.4
"#;
        let origin = Name::from_ascii("override.example.com.").unwrap();
        let zone = parse_str(zone_no_origin, None, Some(origin)).unwrap();
        assert_eq!(zone.origin().to_string(), "override.example.com.");
    }

    #[test]
    fn parse_error_malformed() {
        let bad_zone = "this is not a valid zone file @@@ {{{}}}";
        let result = parse_str(bad_zone, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_missing_file() {
        let result = parse("/nonexistent/path/to/zone.db", None);
        assert!(result.is_err());
    }

    #[test]
    fn parse_preserves_non_apex_ns() {
        let zone_text = r#"
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. admin.example.com. (
                2024010101 3600 1800 604800 86400 )
@       IN NS   ns1.example.com.
sub     IN NS   ns1.sub.example.com.
@       IN A    1.2.3.4
"#;
        let zone = parse_str(zone_text, None, None).unwrap();
        let ns_records: Vec<_> = zone
            .records()
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .collect();
        assert_eq!(ns_records.len(), 1, "non-apex NS should be preserved");
        assert_eq!(ns_records[0].name().to_string(), "sub.example.com.");
    }

    #[test]
    fn parse_separates_wildcard_records() {
        let zone_text = r#"
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. admin.example.com. (
                2024010101 3600 1800 604800 86400 )
@       IN NS   ns1.example.com.
@       IN A    1.2.3.4
*       IN A    5.6.7.8
*.sub   IN A    9.10.11.12
www     IN A    1.2.3.4
"#;
        let zone = parse_str(zone_text, None, None).unwrap();

        // Non-wildcard records should be in records()
        assert_eq!(zone.records().len(), 2, "should have apex A and www A");
        assert!(
            zone.records().iter().all(|r| !r.name().is_wildcard()),
            "records() should not contain wildcards"
        );

        // Wildcard records should be in wildcard_records()
        assert_eq!(zone.wildcard_records().len(), 2, "should have *.example.com and *.sub.example.com");
        assert!(
            zone.wildcard_records().iter().all(|r| r.name().is_wildcard()),
            "wildcard_records() should only contain wildcards"
        );
    }

    #[test]
    fn parse_no_wildcards() {
        let zone = parse_str(MINIMAL_ZONE, None, None).unwrap();
        assert!(zone.wildcard_records().is_empty(), "MINIMAL_ZONE has no wildcards");
    }
}
