// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Domain names.
//!
//! [`Name`] is mhost's own domain name type. It wraps the resolver library's name so that a
//! resolver upgrade does not change mhost's public API.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

type ProtoName = hickory_resolver::proto::rr::Name;

/// A domain name failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid domain name: {reason}")]
pub struct NameError {
    reason: String,
}

impl NameError {
    fn from_proto(err: hickory_resolver::proto::ProtoError) -> Self {
        NameError {
            reason: err.to_string(),
        }
    }
}

/// A DNS domain name.
///
/// Comparison, ordering and hashing ignore ASCII case, as DNS does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Name(ProtoName);

impl Name {
    /// The root name `.`.
    pub fn root() -> Self {
        Name(ProtoName::root())
    }

    /// Parses an ASCII name; labels are not IDNA-converted.
    pub fn from_ascii<S: AsRef<str>>(name: S) -> Result<Self, NameError> {
        ProtoName::from_ascii(name).map(Name).map_err(NameError::from_proto)
    }

    /// Parses a name that may contain Unicode labels; they are IDNA-converted to punycode.
    pub fn from_utf8<S: AsRef<str>>(name: S) -> Result<Self, NameError> {
        ProtoName::from_utf8(name).map(Name).map_err(NameError::from_proto)
    }

    /// Builds a name from raw labels, left to right.
    pub fn from_labels<'a, I: IntoIterator<Item = &'a [u8]>>(labels: I) -> Result<Self, NameError> {
        ProtoName::from_labels(labels).map(Name).map_err(NameError::from_proto)
    }

    /// The name in its ASCII form, punycode labels left encoded.
    pub fn to_ascii(&self) -> String {
        self.0.to_ascii()
    }

    /// The name with punycode labels decoded to Unicode.
    pub fn to_utf8(&self) -> String {
        self.0.to_utf8()
    }

    pub fn to_lowercase(&self) -> Self {
        Name(self.0.to_lowercase())
    }

    pub fn is_root(&self) -> bool {
        self.0.is_root()
    }

    pub fn is_fqdn(&self) -> bool {
        self.0.is_fqdn()
    }

    pub fn set_fqdn(&mut self, fqdn: bool) {
        self.0.set_fqdn(fqdn)
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.is_wildcard()
    }

    /// Number of labels, not counting the root and a leading wildcard.
    pub fn num_labels(&self) -> u8 {
        self.0.num_labels()
    }

    /// The labels from left to right, as raw bytes.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.0.iter()
    }

    /// The name without its leftmost label.
    pub fn base_name(&self) -> Self {
        Name(self.0.base_name())
    }

    /// Whether `name` is this name or below it.
    pub fn zone_of(&self, name: &Self) -> bool {
        self.0.zone_of(&name.0)
    }

    /// Appends `domain` to this name, e.g. for search domains.
    pub fn append_domain(self, domain: &Self) -> Result<Self, NameError> {
        self.0.append_domain(&domain.0).map(Name).map_err(NameError::from_proto)
    }

    pub(crate) fn from_proto(name: ProtoName) -> Self {
        Name(name)
    }

    pub(crate) fn as_proto(&self) -> &ProtoName {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProtoName::from_str(s).map(Name).map_err(NameError::from_proto)
    }
}

/// The reverse-pointer name of an address, e.g. `1.2.0.192.in-addr.arpa.`.
impl From<IpAddr> for Name {
    fn from(ip: IpAddr) -> Self {
        Name(ProtoName::from(ip))
    }
}

impl From<Ipv4Addr> for Name {
    fn from(ip: Ipv4Addr) -> Self {
        Name(ProtoName::from(ip))
    }
}

impl From<Ipv6Addr> for Name {
    fn from(ip: Ipv6Addr) -> Self {
        Name(ProtoName::from(ip))
    }
}

/// Conversion into a [`Name`]; implemented for strings, names, and addresses (their reverse-pointer name).
pub trait IntoName {
    fn into_name(self) -> Result<Name, NameError>;
}

impl IntoName for Name {
    fn into_name(self) -> Result<Name, NameError> {
        Ok(self)
    }
}

impl IntoName for &Name {
    fn into_name(self) -> Result<Name, NameError> {
        Ok(self.clone())
    }
}

impl IntoName for &str {
    fn into_name(self) -> Result<Name, NameError> {
        Name::from_utf8(self)
    }
}

impl IntoName for String {
    fn into_name(self) -> Result<Name, NameError> {
        Name::from_utf8(self)
    }
}

impl IntoName for &String {
    fn into_name(self) -> Result<Name, NameError> {
        Name::from_utf8(self)
    }
}

impl IntoName for IpAddr {
    fn into_name(self) -> Result<Name, NameError> {
        Ok(self.into())
    }
}

impl IntoName for &IpAddr {
    fn into_name(self) -> Result<Name, NameError> {
        Ok((*self).into())
    }
}

impl IntoName for Ipv4Addr {
    fn into_name(self) -> Result<Name, NameError> {
        Ok(self.into())
    }
}

impl IntoName for Ipv6Addr {
    fn into_name(self) -> Result<Name, NameError> {
        Ok(self.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_ascii_round_trip() {
        let name = Name::from_ascii("www.example.com.").unwrap();
        assert_eq!(name.to_string(), "www.example.com.");
        assert_eq!(name.to_ascii(), "www.example.com.");
        assert_eq!(Name::from_str("www.example.com.").unwrap(), name);
    }

    #[test]
    fn eq_and_hash_ignore_case() {
        use std::collections::HashSet;
        let lower = Name::from_ascii("example.com.").unwrap();
        let upper = Name::from_ascii("EXAMPLE.com.").unwrap();
        assert_eq!(lower, upper);
        assert_eq!(HashSet::from([lower, upper]).len(), 1);
    }

    #[test]
    fn utf8_is_idna_converted() {
        let name = Name::from_utf8("bücher.example.").unwrap();
        assert_eq!(name.to_ascii(), "xn--bcher-kva.example.");
        assert_eq!(name.to_utf8(), "bücher.example.");
    }

    #[test]
    fn invalid_name_is_an_error() {
        let label = "a".repeat(64);
        assert!(Name::from_ascii(format!("{label}.example.")).is_err());
        assert!(format!("{label}.example.").into_name().is_err());
    }

    #[test]
    fn ip_into_reverse_name() {
        let v4 = IpAddr::from([192, 0, 2, 1]).into_name().unwrap();
        assert_eq!(v4.to_ascii(), "1.2.0.192.in-addr.arpa.");
        let v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into_name().unwrap();
        assert!(v6.to_ascii().ends_with(".8.b.d.0.1.0.0.2.ip6.arpa."));
    }

    #[test]
    fn from_labels_rebuilds_a_name() {
        let name = Name::from_ascii("www.example.com.").unwrap();
        let sub = Name::from_labels(name.iter().take(1)).unwrap();
        assert_eq!(sub.to_ascii(), "www.");
    }

    #[test]
    fn zone_of_and_base_name() {
        let zone = Name::from_ascii("example.com.").unwrap();
        let host = Name::from_ascii("www.example.com.").unwrap();
        assert!(zone.zone_of(&host));
        assert!(!host.zone_of(&zone));
        assert_eq!(host.base_name(), zone);
    }

    #[cfg(feature = "serde_json")]
    #[test]
    fn serializes_as_plain_string() {
        let name = Name::from_ascii("example.com.").unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"example.com.\"");
    }
}
