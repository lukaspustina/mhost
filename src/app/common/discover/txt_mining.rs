// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;

use tracing::debug;

use crate::resources::rdata::parsed_txt::{Mechanism, Modifier, Spf, Word};
use crate::resources::rdata::TXT;

/// Well-known subdomains that often carry TXT records with discovery-relevant information.
pub fn well_known_txt_subdomains() -> Vec<&'static str> {
    vec![
        "_dmarc",
        "_acme-challenge",
        "autoconfig",
        "autodiscover",
        "_mta-sts",
        "_smtp._tls",
    ]
}

/// Extract domain names referenced in SPF TXT records (include:, redirect=, a:, mx:).
pub fn extract_spf_domains(txt_records: &[&TXT]) -> HashSet<String> {
    let mut domains = HashSet::new();

    for txt in txt_records {
        if !txt.is_spf() {
            continue;
        }
        let text = txt.as_string();
        extract_spf_domains_from_text(&text, &mut domains);
    }

    domains
}

fn extract_spf_domains_from_text(text: &str, domains: &mut HashSet<String>) {
    let spf: Spf<'_> = match Spf::from_str(text) {
        Ok(spf) => spf,
        Err(_) => return,
    };

    for word in spf.words() {
        match word {
            Word::Word(_, Mechanism::Include(domain)) => {
                debug!("SPF include: {}", domain);
                domains.insert(domain.to_string());
            }
            Word::Word(
                _,
                Mechanism::A {
                    domain_spec: Some(domain),
                    ..
                },
            ) => {
                debug!("SPF a: {}", domain);
                domains.insert(domain.to_string());
            }
            Word::Word(
                _,
                Mechanism::MX {
                    domain_spec: Some(domain),
                    ..
                },
            ) => {
                debug!("SPF mx: {}", domain);
                domains.insert(domain.to_string());
            }
            Word::Modifier(Modifier::Redirect(domain)) => {
                debug!("SPF redirect: {}", domain);
                domains.insert(domain.to_string());
            }
            _ => {}
        }
    }
}

/// Extract domain names from DMARC TXT records (rua/ruf mailto: URIs).
pub fn extract_dmarc_domains(txt_records: &[&TXT]) -> HashSet<String> {
    let mut domains = HashSet::new();

    for txt in txt_records {
        let text = txt.as_string();
        if !text.starts_with("v=DMARC1") {
            continue;
        }

        for part in text.split(';') {
            let part = part.trim();
            if part.starts_with("rua=") || part.starts_with("ruf=") {
                for uri in part.split_once('=').map(|x| x.1).into_iter().flat_map(|v| v.split(',')) {
                    let uri = uri.trim();
                    if let Some(addr) = uri.strip_prefix("mailto:") {
                        if let Some(domain) = addr.split('@').nth(1) {
                            let domain = domain.trim();
                            if !domain.is_empty() {
                                debug!("DMARC mailto domain: {}", domain);
                                domains.insert(domain.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_subdomains_not_empty() {
        assert!(!well_known_txt_subdomains().is_empty());
    }

    #[test]
    fn extract_spf_include_and_redirect() {
        let txt = TXT::new(vec![
            "v=spf1 include:_spf.google.com include:spf.protection.outlook.com redirect=_spf.example.com -all"
                .to_string(),
        ]);
        let refs: Vec<&TXT> = vec![&txt];

        let result = extract_spf_domains(&refs);

        assert!(result.contains("_spf.google.com"));
        assert!(result.contains("spf.protection.outlook.com"));
        assert!(result.contains("_spf.example.com"));
    }

    #[test]
    fn extract_spf_a_and_mx() {
        let txt = TXT::new(vec!["v=spf1 a:mail.example.com mx:mx.example.com -all".to_string()]);
        let refs: Vec<&TXT> = vec![&txt];

        let result = extract_spf_domains(&refs);

        assert!(result.contains("mail.example.com"));
        assert!(result.contains("mx.example.com"));
    }

    #[test]
    fn non_spf_records_ignored() {
        let txt = TXT::new(vec!["google-site-verification=abc123".to_string()]);
        let refs: Vec<&TXT> = vec![&txt];

        let result = extract_spf_domains(&refs);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_dmarc_rua_ruf() {
        let txt = TXT::new(vec![
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:dmarc@report.example.net; ruf=mailto:forensics@example.com"
                .to_string(),
        ]);
        let refs: Vec<&TXT> = vec![&txt];

        let result = extract_dmarc_domains(&refs);

        assert!(result.contains("example.com"));
        assert!(result.contains("report.example.net"));
    }

    #[test]
    fn non_dmarc_ignored() {
        let txt = TXT::new(vec!["v=spf1 -all".to_string()]);
        let refs: Vec<&TXT> = vec![&txt];

        let result = extract_dmarc_domains(&refs);
        assert!(result.is_empty());
    }
}
