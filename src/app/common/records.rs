// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use yansi::Paint;

use crate::resources::rdata::parsed_txt::{
    Bimi, Dmarc, DomainVerification, Mechanism, Modifier, MtaSts, ParsedTxt, TlsRpt, Word,
};
use crate::resources::rdata::{
    parsed_txt::Spf, Name, CAA, DNSKEY, DS, HINFO, MX, NAPTR, NSEC, NSEC3, NSEC3PARAM, NULL, OPENPGPKEY, RRSIG, SOA,
    SRV, SSHFP, SVCB, TLSA, TXT, UNKNOWN,
};
use crate::resources::{NameToIpAddr, Record};
use crate::RecordType;

use super::rendering::{Rendering, SummaryOptions};
use super::styles;

/// Escapes characters that would act on the terminal instead of being shown: control characters
/// (ESC starts escape sequences such as OSC 52, which writes the clipboard) and bidirectional
/// overrides. DNS data is attacker-controlled and must pass through this before printing.
pub(crate) fn term_safe(s: &str) -> std::borrow::Cow<'_, str> {
    let unsafe_char = |c: char| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    if !s.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| {
                if unsafe_char(c) {
                    c.escape_unicode().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

impl Rendering for Record {
    fn render(&self, opts: &SummaryOptions) -> String {
        self.render_with_suffix("", opts)
    }

    fn render_with_suffix(&self, suffix: &str, opts: &SummaryOptions) -> String {
        /// Render a record type with its data, falling back to a placeholder on data mismatch.
        macro_rules! render_rr {
            ($label:expr, $style:expr, $accessor:ident) => {
                if let Some(data) = self.data().$accessor() {
                    format!("{}:\t{}{}", $label.paint($style), data.render(opts), suffix)
                } else {
                    format!("{}:\t<data unavailable>{}", $label.paint($style), suffix)
                }
            };
        }

        match self.record_type() {
            RecordType::A => render_rr!("A", styles::A, a),
            RecordType::AAAA => render_rr!("AAAA", styles::AAAA, aaaa),
            RecordType::ANAME => render_rr!("ANAME", styles::NAME, cname),
            RecordType::CAA => render_rr!("CAA", styles::CAA, caa),
            RecordType::CNAME => render_rr!("CNAME", styles::NAME, cname),
            RecordType::MX => render_rr!("MX", styles::MX, mx),
            RecordType::NULL => {
                if let Some(data) = self.data().null() {
                    format!("{}:\t{}{}", "NULL", data.render(opts), suffix)
                } else {
                    format!("{}:\t<data unavailable>{}", "NULL", suffix)
                }
            }
            RecordType::NS => render_rr!("NS", styles::NAME, ns),
            RecordType::PTR => {
                if let Some(data) = self.data().ptr() {
                    format!(
                        "PTR:\t{}:\t{}{}",
                        self.name().to_ip_addr_string(),
                        data.render(opts),
                        suffix
                    )
                } else {
                    format!(
                        "PTR:\t{}:\t<data unavailable>{}",
                        self.name().to_ip_addr_string(),
                        suffix
                    )
                }
            }
            RecordType::SOA => render_rr!("SOA", styles::SOA, soa),
            RecordType::SRV => render_rr!("SRV", styles::SRV, srv),
            RecordType::HINFO => render_rr!("HINFO", styles::HINFO, hinfo),
            RecordType::HTTPS => render_rr!("HTTPS", styles::SVCB, https),
            RecordType::NAPTR => render_rr!("NAPTR", styles::NAPTR, naptr),
            RecordType::OPENPGPKEY => render_rr!("OPENPGPKEY", styles::OPENPGPKEY, openpgpkey),
            RecordType::SSHFP => render_rr!("SSHFP", styles::SSHFP, sshfp),
            RecordType::SVCB => render_rr!("SVCB", styles::SVCB, svcb),
            RecordType::TLSA => render_rr!("TLSA", styles::TLSA, tlsa),
            RecordType::TXT => {
                if let Some(data) = self.data().txt() {
                    format!(
                        "{}:\t{}",
                        "TXT".paint(styles::TXT),
                        data.render_with_suffix(suffix, opts)
                    )
                } else {
                    format!("{}:\t<data unavailable>{}", "TXT".paint(styles::TXT), suffix)
                }
            }
            RecordType::DNSKEY => render_rr!("DNSKEY", styles::DNSSEC, dnskey),
            RecordType::DS => render_rr!("DS", styles::DNSSEC, ds),
            RecordType::RRSIG => render_rr!("RRSIG", styles::DNSSEC, rrsig),
            RecordType::NSEC => render_rr!("NSEC", styles::DNSSEC, nsec),
            RecordType::NSEC3 => render_rr!("NSEC3", styles::DNSSEC, nsec3),
            RecordType::NSEC3PARAM => render_rr!("NSEC3PARAM", styles::DNSSEC, nsec3param),
            RecordType::Unknown(_) => {
                if let Some(data) = self.data().unknown() {
                    format!("Unknown:\t{}{}", data.render(opts), suffix)
                } else {
                    format!("Unknown:\t<data unavailable>{}", suffix)
                }
            }
            rr_type => format!("{}:\t<not yet implemented>{}", rr_type, suffix),
        }
    }
}

impl Rendering for Ipv4Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(styles::A).to_string()
    }
}

impl Rendering for Ipv6Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(styles::AAAA).to_string()
    }
}

impl Rendering for Name {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(styles::NAME).to_string()
    }
}

impl Rendering for MX {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human() {
            format!(
                "{}\tpreference {:2}",
                self.exchange().paint(styles::MX),
                self.preference().paint(styles::MX),
            )
        } else {
            format!(
                "{}\tpreference={:2}",
                self.exchange().paint(styles::MX),
                self.preference().paint(styles::MX),
            )
        }
    }
}

impl Rendering for CAA {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::CAA;
        let critical = if self.issuer_critical() { " (critical)" } else { "" };
        let tag = term_safe(self.tag());
        let value = term_safe(self.value());
        if opts.human() {
            let description = match (tag.as_ref(), value.trim()) {
                ("issue", v) if v.is_empty() || v == ";" => "no CA is allowed to issue certificates".to_string(),
                ("issue", v) => format!("allow {} to issue certificates", v.paint(style)),
                ("issuewild", v) if v.is_empty() || v == ";" => {
                    "no CA is allowed to issue wildcard certificates".to_string()
                }
                ("issuewild", v) => format!("allow {} to issue wildcard certificates", v.paint(style)),
                ("iodef", v) => format!("report policy violations to {}", v.paint(style)),
                (tag, v) => format!("{} {}", tag.paint(style), v.paint(style)),
            };
            format!("{}{}", description, critical.paint(style))
        } else {
            format!(
                "tag={}, value={}, issuer_critical={}",
                tag.paint(style),
                value.paint(style),
                self.issuer_critical().paint(style)
            )
        }
    }
}

impl Rendering for NULL {
    fn render(&self, _: &SummaryOptions) -> String {
        let data = self
            .anything()
            .map(String::from_utf8_lossy)
            .unwrap_or_else(|| std::borrow::Cow::Borrowed("<no data attached>"));
        format!("data: {}", term_safe(&data))
    }
}

impl Rendering for SOA {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human() {
            self.human(opts)
        } else {
            self.plain(opts)
        }
    }
}

impl SOA {
    fn human(&self, _: &SummaryOptions) -> String {
        let refresh = humantime::format_duration(Duration::from_secs(self.refresh() as u64));
        let retry = humantime::format_duration(Duration::from_secs(self.retry() as u64));
        let expire = humantime::format_duration(Duration::from_secs(self.expire() as u64));
        let minimum = humantime::format_duration(Duration::from_secs(self.minimum() as u64));
        format!(
            "origin NS {}, responsible party {}, serial {}, refresh {}, retry {}, expire {}, negative response TTL {}",
            self.mname().paint(styles::SOA),
            self.rname().paint(styles::SOA),
            self.serial().paint(styles::SOA),
            refresh.paint(styles::SOA),
            retry.paint(styles::SOA),
            expire.paint(styles::SOA),
            minimum.paint(styles::SOA),
        )
    }

    fn plain(&self, _: &SummaryOptions) -> String {
        format!(
            "mname {}, rname {}, serial {}, refresh in {}, retry in {}, expire in {}, negative response TTL {}",
            self.mname().paint(styles::SOA),
            self.rname().paint(styles::SOA),
            self.serial().paint(styles::SOA),
            self.refresh().paint(styles::SOA),
            self.retry().paint(styles::SOA),
            self.expire().paint(styles::SOA),
            self.minimum().paint(styles::SOA),
        )
    }
}

impl Rendering for SRV {
    fn render(&self, _: &SummaryOptions) -> String {
        let style = styles::SRV;
        format!(
            "{} on port {} with priority {} and weight {}",
            self.target().paint(style),
            self.port().paint(style),
            self.priority().paint(style),
            self.weight().paint(style)
        )
    }
}

impl Rendering for TLSA {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::TLSA;
        let hex_data: String = self.cert_data().iter().map(|b| format!("{:02x}", b)).collect();
        if opts.human() {
            let usage = match self.cert_usage() {
                crate::resources::rdata::CertUsage::PkixTa => "CA constraint",
                crate::resources::rdata::CertUsage::PkixEe => "service certificate constraint",
                crate::resources::rdata::CertUsage::DaneTa => "trust anchor",
                crate::resources::rdata::CertUsage::DaneEe => "domain-issued certificate",
                other => {
                    return format!(
                        "{}, match {} of {}, data {}",
                        other.paint(style),
                        self.matching().paint(style),
                        self.selector().paint(style),
                        hex_data.paint(style)
                    )
                }
            };
            let selector = match self.selector() {
                crate::resources::rdata::Selector::Full => "full certificate",
                crate::resources::rdata::Selector::Spki => "public key only",
                other => {
                    return format!(
                        "{}, match {} of {}, data {}",
                        usage.paint(style),
                        self.matching().paint(style),
                        other.paint(style),
                        hex_data.paint(style)
                    )
                }
            };
            let matching = match self.matching() {
                crate::resources::rdata::Matching::Raw => "exact match",
                crate::resources::rdata::Matching::Sha256 => "SHA-256 hash",
                crate::resources::rdata::Matching::Sha512 => "SHA-512 hash",
                other => {
                    return format!(
                        "{}, match {} of {}, data {}",
                        usage.paint(style),
                        other.paint(style),
                        selector.paint(style),
                        hex_data.paint(style)
                    )
                }
            };
            format!(
                "{}, match {} of {}, data {}",
                usage.paint(style),
                matching.paint(style),
                selector.paint(style),
                hex_data.paint(style)
            )
        } else {
            format!(
                "{} {} {} {}",
                self.cert_usage().paint(style),
                self.selector().paint(style),
                self.matching().paint(style),
                hex_data.paint(style)
            )
        }
    }
}

impl Rendering for TXT {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human() {
            self.human(None, opts)
        } else {
            self.plain(None, opts)
        }
    }

    fn render_with_suffix(&self, suffix: &str, opts: &SummaryOptions) -> String {
        if opts.human() {
            self.human(suffix, opts)
        } else {
            self.plain(suffix, opts)
        }
    }
}

impl TXT {
    fn human<'a, T: Into<Option<&'a str>>>(&self, suffix: T, _: &SummaryOptions) -> String {
        let suffix = suffix.into().unwrap_or("");

        let txt = term_safe(&self.as_string()).into_owned();
        match ParsedTxt::from_str(&txt) {
            Ok(ParsedTxt::Spf(ref spf)) => TXT::format_spf(spf, suffix),
            Ok(ParsedTxt::Dmarc(ref dmarc)) => TXT::format_dmarc(dmarc, suffix),
            Ok(ParsedTxt::MtaSts(ref mta_sts)) => TXT::format_mta_sts(mta_sts, suffix),
            Ok(ParsedTxt::TlsRpt(ref tls_rpt)) => TXT::format_tls_rpt(tls_rpt, suffix),
            Ok(ParsedTxt::Bimi(ref bimi)) => TXT::format_bimi(bimi, suffix),
            Ok(ParsedTxt::DomainVerification(ref dv)) => TXT::format_dv(dv, suffix),
            _ => format!("'{}'{}", txt.paint(styles::TXT), suffix),
        }
    }

    fn format_spf(spf: &Spf, suffix: &str) -> String {
        let mut buf = String::new();
        buf.push_str(&format!("SPF version={}{}", spf.version().paint(styles::TXT), suffix));
        for word in spf.words() {
            buf.push_str(&format!(
                "\n\t{} {}",
                styles::itemization_prefix(),
                TXT::format_spf_word(word)
            ));
        }
        buf
    }

    fn format_spf_word(word: &Word) -> String {
        let style = styles::TXT;
        match word {
            Word::Word(q, Mechanism::All) => format!("{:?} for {}", q.paint(style), "all".paint(style)),

            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: Some(domain_spec),
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for A/AAAA record of domain {} and all IPs of corresponding cidr /{} subnet",
                q.paint(style),
                domain_spec.paint(style),
                cidr_len.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: Some(domain_spec),
                    cidr_len: None,
                },
            ) => format!(
                "{:?} for A/AAAA record of domain {}",
                q.paint(style),
                domain_spec.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: None,
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for A/AAAA record of this domain and all IPs of corresponding cidr /{} subnet",
                q.paint(style),
                cidr_len.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: None,
                    cidr_len: None,
                },
            ) => format!("{:?} for A/AAAA record of this domain", q.paint(style)),

            Word::Word(q, Mechanism::IPv4(range)) if range.contains('/') => {
                format!("{:?} for IPv4 range {}", q.paint(style), range.paint(style))
            }
            Word::Word(q, Mechanism::IPv4(range)) => format!("{:?} for IPv4 {}", q.paint(style), range.paint(style)),

            Word::Word(q, Mechanism::IPv6(range)) if range.contains('/') => {
                format!("{:?} for IPv6 range {}", q.paint(style), range.paint(style))
            }
            Word::Word(q, Mechanism::IPv6(range)) => format!("{:?} for IPv6 {}", q.paint(style), range.paint(style)),

            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: Some(domain_spec),
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for MX records of domain {} and all IPs of corresponding cidr /{} subnet",
                q.paint(style),
                domain_spec.paint(style),
                cidr_len.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: Some(domain_spec),
                    cidr_len: None,
                },
            ) => format!(
                "{:?} for MX records of domain {}",
                q.paint(style),
                domain_spec.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: None,
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for MX records of this domain and all IPs of corresponding cidr /{} subnet",
                q.paint(style),
                cidr_len.paint(style)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: None,
                    cidr_len: None,
                },
            ) => format!("{:?} for MX records of this domain", q.paint(style)),

            Word::Word(q, Mechanism::PTR(Some(domain_spec))) => format!(
                "{:?} IP addresses reverse mapping to domain {}",
                q.paint(style),
                domain_spec.paint(style)
            ),
            Word::Word(q, Mechanism::PTR(None)) => format!("{:?} IP addresses reverse mapping this domain", q),

            Word::Word(q, Mechanism::Exists(domain)) => format!(
                "{:?} for A/AAAA record according to {}",
                q.paint(style),
                domain.paint(style)
            ),
            Word::Word(q, Mechanism::Include(domain)) => {
                format!("{:?} for include from {}", q.paint(style), domain.paint(style))
            }
            Word::Modifier(Modifier::Redirect(query)) => format!("redirect to query {}", query.paint(style)),
            Word::Modifier(Modifier::Exp(explanation)) => {
                format!("explanation according to {}", explanation.paint(style))
            }
        }
    }

    fn format_dmarc(dmarc: &Dmarc, suffix: &str) -> String {
        let style = styles::TXT;
        let mut buf = String::new();
        buf.push_str(&format!(
            "DMARC version={}, policy={}{}",
            dmarc.version().paint(style),
            dmarc.policy().paint(style),
            suffix
        ));
        if let Some(sp) = dmarc.subdomain_policy() {
            buf.push_str(&format!(
                "\n\t{} subdomain policy: {}",
                styles::itemization_prefix(),
                sp.paint(style)
            ));
        }
        if let Some(adkim) = dmarc.adkim() {
            buf.push_str(&format!(
                "\n\t{} DKIM alignment: {}",
                styles::itemization_prefix(),
                adkim.paint(style)
            ));
        }
        if let Some(aspf) = dmarc.aspf() {
            buf.push_str(&format!(
                "\n\t{} SPF alignment: {}",
                styles::itemization_prefix(),
                aspf.paint(style)
            ));
        }
        if let Some(pct) = dmarc.pct() {
            buf.push_str(&format!(
                "\n\t{} percentage: {}%",
                styles::itemization_prefix(),
                pct.paint(style)
            ));
        }
        if let Some(rua) = dmarc.rua() {
            buf.push_str(&format!(
                "\n\t{} aggregate reports: {}",
                styles::itemization_prefix(),
                rua.paint(style)
            ));
        }
        if let Some(ruf) = dmarc.ruf() {
            buf.push_str(&format!(
                "\n\t{} forensic reports: {}",
                styles::itemization_prefix(),
                ruf.paint(style)
            ));
        }
        if let Some(fo) = dmarc.fo() {
            buf.push_str(&format!(
                "\n\t{} failure options: {}",
                styles::itemization_prefix(),
                fo.paint(style)
            ));
        }
        if let Some(ri) = dmarc.ri() {
            buf.push_str(&format!(
                "\n\t{} report interval: {}s",
                styles::itemization_prefix(),
                ri.paint(style)
            ));
        }
        buf
    }

    fn format_mta_sts(mta_sts: &MtaSts, suffix: &str) -> String {
        let style = styles::TXT;
        format!(
            "MTA-STS version={}, id={}{}",
            mta_sts.version().paint(style),
            mta_sts.id().paint(style),
            suffix
        )
    }

    fn format_tls_rpt(tls_rpt: &TlsRpt, suffix: &str) -> String {
        let style = styles::TXT;
        format!(
            "TLS-RPT version={}, rua={}{}",
            tls_rpt.version().paint(style),
            tls_rpt.rua().paint(style),
            suffix
        )
    }

    fn format_bimi(bimi: &Bimi, suffix: &str) -> String {
        let style = styles::TXT;
        let mut buf = String::new();
        buf.push_str(&format!("BIMI version={}{}", bimi.version().paint(style), suffix));
        if let Some(logo) = bimi.logo() {
            buf.push_str(&format!(
                "\n\t{} logo: {}",
                styles::itemization_prefix(),
                logo.paint(style)
            ));
        }
        if let Some(authority) = bimi.authority() {
            buf.push_str(&format!(
                "\n\t{} authority: {}",
                styles::itemization_prefix(),
                authority.paint(style)
            ));
        }
        buf
    }

    fn format_dv(dv: &DomainVerification, suffix: &str) -> String {
        let style = styles::TXT;
        format!(
            "{} verification for {} with {}{}",
            dv.scope().paint(style),
            dv.verifier().paint(style),
            dv.id().paint(style),
            suffix
        )
    }

    fn plain<'a, T: Into<Option<&'a str>>>(&self, suffix: T, _: &SummaryOptions) -> String {
        let suffix = suffix.into().unwrap_or("");
        let mut buf = String::new();
        for item in self.iter() {
            let str = String::from_utf8_lossy(item);
            buf.push_str(&str);
        }

        format!("'{}'{}", term_safe(&buf).paint(styles::TXT), suffix)
    }
}

impl Rendering for HINFO {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::HINFO;
        let cpu = term_safe(self.cpu());
        let os = term_safe(self.os());
        if opts.human() {
            format!("CPU: {}, OS: {}", cpu.paint(style), os.paint(style))
        } else {
            format!("cpu={}, os={}", cpu.paint(style), os.paint(style))
        }
    }
}

impl Rendering for NAPTR {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::NAPTR;
        let flags = term_safe(self.flags());
        let services = term_safe(self.services());
        let regexp = term_safe(self.regexp());
        if opts.human() {
            let flag_desc = match flags.to_lowercase().as_str() {
                "s" => "\u{2192} SRV lookup",
                "a" => "\u{2192} address lookup",
                "u" => "\u{2192} URI result",
                "p" => "\u{2192} protocol-specific",
                "" => "\u{2192} non-terminal (continue rewriting)",
                _ => flags.as_ref(),
            };
            let mut result = format!(
                "order {}, preference {}, service {} {}",
                self.order().paint(style),
                self.preference().paint(style),
                services.paint(style),
                flag_desc.paint(style)
            );
            if !regexp.is_empty() {
                result.push_str(&format!(", rewrite: {}", regexp.paint(style)));
            }
            let replacement_str = self.replacement().to_string();
            if replacement_str != "." && !replacement_str.is_empty() {
                result.push_str(&format!(", then lookup {}", self.replacement().paint(style)));
            }
            result
        } else {
            format!(
                "order={}, preference={}, flags={}, services={}, regexp={}, replacement={}",
                self.order().paint(style),
                self.preference().paint(style),
                flags.paint(style),
                services.paint(style),
                regexp.paint(style),
                self.replacement().paint(style),
            )
        }
    }
}

impl Rendering for OPENPGPKEY {
    fn render(&self, _: &SummaryOptions) -> String {
        let style = styles::OPENPGPKEY;
        let hex: String = self
            .public_key()
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect();
        let suffix = if self.public_key().len() > 16 { "..." } else { "" };
        format!("key={}{} ({} bytes)", hex.paint(style), suffix, self.public_key().len())
    }
}

impl Rendering for SSHFP {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::SSHFP;
        let hex: String = self.fingerprint().iter().map(|b| format!("{:02x}", b)).collect();
        if opts.human() {
            format!(
                "{} key, {} fingerprint: {}",
                self.algorithm().paint(style),
                self.fingerprint_type().paint(style),
                hex.paint(style),
            )
        } else {
            format!(
                "algorithm={}, type={}, fingerprint={}",
                self.algorithm().paint(style),
                self.fingerprint_type().paint(style),
                hex.paint(style),
            )
        }
    }
}

impl Rendering for SVCB {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::SVCB;
        if opts.human() {
            if self.is_alias() {
                format!("alias to {}", self.target_name().paint(style))
            } else {
                let mut result = format!(
                    "priority {}, target {}",
                    self.svc_priority().paint(style),
                    self.target_name().paint(style),
                );
                for p in self.svc_params() {
                    let value = term_safe(p.value());
                    let clean_value = value.trim_end_matches(',');
                    let param_str = match p.key() {
                        "alpn" => format!("protocols: {}", clean_value.paint(style)),
                        "no-default-alpn" => "no default protocols".to_string(),
                        "port" => format!("port: {}", clean_value.paint(style)),
                        "ipv4hint" => format!("IPv4 hints: {}", clean_value.paint(style)),
                        "ipv6hint" => format!("IPv6 hints: {}", clean_value.paint(style)),
                        "ech" => {
                            let byte_count = clean_value.len() * 3 / 4;
                            format!("encrypted client hello: ({} bytes)", byte_count)
                        }
                        key => format!("{}: {}", key, clean_value.paint(style)),
                    };
                    result.push_str(&format!("\n\t{} {}", styles::itemization_prefix(), param_str));
                }
                result
            }
        } else {
            let params: Vec<String> = self
                .svc_params()
                .iter()
                .map(|p| format!("{}={}", term_safe(p.key()), term_safe(p.value())))
                .collect();
            format!(
                "{} {} {}",
                self.svc_priority().paint(style),
                self.target_name().paint(style),
                params.join(" ").paint(style),
            )
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

impl Rendering for DNSKEY {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        if opts.human() {
            let role = if self.is_revoked() {
                "revoked key"
            } else if self.is_secure_entry_point() && self.is_zone_key() {
                "KSK (key signing key)"
            } else if self.is_zone_key() {
                "ZSK (zone signing key)"
            } else {
                "non-zone key"
            };
            let key_tag_str = self
                .key_tag()
                .map(|t| format!(", key tag {}", t.paint(style)))
                .unwrap_or_default();
            format!(
                "{}, {}{}",
                role.paint(style),
                self.algorithm().paint(style),
                key_tag_str
            )
        } else {
            let key_display = truncate(self.public_key(), 20);
            let key_tag_str = self
                .key_tag()
                .map(|t| format!(", key_tag={}", t.paint(style)))
                .unwrap_or_default();
            format!(
                "flags={}, protocol={}, algorithm={}{}, key={}",
                self.flags().paint(style),
                self.protocol().paint(style),
                self.algorithm().paint(style),
                key_tag_str,
                key_display.paint(style),
            )
        }
    }
}

impl Rendering for DS {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        let digest_display = truncate(self.digest(), 16);
        if opts.human() {
            format!(
                "key tag {}, {}, {} digest {}",
                self.key_tag().paint(style),
                self.algorithm().paint(style),
                self.digest_type().paint(style),
                digest_display.paint(style),
            )
        } else {
            format!(
                "key_tag={}, algorithm={}, digest_type={}, digest={}",
                self.key_tag().paint(style),
                self.algorithm().paint(style),
                self.digest_type().paint(style),
                digest_display.paint(style),
            )
        }
    }
}

impl Rendering for RRSIG {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        if opts.human() {
            format!(
                "covers {}, by {}, {}, key tag {}",
                self.type_covered().paint(style),
                self.signer_name().paint(style),
                self.algorithm().paint(style),
                self.key_tag().paint(style),
            )
        } else {
            format!(
                "type_covered={}, signer={}, algorithm={}, key_tag={}, labels={}, original_ttl={}, expiration={}, inception={}",
                self.type_covered().paint(style),
                self.signer_name().paint(style),
                self.algorithm().paint(style),
                self.key_tag().paint(style),
                self.labels().paint(style),
                self.original_ttl().paint(style),
                self.expiration().paint(style),
                self.inception().paint(style),
            )
        }
    }
}

impl Rendering for NSEC {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        if opts.human() {
            format!(
                "next domain {}, types: {}",
                self.next_domain_name().paint(style),
                self.types().join(", ").paint(style),
            )
        } else {
            format!(
                "next_domain={}, types={}",
                self.next_domain_name().paint(style),
                self.types().join(" ").paint(style),
            )
        }
    }
}

impl Rendering for NSEC3 {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        if opts.human() {
            format!(
                "{}, {} iteration(s), opt-out: {}, types: {}",
                self.hash_algorithm().paint(style),
                self.iterations().paint(style),
                if self.opt_out() { "yes" } else { "no" }.paint(style),
                self.types().join(", ").paint(style),
            )
        } else {
            format!(
                "hash_algorithm={}, iterations={}, opt_out={}, salt={}, types={}",
                self.hash_algorithm().paint(style),
                self.iterations().paint(style),
                self.opt_out().paint(style),
                self.salt().paint(style),
                self.types().join(" ").paint(style),
            )
        }
    }
}

impl Rendering for NSEC3PARAM {
    fn render(&self, opts: &SummaryOptions) -> String {
        let style = styles::DNSSEC;
        let salt_display = if self.salt() == "-" { "(empty)" } else { self.salt() };
        if opts.human() {
            format!(
                "{}, {} iteration(s), opt-out: {}, salt: {}",
                self.hash_algorithm().paint(style),
                self.iterations().paint(style),
                if self.opt_out() { "yes" } else { "no" }.paint(style),
                salt_display.paint(style),
            )
        } else {
            format!(
                "hash_algorithm={}, iterations={}, opt_out={}, salt={}",
                self.hash_algorithm().paint(style),
                self.iterations().paint(style),
                self.opt_out().paint(style),
                self.salt().paint(style),
            )
        }
    }
}

impl Rendering for UNKNOWN {
    fn render(&self, opts: &SummaryOptions) -> String {
        format!("code: {}, {}", self.code(), self.rdata().render(opts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::rdata::SvcParam;

    // OSC 52 writes the clipboard, BEL ends it; neither may reach the terminal from DNS data.
    const HOSTILE: &str = "x\u{1b}]52;c;aGk=\u{7}y\u{202e}z";

    fn assert_term_safe(rendered: &str) {
        assert!(!rendered.contains('\u{7}'), "raw BEL in {rendered:?}");
        assert!(!rendered.contains("\u{1b}]"), "raw OSC in {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "raw bidi override in {rendered:?}");
        assert!(rendered.contains("\\u{1b}"), "escaped ESC missing in {rendered:?}");
    }

    #[test]
    fn dns_strings_are_escaped_for_the_terminal() {
        for opts in [
            SummaryOptions::new(true, false, false),
            SummaryOptions::new(false, false, false),
        ] {
            assert_term_safe(&TXT::new(vec![HOSTILE.to_string()]).render(&opts));
            assert_term_safe(&CAA::new(false, "issue".to_string(), HOSTILE.to_string()).render(&opts));
            assert_term_safe(&CAA::new(false, HOSTILE.to_string(), "v".to_string()).render(&opts));
            assert_term_safe(&HINFO::new(HOSTILE.to_string(), HOSTILE.to_string()).render(&opts));
            let naptr = NAPTR::new(
                1,
                1,
                HOSTILE.to_string(),
                HOSTILE.to_string(),
                HOSTILE.to_string(),
                Name::root(),
            );
            assert_term_safe(&naptr.render(&opts));
            assert_term_safe(&NULL::with(HOSTILE.as_bytes().to_vec()).render(&opts));
            let svcb = SVCB::new(
                1,
                Name::root(),
                vec![SvcParam::new("alpn".to_string(), HOSTILE.to_string())],
            );
            assert_term_safe(&svcb.render(&opts));
        }
    }

    #[test]
    fn printable_text_is_unchanged() {
        assert_eq!(term_safe("v=spf1 -all ü"), "v=spf1 -all ü");
    }
}
