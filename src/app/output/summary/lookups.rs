// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tabwriter::TabWriter;

use crate::resolver::Lookups;
use crate::resources::rdata::parsed_txt::{DomainVerification, Mechanism, Modifier, ParsedTxt, Word};
use crate::resources::rdata::{parsed_txt::Spf, Name, MX, NULL, SOA, SRV, TXT, UNKNOWN};
use crate::resources::{NameToIpAddr, Record};
use crate::{Error, RecordType};

use super::*;
use crate::app::output::styles::ITEMAZATION_PREFIX;

impl SummaryFormatter for Lookups {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        let mut rr_types: Vec<_> = self.record_types().into_iter().collect();
        rr_types.sort_by(order_by_ordinal);

        let mut tw = TabWriter::new(vec![]);

        for rr_type in rr_types {
            let records = self.records_by_type(rr_type);
            output_records(&mut tw, records, opts)?;
        }

        let text_buffer = tw.into_inner().map_err(|_| Error::InternalError {
            msg: "finish TabWriter buffer",
        })?;
        let out = String::from_utf8(text_buffer).map_err(|_| Error::InternalError {
            msg: "convert TabWriter buffer to output",
        })?;
        write!(writer, "{}", out)?;

        Ok(())
    }
}

fn output_records<W: Write>(writer: &mut W, records: Vec<&Record>, opts: &SummaryOptions) -> Result<()> {
    let records_counted = summarize_records(records);

    for (r, set) in records_counted {
        let mut suffix = if opts.condensed {
            "".to_string()
        } else {
            let ttls: Vec<_> = set.iter().map(|x| x.ttl()).collect();
            let ttl_summary = crate::statistics::Summary::summary(ttls.as_slice());

            let ttl = format_ttl_summary(&ttl_summary, opts);
            format!(" {} ({})", ttl, set.len())
        };

        if opts.show_domain_names {
            if opts.human {
                suffix = format!("{} for domain name {}", suffix, r.name())
            } else {
                suffix = format!("{} q={}", suffix, r.name())
            }
        }

        writeln!(
            writer,
            " {} {}",
            &*ITEMAZATION_PREFIX,
            r.render_with_suffix(&suffix, opts)
        )?;
    }

    Ok(())
}

//noinspection RsExternalLinter
fn summarize_records(records: Vec<&Record>) -> HashMap<&Record, Vec<&Record>> {
    let mut records_set: HashMap<&Record, Vec<&Record>> = HashMap::new();
    for r in records {
        let set = records_set.entry(r).or_default();
        set.push(r)
    }
    records_set
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn format_ttl_summary(summary: &crate::statistics::Summary<u32>, opts: &SummaryOptions) -> String {
    let ttl_min = summary.min.unwrap_or(0) as u64;
    let ttl_max = summary.max.unwrap_or(0) as u64;

    match (opts.human, ttl_min == ttl_max) {
        (true, true) => format!(
            "expires in {}",
            humantime::format_duration(Duration::from_secs(ttl_min))
        ),
        (true, false) => format!(
            "expires in [min {}, max {}]",
            humantime::format_duration(Duration::from_secs(ttl_min)),
            humantime::format_duration(Duration::from_secs(ttl_max)),
        ),
        (false, true) => format!("TTL={}", ttl_min),
        (false, false) => format!("TTL=[{}, {}]", ttl_min, ttl_max),
    }
}

impl Rendering for Record {
    fn render(&self, opts: &SummaryOptions) -> String {
        self.render_with_suffix("", opts)
    }

    fn render_with_suffix(&self, suffix: &str, opts: &SummaryOptions) -> String {
        use styles::*;
        match self.record_type() {
            RecordType::A => format!("{}:\t{}{}", A.paint("A"), self.data().a().unwrap().render(opts), suffix),
            RecordType::AAAA => format!(
                "{}:\t{}{}",
                AAAA.paint("AAAA"),
                self.data().aaaa().unwrap().render(opts),
                suffix
            ),
            RecordType::ANAME => format!(
                "{}:\t{}{}",
                NAME.paint("ANAME"),
                self.data().cname().unwrap().render(opts),
                suffix
            ),
            RecordType::CNAME => format!(
                "{}:\t{}{}",
                NAME.paint("CNAME"),
                self.data().cname().unwrap().render(opts),
                suffix
            ),
            RecordType::MX => format!(
                "{}:\t{}{}",
                MX.paint("MX"),
                self.data().mx().unwrap().render(opts),
                suffix
            ),
            RecordType::NULL => format!("{}:\t{}{}", "NULL", self.data().null().unwrap().render(opts), suffix),
            RecordType::NS => format!(
                "{}:\t{}{}",
                NAME.paint("NS"),
                self.data().ns().unwrap().render(opts),
                suffix
            ),
            RecordType::PTR => format!(
                "PTR:\t{}:\t{}{}",
                self.name().to_ip_addr_string(),
                self.data().ptr().unwrap().render(opts),
                suffix
            ),
            RecordType::SOA => format!(
                "{}:\t{}{}",
                SOA.paint("SOA"),
                self.data().soa().unwrap().render(opts),
                suffix
            ),
            RecordType::SRV => format!(
                "{}:\t{}{}",
                SRV.paint("SRV"),
                self.data().srv().unwrap().render(opts),
                suffix
            ),
            RecordType::TXT => format!(
                "{}:\t{}",
                TXT.paint("TXT"),
                self.data().txt().unwrap().render_with_suffix(suffix, opts)
            ),
            RecordType::Unknown(_) => format!("Unknown:\t{}{}", self.data().unknown().unwrap().render(opts), suffix),
            rr_type => format!("{}:\t<not yet implemented>{}", rr_type, suffix),
        }
    }
}

impl Rendering for Ipv4Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::A.paint(self).to_string()
    }
}

impl Rendering for Ipv6Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::AAAA.paint(self).to_string()
    }
}

impl Rendering for Name {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::NAME.paint(self).to_string()
    }
}

impl Rendering for MX {
    fn render(&self, _: &SummaryOptions) -> String {
        format!(
            "{}\twith preference {:2}",
            styles::MX.paint(self.exchange()),
            styles::MX.paint(self.preference()),
        )
    }
}

impl Rendering for NULL {
    fn render(&self, _: &SummaryOptions) -> String {
        let data = self
            .anything()
            .map(String::from_utf8_lossy)
            .unwrap_or_else(|| std::borrow::Cow::Borrowed("<no data attached>"));
        format!("data: {}", data)
    }
}

impl Rendering for SOA {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human {
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
            styles::SOA.paint(self.mname()),
            styles::SOA.paint(self.rname()),
            styles::SOA.paint(self.serial()),
            styles::SOA.paint(refresh),
            styles::SOA.paint(retry),
            styles::SOA.paint(expire),
            styles::SOA.paint(minimum),
        )
    }

    fn plain(&self, _: &SummaryOptions) -> String {
        format!(
            "mname {}, rname {}, serial {}, refresh in {}, retry in {}, expire in {}, negative response TTL {}",
            styles::SOA.paint(self.mname()),
            styles::SOA.paint(self.rname()),
            styles::SOA.paint(self.serial()),
            styles::SOA.paint(self.refresh()),
            styles::SOA.paint(self.retry()),
            styles::SOA.paint(self.expire()),
            styles::SOA.paint(self.minimum()),
        )
    }
}

impl Rendering for SRV {
    fn render(&self, _: &SummaryOptions) -> String {
        use styles::SRV as style;
        format!(
            "{} on port {} with priority {} and weight {}",
            style.paint(self.target()),
            style.paint(self.port()),
            style.paint(self.priority()),
            style.paint(self.weight())
        )
    }
}

impl Rendering for TXT {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human {
            self.human(None, opts)
        } else {
            self.plain(None, opts)
        }
    }

    fn render_with_suffix(&self, suffix: &str, opts: &SummaryOptions) -> String {
        if opts.human {
            self.human(suffix, opts)
        } else {
            self.plain(suffix, opts)
        }
    }
}

impl TXT {
    fn human<'a, T: Into<Option<&'a str>>>(&self, suffix: T, _: &SummaryOptions) -> String {
        let suffix = suffix.into().unwrap_or("");

        let txt = self.as_string();
        match ParsedTxt::from_str(&txt) {
            Ok(ParsedTxt::Spf(ref spf)) => TXT::format_spf(spf, suffix),
            Ok(ParsedTxt::DomainVerification(ref dv)) => TXT::format_dv(dv, suffix),
            _ => format!("'{}'{}", styles::TXT.paint(&txt), suffix),
        }
    }

    fn format_spf(spf: &Spf, suffix: &str) -> String {
        let mut buf = String::new();
        buf.push_str(&format!("SPF version={}{}", styles::TXT.paint(spf.version()), suffix));
        for word in spf.words() {
            buf.push_str(&format!("\n\t{} {}", &*ITEMAZATION_PREFIX, TXT::format_spf_word(word)));
        }
        buf
    }

    fn format_spf_word(word: &Word) -> String {
        use styles::TXT as style;
        match word {
            Word::Word(q, Mechanism::All) => format!("{:?} for {}", style.paint(q), style.paint("all")),

            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: Some(domain_spec),
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for A/AAAA record of domain {} and all IPs of corresponding cidr /{} subnet",
                style.paint(q),
                style.paint(domain_spec),
                style.paint(cidr_len)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: Some(domain_spec),
                    cidr_len: None,
                },
            ) => format!(
                "{:?} for A/AAAA record of domain {}",
                style.paint(q),
                style.paint(domain_spec)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: None,
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for A/AAAA record of this domain and all IPs of corresponding cidr /{} subnet",
                style.paint(q),
                style.paint(cidr_len)
            ),
            Word::Word(
                q,
                Mechanism::A {
                    domain_spec: None,
                    cidr_len: None,
                },
            ) => format!("{:?} for A/AAAA record of this domain", style.paint(q)),

            Word::Word(q, Mechanism::IPv4(range)) if range.contains('/') => {
                format!("{:?} for IPv4 range {}", style.paint(q), style.paint(range))
            }
            Word::Word(q, Mechanism::IPv4(range)) => format!("{:?} for IPv4 {}", style.paint(q), style.paint(range)),

            Word::Word(q, Mechanism::IPv6(range)) if range.contains('/') => {
                format!("{:?} for IPv6 range {}", style.paint(q), style.paint(range))
            }
            Word::Word(q, Mechanism::IPv6(range)) => format!("{:?} for IPv6 {}", style.paint(q), style.paint(range)),

            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: Some(domain_spec),
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for MX records of domain {} and all IPs of corresponding cidr /{} subnet",
                style.paint(q),
                style.paint(domain_spec),
                style.paint(cidr_len)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: Some(domain_spec),
                    cidr_len: None,
                },
            ) => format!(
                "{:?} for MX records of domain {}",
                style.paint(q),
                style.paint(domain_spec)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: None,
                    cidr_len: Some(cidr_len),
                },
            ) => format!(
                "{:?} for MX records of this domain and all IPs of corresponding cidr /{} subnet",
                style.paint(q),
                style.paint(cidr_len)
            ),
            Word::Word(
                q,
                Mechanism::MX {
                    domain_spec: None,
                    cidr_len: None,
                },
            ) => format!("{:?} for MX records of this domain", style.paint(q)),

            Word::Word(q, Mechanism::PTR(Some(domain_spec))) => format!(
                "{:?} IP addresses reverse mapping to domain {}",
                style.paint(q),
                style.paint(domain_spec)
            ),
            Word::Word(q, Mechanism::PTR(None)) => format!("{:?} IP addresses reverse mapping this domain", q),

            Word::Word(q, Mechanism::Exists(domain)) => format!(
                "{:?} for A/AAAA record according to {}",
                style.paint(q),
                style.paint(domain)
            ),
            Word::Word(q, Mechanism::Include(domain)) => {
                format!("{:?} for include from {}", style.paint(q), style.paint(domain))
            }
            Word::Modifier(Modifier::Redirect(query)) => format!("redirect to query {}", style.paint(query)),
            Word::Modifier(Modifier::Exp(explanation)) => {
                format!("explanation according to {}", style.paint(explanation))
            }
        }
    }

    fn format_dv(dv: &DomainVerification, suffix: &str) -> String {
        use styles::TXT as style;
        format!(
            "{} verification for {} with {}{}",
            style.paint(dv.scope()),
            style.paint(dv.verifier()),
            style.paint(dv.id()),
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

        format!("'{}'{}", styles::TXT.paint(&buf), suffix)
    }
}

impl Rendering for UNKNOWN {
    fn render(&self, opts: &SummaryOptions) -> String {
        format!("code: {}, {}", self.code(), self.rdata().render(opts))
    }
}

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};

    lazy_static! {
        pub static ref A: Style = Style::new(Color::White).bold();
        pub static ref AAAA: Style = Style::new(Color::White).bold();
        pub static ref MX: Style = Style::new(Color::Yellow);
        pub static ref NAME: Style = Style::new(Color::Blue);
        pub static ref SOA: Style = Style::new(Color::Green);
        pub static ref SRV: Style = Style::new(Color::Red);
        pub static ref TXT: Style = Style::new(Color::Magenta);
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;

    #[test]
    fn summary() {
        crate::utils::tests::logging::init();
        let opts = SummaryOptions::default();
        let config = OutputConfig::summary(opts);
        let output = Output::new(&config);
        let lookups = Lookups::new(Vec::new());

        let mut buf = Vec::new();
        let res = output.output(&mut buf, &lookups);

        assert_that(&res).is_ok();
    }
}
