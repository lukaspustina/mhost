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

use yansi::Paint;

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
        match self.record_type() {
            RecordType::A => format!("{}:\t{}{}", "A".paint(*styles::A), self.data().a().unwrap().render(opts), suffix),
            RecordType::AAAA => format!(
                "{}:\t{}{}",
                "AAAA".paint(*styles::AAAA),
                self.data().aaaa().unwrap().render(opts),
                suffix
            ),
            RecordType::ANAME => format!(
                "{}:\t{}{}",
                "ANAME".paint(*styles::NAME),
                self.data().cname().unwrap().render(opts),
                suffix
            ),
            RecordType::CNAME => format!(
                "{}:\t{}{}",
                "CNAME".paint(*styles::NAME),
                self.data().cname().unwrap().render(opts),
                suffix
            ),
            RecordType::MX => format!(
                "{}:\t{}{}",
                "MX".paint(*styles::MX),
                self.data().mx().unwrap().render(opts),
                suffix
            ),
            RecordType::NULL => format!("{}:\t{}{}", "NULL", self.data().null().unwrap().render(opts), suffix),
            RecordType::NS => format!(
                "{}:\t{}{}",
                "NS".paint(*styles::NAME),
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
                "SOA".paint(*styles::SOA),
                self.data().soa().unwrap().render(opts),
                suffix
            ),
            RecordType::SRV => format!(
                "{}:\t{}{}",
                "SRV".paint(*styles::SRV),
                self.data().srv().unwrap().render(opts),
                suffix
            ),
            RecordType::TXT => format!(
                "{}:\t{}",
                "TXT".paint(*styles::TXT),
                self.data().txt().unwrap().render_with_suffix(suffix, opts)
            ),
            RecordType::Unknown(_) => format!("Unknown:\t{}{}", self.data().unknown().unwrap().render(opts), suffix),
            rr_type => format!("{}:\t<not yet implemented>{}", rr_type, suffix),
        }
    }
}

impl Rendering for Ipv4Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(*styles::A).to_string()
    }
}

impl Rendering for Ipv6Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(*styles::AAAA).to_string()
    }
}

impl Rendering for Name {
    fn render(&self, _: &SummaryOptions) -> String {
        self.paint(*styles::NAME).to_string()
    }
}

impl Rendering for MX {
    fn render(&self, _: &SummaryOptions) -> String {
        format!(
            "{}\twith preference {:2}",
            self.exchange().paint(*styles::MX),
            self.preference().paint(*styles::MX),
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
            self.mname().paint(*styles::SOA),
            self.rname().paint(*styles::SOA),
            self.serial().paint(*styles::SOA),
            refresh.paint(*styles::SOA),
            retry.paint(*styles::SOA),
            expire.paint(*styles::SOA),
            minimum.paint(*styles::SOA),
        )
    }

    fn plain(&self, _: &SummaryOptions) -> String {
        format!(
            "mname {}, rname {}, serial {}, refresh in {}, retry in {}, expire in {}, negative response TTL {}",
            self.mname().paint(*styles::SOA),
            self.rname().paint(*styles::SOA),
            self.serial().paint(*styles::SOA),
            self.refresh().paint(*styles::SOA),
            self.retry().paint(*styles::SOA),
            self.expire().paint(*styles::SOA),
            self.minimum().paint(*styles::SOA),
        )
    }
}

impl Rendering for SRV {
    fn render(&self, _: &SummaryOptions) -> String {
        let style = *styles::SRV;
        format!(
            "{} on port {} with priority {} and weight {}",
            self.target().paint(style),
            self.port().paint(style),
            self.priority().paint(style),
            self.weight().paint(style)
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
            _ => format!("'{}'{}", txt.paint(*styles::TXT), suffix),
        }
    }

    fn format_spf(spf: &Spf, suffix: &str) -> String {
        let mut buf = String::new();
        buf.push_str(&format!("SPF version={}{}", spf.version().paint(*styles::TXT), suffix));
        for word in spf.words() {
            buf.push_str(&format!("\n\t{} {}", &*ITEMAZATION_PREFIX, TXT::format_spf_word(word)));
        }
        buf
    }

    fn format_spf_word(word: &Word) -> String {
        let style = *styles::TXT;
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

    fn format_dv(dv: &DomainVerification, suffix: &str) -> String {
        let style = *styles::TXT;
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

        format!("'{}'{}", buf.paint(*styles::TXT), suffix)
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
        pub static ref A: Style = Style::new().fg(Color::White).bold();
        pub static ref AAAA: Style = Style::new().fg(Color::White).bold();
        pub static ref MX: Style = Style::new().fg(Color::Yellow);
        pub static ref NAME: Style = Style::new().fg(Color::Blue);
        pub static ref SOA: Style = Style::new().fg(Color::Green);
        pub static ref SRV: Style = Style::new().fg(Color::Red);
        pub static ref TXT: Style = Style::new().fg(Color::Magenta);
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
