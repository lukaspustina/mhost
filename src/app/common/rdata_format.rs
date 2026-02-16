use crate::resources::rdata::parsed_txt::{Mechanism, Modifier, ParsedTxt, Qualifier, Word};
use crate::resources::rdata::RData;

pub fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(ip) => ip.to_string(),
        RData::AAAA(ip) => ip.to_string(),
        RData::ANAME(name) => name.to_string(),
        RData::CNAME(name) => name.to_string(),
        RData::NS(name) => name.to_string(),
        RData::PTR(name) => name.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname(),
            soa.rname(),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        RData::TXT(txt) => txt.as_string(),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            srv.target()
        ),
        RData::CAA(caa) => {
            let critical = if caa.issuer_critical() { "128" } else { "0" };
            format!("{} {} \"{}\"", critical, caa.tag(), caa.value())
        }
        RData::SVCB(svcb) | RData::HTTPS(svcb) => {
            let params: Vec<String> = svcb
                .svc_params()
                .iter()
                .map(|p| format!("{}={}", p.key(), p.value()))
                .collect();
            if params.is_empty() {
                format!("{} {}", svcb.svc_priority(), svcb.target_name())
            } else {
                format!(
                    "{} {} {}",
                    svcb.svc_priority(),
                    svcb.target_name(),
                    params.join(" ")
                )
            }
        }
        RData::TLSA(tlsa) => format!(
            "{} {} {} [{}B]",
            tlsa.cert_usage(),
            tlsa.selector(),
            tlsa.matching(),
            tlsa.cert_data().len()
        ),
        RData::SSHFP(sshfp) => {
            let fp_hex: String = sshfp.fingerprint().iter().map(|b| format!("{b:02x}")).collect();
            format!("{} {} {}", sshfp.algorithm(), sshfp.fingerprint_type(), fp_hex)
        }
        RData::HINFO(hinfo) => format!("\"{}\" \"{}\"", hinfo.cpu(), hinfo.os()),
        RData::NAPTR(naptr) => format!(
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            naptr.order(),
            naptr.preference(),
            naptr.flags(),
            naptr.services(),
            naptr.regexp(),
            naptr.replacement()
        ),
        RData::OPENPGPKEY(key) => format!("[{}B key]", key.public_key().len()),
        RData::DNSKEY(key) => {
            let tag = key
                .key_tag()
                .map(|t| t.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!("tag={} algo={} flags={}", tag, key.algorithm(), key.flags())
        }
        RData::DS(ds) => format!(
            "tag={} algo={} digest={}",
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type()
        ),
        RData::RRSIG(rrsig) => format!(
            "{} {} tag={}",
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.key_tag()
        ),
        RData::NSEC(nsec) => {
            let types: Vec<String> = nsec.types().iter().map(|t| t.to_string()).collect();
            format!("{} [{}]", nsec.next_domain_name(), types.join(" "))
        }
        RData::NSEC3(nsec3) => format!(
            "algo={} iters={} [{}B]",
            nsec3.hash_algorithm(),
            nsec3.iterations(),
            nsec3.next_hashed_owner().len()
        ),
        RData::NSEC3PARAM(p) => format!("algo={} iters={}", p.hash_algorithm(), p.iterations()),
        RData::NULL(null) => format!("[{}B]", null.anything().map(|d| d.len()).unwrap_or(0)),
        RData::Unknown(unknown) => format!(
            "type{} [{}B]",
            unknown.code(),
            unknown.rdata().anything().map(|d| d.len()).unwrap_or(0)
        ),
        RData::OPT => "OPT".to_string(),
        RData::ZERO => "ZERO".to_string(),
    }
}

/// Human-readable multiline formatting of RData using typed accessors.
///
/// Returns a "Label: value" formatted string suitable for TUI display.
/// Uses the typed RData variants directly rather than re-parsing format_rdata output.
pub fn format_rdata_human(rdata: &RData) -> String {
    match rdata {
        RData::MX(mx) => {
            format!("Priority: {}\nExchange: {}", mx.preference(), mx.exchange())
        }
        RData::SOA(soa) => {
            format!(
                "Primary NS: {}\nContact: {}\nSerial: {}\nRefresh: {}\nRetry: {}\nExpire: {}\nMinimum TTL: {}",
                soa.mname(), soa.rname(), soa.serial(), soa.refresh(), soa.retry(), soa.expire(), soa.minimum()
            )
        }
        RData::SRV(srv) => {
            format!(
                "Priority: {}\nWeight: {}\nPort: {}\nTarget: {}",
                srv.priority(), srv.weight(), srv.port(), srv.target()
            )
        }
        RData::CAA(caa) => {
            let critical = caa.issuer_critical();
            let critical_suffix = if critical { " (critical)" } else { "" };
            let description = match (caa.tag(), caa.value().trim()) {
                ("issue", v) if v.is_empty() || v == ";" => "no CA is allowed to issue certificates".to_string(),
                ("issue", v) => format!("allow {v} to issue certificates"),
                ("issuewild", v) if v.is_empty() || v == ";" => "no CA is allowed to issue wildcard certificates".to_string(),
                ("issuewild", v) => format!("allow {v} to issue wildcard certificates"),
                ("iodef", v) => format!("report policy violations to {v}"),
                (t, v) => format!("{t} {v}"),
            };
            format!("Policy: {description}{critical_suffix}")
        }
        RData::SVCB(svcb) | RData::HTTPS(svcb) => {
            let priority = svcb.svc_priority();
            if priority == 0 {
                format!("alias to {}", svcb.target_name())
            } else {
                let mut lines = vec![format!("priority {}, target {}", priority, svcb.target_name())];
                for param in svcb.svc_params() {
                    let key = param.key().to_string();
                    let val = param.value().to_string();
                    let formatted = match key.as_str() {
                        "alpn" => format!("protocols: {val}"),
                        "no-default-alpn" => "no default protocols".to_string(),
                        "port" => format!("port: {val}"),
                        "ipv4hint" => format!("IPv4 hints: {val}"),
                        "ipv6hint" => format!("IPv6 hints: {val}"),
                        "ech" => {
                            let byte_count = val.len() * 3 / 4;
                            format!("encrypted client hello: ({byte_count} bytes)")
                        }
                        _ => format!("{key}: {val}"),
                    };
                    lines.push(formatted);
                }
                lines.join("\n")
            }
        }
        RData::TLSA(tlsa) => {
            format!(
                "Usage: {}\nSelector: {}\nMatching: {}\nData: [{}B]",
                tlsa.cert_usage(), tlsa.selector(), tlsa.matching(), tlsa.cert_data().len()
            )
        }
        RData::SSHFP(sshfp) => {
            let fp_hex: String = sshfp.fingerprint().iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "Algorithm: {}\nFingerprint Type: {}\nFingerprint: {}",
                sshfp.algorithm(), sshfp.fingerprint_type(), fp_hex
            )
        }
        RData::NAPTR(naptr) => {
            format!(
                "Order: {}\nPreference: {}\nFlags: {}\nServices: {}\nRegexp: {}\nReplacement: {}",
                naptr.order(), naptr.preference(), naptr.flags(), naptr.services(), naptr.regexp(), naptr.replacement()
            )
        }
        RData::TXT(txt) => format_txt_human(txt),
        RData::HINFO(hinfo) => {
            format!("CPU: {}\nOS: {}", hinfo.cpu(), hinfo.os())
        }
        RData::DNSKEY(key) => {
            let tag = key.key_tag().map(|t| t.to_string()).unwrap_or_else(|| "-".to_string());
            format!("Flags: {}\nAlgorithm: {}\nKey Tag: {}", key.flags(), key.algorithm(), tag)
        }
        RData::DS(ds) => {
            format!("Key Tag: {}\nAlgorithm: {}\nDigest Type: {}", ds.key_tag(), ds.algorithm(), ds.digest_type())
        }
        RData::RRSIG(rrsig) => {
            format!("Type Covered: {}\nAlgorithm: {}\nKey Tag: {}", rrsig.type_covered(), rrsig.algorithm(), rrsig.key_tag())
        }
        // For simple types, the plain format is sufficient
        _ => format_rdata(rdata),
    }
}

fn format_txt_human(txt: &crate::resources::rdata::TXT) -> String {
    let text = txt.as_string();
    match ParsedTxt::from_str(&text) {
        Ok(ParsedTxt::Spf(spf)) => {
            let mut lines = vec![
                "Type: SPF".to_string(),
                format!("Version: {}", spf.version()),
            ];
            for word in spf.words() {
                match word {
                    Word::Word(q, mechanism) => {
                        let qualifier = match q {
                            Qualifier::Pass => "Pass",
                            Qualifier::Neutral => "Neutral",
                            Qualifier::Softfail => "Softfail",
                            Qualifier::Fail => "Fail",
                        };
                        let mechanism_str = match mechanism {
                            Mechanism::All => "all".to_string(),
                            Mechanism::A { domain_spec, cidr_len } => {
                                let mut s = "a".to_string();
                                if let Some(d) = domain_spec { s = format!("a:{d}"); }
                                if let Some(c) = cidr_len { s = format!("{s}/{c}"); }
                                s
                            }
                            Mechanism::IPv4(ip) => format!("ip4:{ip}"),
                            Mechanism::IPv6(ip) => format!("ip6:{ip}"),
                            Mechanism::MX { domain_spec, cidr_len } => {
                                let mut s = "mx".to_string();
                                if let Some(d) = domain_spec { s = format!("mx:{d}"); }
                                if let Some(c) = cidr_len { s = format!("{s}/{c}"); }
                                s
                            }
                            Mechanism::PTR(d) => match d {
                                Some(d) => format!("ptr:{d}"),
                                None => "ptr".to_string(),
                            },
                            Mechanism::Exists(d) => format!("exists:{d}"),
                            Mechanism::Include(d) => format!("include:{d}"),
                        };
                        lines.push(format!("{qualifier}: {mechanism_str}"));
                    }
                    Word::Modifier(modifier) => match modifier {
                        Modifier::Redirect(d) => lines.push(format!("Redirect: {d}")),
                        Modifier::Exp(d) => lines.push(format!("Exp: {d}")),
                    },
                }
            }
            lines.join("\n")
        }
        Ok(ParsedTxt::Dmarc(dmarc)) => {
            let mut lines = vec![
                "Type: DMARC".to_string(),
                format!("Policy: {}", dmarc.policy()),
            ];
            if let Some(sp) = dmarc.subdomain_policy() { lines.push(format!("Subdomain Policy: {sp}")); }
            if let Some(rua) = dmarc.rua() { lines.push(format!("RUA: {rua}")); }
            if let Some(ruf) = dmarc.ruf() { lines.push(format!("RUF: {ruf}")); }
            if let Some(adkim) = dmarc.adkim() { lines.push(format!("DKIM Alignment: {adkim}")); }
            if let Some(aspf) = dmarc.aspf() { lines.push(format!("SPF Alignment: {aspf}")); }
            if let Some(pct) = dmarc.pct() { lines.push(format!("Percentage: {pct}")); }
            if let Some(fo) = dmarc.fo() { lines.push(format!("Failure Options: {fo}")); }
            if let Some(ri) = dmarc.ri() { lines.push(format!("Report Interval: {ri}")); }
            lines.join("\n")
        }
        Ok(ParsedTxt::MtaSts(mta_sts)) => {
            format!("Type: MTA-STS\nVersion: {}\nID: {}", mta_sts.version(), mta_sts.id())
        }
        Ok(ParsedTxt::TlsRpt(tls_rpt)) => {
            format!("Type: TLS-RPT\nVersion: {}\nRUA: {}", tls_rpt.version(), tls_rpt.rua())
        }
        Ok(ParsedTxt::Bimi(bimi)) => {
            let mut lines = vec![
                "Type: BIMI".to_string(),
                format!("Version: {}", bimi.version()),
            ];
            if let Some(logo) = bimi.logo() { lines.push(format!("Logo: {logo}")); }
            if let Some(authority) = bimi.authority() { lines.push(format!("Authority: {authority}")); }
            lines.join("\n")
        }
        Ok(ParsedTxt::DomainVerification(dv)) => {
            format!("Type: Verification\nVerifier: {}\nScope: {}\nID: {}", dv.verifier(), dv.scope(), dv.id())
        }
        Err(_) => text,
    }
}
