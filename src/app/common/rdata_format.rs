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
