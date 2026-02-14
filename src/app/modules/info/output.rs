// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::Write;

use anyhow::Result;
use tabwriter::TabWriter;

use crate::app::console::{Console, ConsoleOpts, Fmt};
use crate::app::output::styles::ITEMAZATION_PREFIX;
use crate::app::ExitStatus;

use super::reference_data::{self, InfoEntry, Tier};

pub fn run(topic: Option<&str>) -> Result<ExitStatus> {
    let console = Console::new(ConsoleOpts::default());

    match topic {
        None => print_listing(&console),
        Some(topic) => print_detail(&console, topic),
    }
}

fn print_listing(console: &Console) -> Result<ExitStatus> {
    // DNS Record Types
    console.caption("DNS Record Types:");
    let mut tw = TabWriter::new(vec![]);
    for rt in reference_data::record_types() {
        let rfc_str = rt.rfc.map(|r| format!("({})", r)).unwrap_or_default();
        writeln!(tw, " {} {}\t{}\t{}", &*ITEMAZATION_PREFIX, rt.name, rt.summary, rfc_str)?;
    }
    flush_tabwriter(tw)?;

    // Parsed TXT Sub-Types
    println!();
    console.caption("Parsed TXT Sub-Types:");
    let mut tw = TabWriter::new(vec![]);
    for txt in reference_data::txt_sub_types() {
        let rfc_str = txt.rfc.map(|r| format!("({})", r)).unwrap_or_default();
        writeln!(tw, " {} {}\t{}\t{}", &*ITEMAZATION_PREFIX, txt.name, txt.summary, rfc_str)?;
    }
    flush_tabwriter(tw)?;

    // Well-Known Subdomains
    println!();
    console.caption("Well-Known Subdomains (domain-lookup):");
    let mut tw = TabWriter::new(vec![]);
    let mut last_category = "";
    for sub in reference_data::subdomains() {
        if sub.category != last_category {
            if !last_category.is_empty() {
                writeln!(tw)?;
            }
            let tier_label = match sub.tier {
                Tier::Default => "",
                Tier::Extended => " [extended]",
            };
            writeln!(tw, "  {}{}", Fmt::emph(sub.category), tier_label)?;
            last_category = sub.category;
        }
        writeln!(
            tw,
            " {} {}\t{}\t{}",
            &*ITEMAZATION_PREFIX, sub.subdomain, sub.record_type, sub.summary
        )?;
    }
    flush_tabwriter(tw)?;

    println!();
    console.info("Use 'mhost info <TOPIC>' for details on a specific type.");

    Ok(ExitStatus::Ok)
}

fn print_detail(console: &Console, topic: &str) -> Result<ExitStatus> {
    match reference_data::find(topic) {
        Some(InfoEntry::RecordType(rt)) => {
            console.caption(format!("{} — {}", rt.name, rt.summary));
            println!("  {}", rt.detail);
            if let (Some(rfc), Some(url)) = (rt.rfc, rt.rfc_url) {
                println!("  RFC: {} ({})", rfc, url);
            }
            Ok(ExitStatus::Ok)
        }
        Some(InfoEntry::TxtSubType(txt)) => {
            console.caption(format!("{} — {}", txt.name, txt.summary));
            println!("  Detected by prefix: {}", txt.prefix);
            println!("  {}", txt.detail);
            if let (Some(rfc), Some(url)) = (txt.rfc, txt.rfc_url) {
                println!("  RFC: {} ({})", rfc, url);
            } else if let Some(url) = txt.rfc_url {
                println!("  Spec: {}", url);
            }
            Ok(ExitStatus::Ok)
        }
        Some(InfoEntry::Subdomain(sub)) => {
            console.caption(format!("{} — {}", sub.subdomain, sub.summary));
            println!("  Record type: {}", sub.record_type);
            println!("  Category: {}", sub.category);
            println!(
                "  Tier: {}",
                match sub.tier {
                    Tier::Default => "Default (always queried)",
                    Tier::Extended => "Extended (--all flag)",
                }
            );
            println!("  {}", sub.detail);
            if let (Some(rfc), Some(url)) = (sub.rfc, sub.rfc_url) {
                println!("  RFC: {} ({})", rfc, url);
            } else if let Some(url) = sub.rfc_url {
                println!("  Spec: {}", url);
            }
            Ok(ExitStatus::Ok)
        }
        None => {
            console.caption(format!("Unknown topic: '{}'", topic));
            console.info(
                "Use 'mhost info' to list all supported record types, TXT sub-types, and well-known subdomains.",
            );
            Ok(ExitStatus::Ok)
        }
    }
}

fn flush_tabwriter(tw: TabWriter<Vec<u8>>) -> Result<()> {
    let inner = tw.into_inner()?;
    let text = String::from_utf8(inner)?;
    print!("{}", text);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_listing_succeeds() {
        // Listing mode should succeed without errors
        let result = run(None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExitStatus::Ok));
    }

    #[test]
    fn run_detail_record_type_succeeds() {
        let result = run(Some("A"));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExitStatus::Ok));
    }

    #[test]
    fn run_detail_unknown_succeeds() {
        // Unknown topic should still succeed (prints help message)
        let result = run(Some("NOTARECORD"));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ExitStatus::Ok));
    }
}
