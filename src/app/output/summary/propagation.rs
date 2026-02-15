// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tabwriter::TabWriter;
use yansi::Paint;

use super::*;
use crate::app::modules::propagation::propagation::{PropagationResults, ResolverInfo};
use crate::app::output::styles as output_styles;
use crate::app::output::Ordinal;
use crate::resources::Record;

impl SummaryFormatter for PropagationResults {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        let types_str: Vec<String> = self.record_types.iter().map(|t| t.to_string()).collect();
        writeln!(
            writer,
            "{} DNS Propagation for {} ({})",
            output_styles::caption_prefix(),
            self.domain_name,
            types_str.join(",")
        )?;

        // --- Authoritative Nameservers section ---
        if !self.authoritative_ns.is_empty() {
            writeln!(
                writer,
                "{} Authoritative Nameservers:",
                output_styles::info_prefix()
            )?;

            if let Some(ref soa) = self.soa_details {
                if let Some(serial) = self.authoritative_serial {
                    writeln!(
                        writer,
                        "  {} SOA serial: {} (refresh={}s, retry={}s, minimum={}s)",
                        output_styles::info_prefix(),
                        serial,
                        soa.refresh,
                        soa.retry,
                        soa.minimum,
                    )?;
                }
            } else if let Some(serial) = self.authoritative_serial {
                writeln!(
                    writer,
                    "  {} SOA serial: {}",
                    output_styles::info_prefix(),
                    serial
                )?;
            }

            // List each NS compactly
            for ns in &self.authoritative_ns {
                let serial_str = ns
                    .serial
                    .map(|s| format!(" \u{2014} serial {}", s))
                    .unwrap_or_default();
                let error_str = ns
                    .error
                    .as_ref()
                    .map(|e| format!(" \u{2014} error: {}", e))
                    .unwrap_or_default();
                writeln!(
                    writer,
                    "  {} {} ({}){}{}",
                    output_styles::info_prefix(),
                    ns.ns_name,
                    ns.ip,
                    serial_str,
                    error_str,
                )?;
            }

            // Sync status
            let serials: Vec<u32> = self
                .authoritative_ns
                .iter()
                .filter_map(|ns| ns.serial)
                .collect();
            let all_same = !serials.is_empty() && serials.iter().all(|s| *s == serials[0]);
            if all_same {
                writeln!(
                    writer,
                    " {} All authoritative servers in sync.",
                    output_styles::ok_prefix()
                )?;
            } else if serials.len() > 1 {
                writeln!(
                    writer,
                    " {} Authoritative servers have different serials: zone sync may be in progress.",
                    output_styles::attention_prefix(),
                )?;
            }

            // Deduplicated records across all authoritative NSes
            let mut all_records: Vec<Record> = Vec::new();
            for ns in &self.authoritative_ns {
                for record in &ns.records {
                    if !all_records.contains(record) {
                        all_records.push(record.clone());
                    }
                }
            }
            write_records(writer, &all_records, opts)?;
        }

        // --- Recursive Resolvers section ---
        writeln!(
            writer,
            "{} Recursive Resolvers:",
            output_styles::info_prefix()
        )?;

        if self.resolver_groups.is_empty() {
            writeln!(
                writer,
                " {} No responses received.",
                output_styles::info_prefix()
            )?;
        } else {
            for group in &self.resolver_groups {
                let count = group.servers.len();
                let pct = if self.total_resolvers > 0 {
                    count * 100 / self.total_resolvers
                } else {
                    0
                };

                match group.serial {
                    Some(serial) => {
                        let status = if group.is_current { "Current" } else { "Stale" };
                        writeln!(
                            writer,
                            " {} {} serial {} ({}/{} servers, {}%):",
                            output_styles::info_prefix(),
                            status,
                            serial,
                            count,
                            self.total_resolvers,
                            pct,
                        )?;
                    }
                    None => {
                        writeln!(
                            writer,
                            " {} {} ({}/{} servers, {}%):",
                            output_styles::caption_prefix(),
                            "No SOA / Error".paint(output_styles::ERROR),
                            count,
                            self.total_resolvers,
                            pct,
                        )?;
                    }
                }

                write_server_list(writer, &group.servers)?;
                write_records(writer, &group.records, opts)?;
            }
        }

        // --- Unreachable servers ---
        if !self.unreachable_servers.is_empty() {
            writeln!(
                writer,
                " {} {} ({} server{}, not counted):",
                output_styles::caption_prefix(),
                "Unreachable".paint(output_styles::ERROR),
                self.unreachable_servers.len(),
                if self.unreachable_servers.len() == 1 {
                    ""
                } else {
                    "s"
                },
            )?;
            write_server_list(writer, &self.unreachable_servers)?;
        }

        // --- Propagation summary ---
        if self.authoritative_serial.is_some() {
            let pct = self.propagation_pct();
            if self.is_fully_propagated() {
                writeln!(
                    writer,
                    " {} Propagation: 100% complete.",
                    output_styles::ok_prefix()
                )?;
            } else {
                writeln!(
                    writer,
                    "{} Propagation: {}% complete.",
                    output_styles::attention_prefix(),
                    pct,
                )?;
            }
        } else {
            writeln!(
                writer,
                "{} Could not determine authoritative serial for propagation comparison.",
                output_styles::attention_prefix(),
            )?;
        }

        Ok(())
    }
}

/// Render records sorted by type ordinal, tab-aligned, using the same ` * TYPE: DATA`
/// pattern as the lookup command.
fn write_records<W: Write>(
    writer: &mut W,
    records: &[Record],
    opts: &SummaryOptions,
) -> crate::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let mut sorted: Vec<&Record> = records.iter().collect();
    sorted.sort_by_key(|a| a.record_type().ordinal());

    let mut tw = TabWriter::new(vec![]);
    for record in sorted {
        writeln!(
            tw,
            " {} {}",
            output_styles::itemization_prefix(),
            record.render(opts)
        )?;
    }
    let buf = tw
        .into_inner()
        .map_err(|_| crate::Error::InternalError {
            msg: "finish TabWriter buffer",
        })?;
    writer.write_all(&buf)?;
    Ok(())
}

fn write_server_list<W: Write>(writer: &mut W, servers: &[ResolverInfo]) -> crate::Result<()> {
    for server in servers {
        writeln!(
            writer,
            "  {} {} ({})",
            output_styles::info_prefix(),
            server.name,
            server.ip
        )?;
    }
    Ok(())
}
