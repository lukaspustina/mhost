// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::convert::TryInto;
use std::io::Write;

use anyhow::Result;
use clap::ArgMatches;
use serde::Serialize;
use tracing::info;
use yansi::Paint;

use chain::{DelegationLevel, TrustChain};
use config::DnssecConfig;

use crate::app::modules::{AppModule, Environment, PartialResult, PartialResultExt, RunInfo};
use crate::app::output::styles as output_styles;
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resources::dnssec_validation::{self, Severity};

pub mod chain;
pub mod config;

pub async fn run(args: &ArgMatches, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("dnssec module selected.");
    let args = args.subcommand_matches("dnssec").unwrap();
    let config: DnssecConfig = args.try_into()?;

    Dnssec::init(app_config, &config)
        .await?
        .execute()
        .await?
        .output()
        .into_result()
}

pub struct Dnssec {}

impl AppModule<DnssecConfig> for Dnssec {}

impl Dnssec {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a DnssecConfig,
    ) -> PartialResult<DnssecRun<'a>> {
        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;

        Ok(DnssecRun { env, domain_name })
    }
}

pub struct DnssecRun<'a> {
    env: Environment<'a, DnssecConfig>,
    domain_name: hickory_resolver::Name,
}

impl<'a> DnssecRun<'a> {
    pub async fn execute(self) -> PartialResult<DnssecOutput<'a>> {
        let max_hops = self.env.mod_config.max_hops;
        let partial_results = self.env.console.show_partial_results();

        let root_label = match (self.env.app_config.ipv4_only, self.env.app_config.ipv6_only) {
            (true, _) => "IPv4 root servers",
            (_, true) => "IPv6 root servers",
            _ => "IPv4+IPv6 root servers",
        };
        if self.env.console.not_quiet() {
            self.env.console.info(format!(
                "Walking DNSSEC trust chain for {} from {}.",
                self.domain_name, root_label
            ));
        }
        info!(
            "Starting DNSSEC trust chain walk for {}",
            self.domain_name
        );

        // Print header early when partial results are enabled
        if partial_results {
            let mut stdout = std::io::stdout();
            write_header(&mut stdout, &self.env.mod_config.domain_name)
                .map_err(|e| anyhow::anyhow!("failed to write partial output: {}", e))?;
        }

        // For partial results, we render each level as soon as the *next* level
        // arrives (so we can validate DS→DNSKEY bindings). We track how many
        // levels have been rendered so far.
        let rendered_count = std::cell::Cell::new(0usize);
        let opts = SummaryOptions::default();

        type LevelCallback<'b> = Option<Box<dyn FnMut(&[DelegationLevel]) + 'b>>;
        let callback: LevelCallback<'_> = if partial_results {
            Some(Box::new(|levels: &[DelegationLevel]| {
                let already = rendered_count.get();
                let mut stdout = std::io::stdout();
                // When a new level arrives, we can now render the *previous* level
                // with full DS→DNSKEY validation (because we have the new level's keys).
                // On first call (levels.len()==1), nothing to render yet — we need the
                // next level's keys. On subsequent calls, render the previous level.
                if levels.len() >= 2 && already < levels.len() - 1 {
                    for i in already..levels.len() - 1 {
                        let level = &levels[i];
                        let next = &levels[i + 1];
                        let _ = write_level(
                            &mut stdout,
                            level,
                            Some(&next.ds_records),
                            Some(&next.dnskeys),
                            false,
                            &opts,
                        );
                    }
                    rendered_count.set(levels.len() - 1);
                }
            }))
        } else {
            None
        };

        let trust_chain = chain::walk_trust_chain(
            &self.env.mod_config.domain_name,
            self.env.app_config,
            max_hops,
            callback,
        )
        .await;

        // Render the last level (which has no child) and the footer
        if partial_results {
            let already = rendered_count.get();
            let mut stdout = std::io::stdout();
            if already < trust_chain.levels.len() {
                for i in already..trust_chain.levels.len() {
                    let level = &trust_chain.levels[i];
                    let next_ds = trust_chain.levels.get(i + 1).map(|l| &l.ds_records);
                    let next_dnskeys = trust_chain.levels.get(i + 1).map(|l| &l.dnskeys);
                    let is_last = i + 1 == trust_chain.levels.len();
                    let _ = write_level(&mut stdout, level, next_ds, next_dnskeys, is_last, &opts);
                }
            }
            let _ = write_footer(&mut stdout, &trust_chain);
        }

        Ok(DnssecOutput {
            env: self.env,
            trust_chain,
            partial_results_shown: partial_results,
        })
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub struct DnssecOutput<'a> {
    pub env: Environment<'a, DnssecConfig>,
    pub trust_chain: TrustChain,
    pub partial_results_shown: bool,
}

impl DnssecOutput<'_> {
    pub fn output(self) -> PartialResult<ExitStatus> {
        match self.env.app_config.output {
            OutputType::Json => self.json_output(),
            OutputType::Summary => self.summary_output(),
        }
    }

    fn json_output(self) -> PartialResult<ExitStatus> {
        #[derive(Debug, Serialize)]
        struct Json {
            info: RunInfo,
            #[serde(flatten)]
            trust_chain: TrustChain,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                Err(crate::Error::InternalError {
                    msg: "summary formatting is not supported for JSON output",
                })
            }
        }
        let data = Json {
            info: self.env.run_info,
            trust_chain: self.trust_chain,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        if !self.partial_results_shown {
            output::output(&self.env.app_config.output_config, &self.trust_chain)?;
        }

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        Ok(ExitStatus::Ok)
    }
}

// ---------------------------------------------------------------------------
// Summary formatter — tree rendering
// ---------------------------------------------------------------------------

impl SummaryFormatter for TrustChain {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> crate::Result<()> {
        write_header(writer, &self.domain_name)?;

        for (i, level) in self.levels.iter().enumerate() {
            let next_ds = self.levels.get(i + 1).map(|l| &l.ds_records);
            let next_dnskeys = self.levels.get(i + 1).map(|l| &l.dnskeys);
            let is_last = i + 1 == self.levels.len();
            write_level(writer, level, next_ds, next_dnskeys, is_last, opts)?;
        }

        write_footer(writer, self)?;
        Ok(())
    }
}

fn write_header<W: Write>(writer: &mut W, domain_name: &str) -> crate::Result<()> {
    writeln!(
        writer,
        "{} DNSSEC Trust Chain: {}",
        output_styles::caption_prefix(),
        domain_name,
    )?;
    Ok(())
}

fn write_level<W: Write>(
    writer: &mut W,
    level: &DelegationLevel,
    next_ds: Option<&Vec<crate::resources::rdata::DS>>,
    next_dnskeys: Option<&Vec<crate::resources::rdata::DNSKEY>>,
    is_last: bool,
    _opts: &SummaryOptions,
) -> crate::Result<()> {
    writeln!(writer)?;

    // Zone name header
    let zone_label = if level.zone_name == "." {
        ". (root)".to_string()
    } else {
        level.zone_name.clone()
    };
    writeln!(writer, "  {}", zone_label.paint(output_styles::EMPH))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let has_ds_link = next_ds.is_some_and(|ds| !ds.is_empty());
    let total_items = level.dnskeys.len() + level.rrsigs.len();

    // Collect chain-link tag sets to highlight only tags that connect records
    let rrsig_tags: HashSet<u16> = level
        .rrsigs
        .iter()
        .filter(|r| r.type_covered() == "DNSKEY")
        .map(|r| r.key_tag())
        .collect();
    let parent_ds_tags: HashSet<u16> = level.ds_records.iter().map(|ds| ds.key_tag()).collect();
    let dnskey_tags: HashSet<u16> = level.dnskeys.iter().filter_map(|k| k.key_tag()).collect();
    let child_dnskey_tags: HashSet<u16> = next_dnskeys
        .map(|keys| keys.iter().filter_map(|k| k.key_tag()).collect())
        .unwrap_or_default();

    // DNSKEY records
    for (j, key) in level.dnskeys.iter().enumerate() {
        let is_last_item = !has_ds_link && j + level.rrsigs.len() == total_items - 1 && is_last;
        let prefix = tree_prefix(is_last_item);

        let role = if key.is_revoked() {
            "revoked"
        } else if key.is_secure_entry_point() {
            "KSK"
        } else if key.is_zone_key() {
            "ZSK"
        } else {
            "key"
        };

        let tag_str = key
            .key_tag()
            .map(|t| format!("tag={}", t))
            .unwrap_or_default();

        let algo_finding = dnssec_validation::classify_algorithm(key.algorithm());
        let status = format_finding_inline(&algo_finding);

        let is_linked = key
            .key_tag()
            .is_some_and(|t| rrsig_tags.contains(&t) || parent_ds_tags.contains(&t));

        writeln!(
            writer,
            "  {} DNSKEY  {}  {}  {}{}",
            prefix,
            role,
            style_chain_tag(&tag_str, is_linked),
            key.algorithm(),
            status,
        )?;
    }

    // RRSIG records (only those covering DNSKEY)
    let dnskey_rrsigs: Vec<&crate::resources::rdata::RRSIG> = level
        .rrsigs
        .iter()
        .filter(|r| r.type_covered() == "DNSKEY")
        .collect();

    for (j, rrsig) in dnskey_rrsigs.iter().enumerate() {
        let is_last_item = !has_ds_link && j == dnskey_rrsigs.len() - 1 && is_last;
        let prefix = tree_prefix(is_last_item);

        let exp_finding = dnssec_validation::classify_rrsig_expiration(rrsig, now);
        let expiry_text = format_rrsig_expiry(rrsig, now);
        let status = format_finding_inline(&exp_finding);

        let is_linked = dnskey_tags.contains(&rrsig.key_tag());

        writeln!(
            writer,
            "  {} RRSIG   covers DNSKEY  {}  {}{}",
            prefix,
            style_chain_tag(&format!("tag={}", rrsig.key_tag()), is_linked),
            expiry_text,
            status,
        )?;
    }

    // DS records linking to child zone
    if let Some(ds_records) = next_ds {
        if !ds_records.is_empty() {
            // Separator
            writeln!(writer, "  {}", tree_continuation())?;

            let child_dnskey_refs: Vec<&crate::resources::rdata::DNSKEY> = next_dnskeys
                .map(|keys| keys.iter().collect())
                .unwrap_or_default();

            for (j, ds) in ds_records.iter().enumerate() {
                let is_last_ds = j == ds_records.len() - 1;
                let prefix = if is_last_ds && is_last {
                    tree_prefix(true)
                } else {
                    tree_ds_prefix()
                };

                let binding = dnssec_validation::classify_ds_binding(ds, &child_dnskey_refs);

                // Show what the DS links to for chain-of-trust visibility
                let link_info = if binding.severity == Severity::Ok {
                    let matched_key = child_dnskey_refs.iter().find(|k| k.key_tag() == Some(ds.key_tag()));
                    let role = match matched_key {
                        Some(k) if k.is_secure_entry_point() => "KSK",
                        Some(k) if k.is_zone_key() => "ZSK",
                        _ => "DNSKEY",
                    };
                    format!(
                        "  {} {}",
                        tree_link_arrow(),
                        format!("{} tag={}", role, ds.key_tag()).paint(output_styles::EMPH),
                    )
                } else {
                    String::new()
                };

                let status = format_finding_inline(&binding);
                let is_linked = child_dnskey_tags.contains(&ds.key_tag());

                writeln!(
                    writer,
                    "  {} DS  {}  {}  {}{}{}",
                    prefix,
                    style_chain_tag(&format!("tag={}", ds.key_tag()), is_linked),
                    ds.algorithm(),
                    ds.digest_type(),
                    status,
                    link_info,
                )?;
            }
        }
    }

    Ok(())
}

fn write_footer<W: Write>(writer: &mut W, chain: &TrustChain) -> crate::Result<()> {
    writeln!(writer)?;

    let status_text = match chain.status {
        Severity::Ok => "secure".paint(output_styles::OK).to_string(),
        Severity::Warning => "warnings".paint(output_styles::ATTENTION).to_string(),
        Severity::Failed => "broken".paint(output_styles::ERROR).to_string(),
    };

    writeln!(
        writer,
        "{} Chain status: {} ({} level{}, {:.0?})",
        output_styles::finished_prefix(),
        status_text,
        chain.levels.len(),
        if chain.levels.len() == 1 { "" } else { "s" },
        chain.total_time,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tree rendering helpers
// ---------------------------------------------------------------------------

fn tree_prefix(is_last: bool) -> &'static str {
    if output_styles::caption_prefix() == ">" {
        // ASCII mode
        if is_last { "\\--" } else { "+--" }
    } else if is_last {
        "\u{2514}\u{2500}\u{2500}"
    } else {
        "\u{251C}\u{2500}\u{2500}"
    }
}

fn tree_ds_prefix() -> &'static str {
    if output_styles::caption_prefix() == ">" {
        // ASCII mode
        "+->"
    } else {
        "\u{251C}\u{2500}\u{25B8}"
    }
}

fn tree_link_arrow() -> &'static str {
    if output_styles::caption_prefix() == ">" {
        "->"
    } else {
        "\u{2192}" // →
    }
}

fn tree_continuation() -> &'static str {
    if output_styles::caption_prefix() == ">" {
        // ASCII mode
        "|"
    } else {
        "\u{2502}"
    }
}

fn style_chain_tag(tag: &str, linked: bool) -> String {
    if linked {
        tag.cyan().bold().to_string()
    } else {
        tag.to_string()
    }
}

fn format_finding_inline(finding: &dnssec_validation::Finding) -> String {
    match finding.severity {
        Severity::Ok => format!(
            "  {}",
            "valid".paint(output_styles::OK)
        ),
        Severity::Warning => format!(
            "  {}",
            finding.message.paint(output_styles::ATTENTION)
        ),
        Severity::Failed => format!(
            "  {}",
            finding.message.paint(output_styles::ERROR)
        ),
    }
}

fn format_rrsig_expiry(rrsig: &crate::resources::rdata::RRSIG, now: u32) -> String {
    let expiration = rrsig.expiration();
    if expiration < now {
        "expired".to_string()
    } else {
        let remaining_secs = expiration - now;
        let remaining_days = remaining_secs / 86400;
        format!("expires in {}d", remaining_days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::resources::dnssec_validation::Finding;

    #[test]
    fn summary_output_renders_header() {
        let chain = TrustChain {
            domain_name: "example.com".to_string(),
            levels: Vec::new(),
            total_time: Duration::from_millis(0),
            status: Severity::Ok,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        chain.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("DNSSEC Trust Chain: example.com"));
        assert!(output.contains("Chain status:"));
    }

    #[test]
    fn summary_output_renders_levels() {
        use crate::resources::rdata::{DnssecAlgorithm, DNSKEY};

        let ksk = DNSKEY::new(257, 3, DnssecAlgorithm::EcdsaP256Sha256, "key".to_string(), Some(20326), true, true, false);

        let chain = TrustChain {
            domain_name: "example.com".to_string(),
            levels: vec![DelegationLevel {
                zone_name: ".".to_string(),
                dnskeys: vec![ksk],
                ds_records: Vec::new(),
                rrsigs: Vec::new(),
                findings: vec![Finding::ok("test")],
                status: Severity::Ok,
            }],
            total_time: Duration::from_millis(50),
            status: Severity::Ok,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        chain.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains(". (root)"));
        assert!(output.contains("DNSKEY"));
        assert!(output.contains("KSK"));
        assert!(output.contains("tag=20326"));
    }

    #[test]
    fn summary_output_broken_chain() {
        let chain = TrustChain {
            domain_name: "dnssec-failed.org".to_string(),
            levels: vec![DelegationLevel {
                zone_name: ".".to_string(),
                dnskeys: Vec::new(),
                ds_records: Vec::new(),
                rrsigs: Vec::new(),
                findings: vec![Finding::failed("broken chain")],
                status: Severity::Failed,
            }],
            total_time: Duration::from_millis(100),
            status: Severity::Failed,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        chain.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("broken"));
    }

    #[test]
    fn summary_output_unsigned_zone() {
        let chain = TrustChain {
            domain_name: "unsigned.example".to_string(),
            levels: vec![
                DelegationLevel {
                    zone_name: ".".to_string(),
                    dnskeys: Vec::new(),
                    ds_records: Vec::new(),
                    rrsigs: Vec::new(),
                    findings: Vec::new(),
                    status: Severity::Ok,
                },
                DelegationLevel {
                    zone_name: "example.".to_string(),
                    dnskeys: Vec::new(),
                    ds_records: Vec::new(),
                    rrsigs: Vec::new(),
                    findings: vec![Finding::warning("not DNSSEC-signed")],
                    status: Severity::Warning,
                },
            ],
            total_time: Duration::from_millis(75),
            status: Severity::Warning,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        chain.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("warnings"));
        assert!(output.contains("2 levels"));
    }
}
