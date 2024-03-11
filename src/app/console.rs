// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;
use yansi::Paint;

use crate::app::output::styles::{
    self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, FINISHED_PREFIX, INFO_PREFIX, ITEMAZATION_PREFIX, OK_PREFIX,
};
use crate::app::output::summary::SummaryFormatter;
use crate::app::output::OutputConfig;
use crate::app::{output, AppConfig};
use crate::error::Errors;
use crate::estimate::Estimate;
use crate::resolver::{self, MultiQuery, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::services::server_lists::ServerListSpec;
use crate::services::whois;
use crate::statistics::Statistics;

#[derive(Debug, Default)]
pub struct ConsoleOpts {
    quiet: bool,
    show_errors: bool,
    partial_results: bool,
}

impl ConsoleOpts {
    pub fn with_partial_results(self, partial_results: bool) -> ConsoleOpts {
        ConsoleOpts {
            partial_results,
            ..self
        }
    }
}

impl From<&AppConfig> for ConsoleOpts {
    fn from(app_config: &AppConfig) -> Self {
        ConsoleOpts {
            quiet: app_config.quiet,
            show_errors: app_config.show_errors,
            partial_results: false,
        }
    }
}

#[derive(Debug)]
pub struct Console {
    opts: ConsoleOpts,
}

impl Console {
    pub fn new(opts: ConsoleOpts) -> Console {
        Console { opts }
    }

    pub fn print_resolver_opts(&self, group_opts: &ResolverGroupOpts, opts: &ResolverOpts) {
        if self.not_quiet() {
            self.caption(format!(
            "{}: mode={}, concurrent nameservers={}, max. nameservers={}, concurrent requests={}, retries={}, timeout={}s, ndots={}{}{}{}",
            Fmt::emph("Options"),
            group_opts.mode,
            group_opts.max_concurrent,
            group_opts.limit.unwrap(), // Safe unwrap, because of Clap's default value
            opts.max_concurrent_requests,
            opts.retries,
            opts.timeout.as_secs(),
            opts.ndots,
            if opts.expects_multiple_responses {
                ", wait for additional responses"
            } else {
                ""
            },
            if opts.abort_on_error { ", abort on error" } else { "" },
            if opts.abort_on_timeout {
                ", abort on timeout"
            } else {
                ""
            },
        ));
        }
    }

    pub fn print_lookup_estimates(&self, resolvers: &ResolverGroup, query: &resolver::MultiQuery) {
        let num_servers = resolvers.opts.limit.unwrap().min(resolvers.len()); // Safe unwrap, because of Clap's default value
        let num_names = query.num_names();
        let num_record_types = query.num_record_types();
        let estimate = resolvers.estimate(query);

        let queries_str = if estimate.min_requests == estimate.max_requests {
            format!(
                "{} {}",
                estimate.min_requests,
                if estimate.min_requests > 1 {
                    "requests"
                } else {
                    "request"
                }
            )
        } else {
            format!(
                "between {} and {} requests",
                estimate.min_requests, estimate.max_requests
            )
        };
        let namesservers_str = if num_servers > 1 {
            format!("{} nameservers", num_servers)
        } else {
            "1 nameserver".to_string()
        };
        let record_types_str = if num_record_types > 1 {
            format!("{} record types", num_record_types)
        } else {
            "1 record type".to_string()
        };
        let names_str = if num_names > 1 {
            format!("{} names", num_names)
        } else {
            "1 name".to_string()
        };

        self.info(format!(
            "Sending {} to {} for {} of {}.",
            queries_str, namesservers_str, record_types_str, names_str
        ));
    }

    pub fn print_download_estimates(&self, server_list_specs: &[ServerListSpec]) {
        self.info(format!("Downloading {} server lists.", server_list_specs.len()));
    }

    pub fn print_whois_estimates(&self, query: &whois::MultiQuery) {
        let num_resources = query.resources().len();
        let num_queries = query.query_types().len();
        let num_calls = num_resources * num_queries;

        println!(
            "{} Sending up to {} requests for {} query types of {} resources.",
            &*INFO_PREFIX, num_calls, num_queries, num_resources
        );
    }

    pub fn print_partial_headers(&self, caption: &str, resolvers: &ResolverGroup, query: &MultiQuery) {
        if self.show_partial_headers() {
            self.caption(caption);
            self.print_lookup_estimates(resolvers, query);
        }
    }

    /// Print partial results in case they are not muted and output-type is not JSON
    pub fn print_partial_results<'a, T>(
        &self,
        output_config: &OutputConfig,
        results: &'a T,
        run_time: Duration,
    ) -> anyhow::Result<()>
    where
        T: Serialize + SummaryFormatter + Statistics<'a> + Errors,
        <T as Statistics<'a>>::StatsOut: std::fmt::Display,
    {
        if self.show_partial_headers() {
            self.print_statistics(results, run_time);
        }
        if self.show_partial_results() && !matches!(output_config, OutputConfig::Json { .. }) {
            output::output(output_config, results)?;
        }
        if self.show_errors() {
            self.print_error_counts(results);
        }

        Ok(())
    }

    pub fn print_error_counts<E: Errors>(&self, results: &E) {
        let mut counts: HashMap<String, usize> = HashMap::new();

        for err in results.errors() {
            let key = format!("{:?}", err);
            let val = counts.entry(key).or_insert(0);
            *val += 1;
        }

        self.info("Error counts");
        if counts.is_empty() {
            self.ok("No errors occurred.");
        } else {
            for (k, v) in counts.iter() {
                self.itemize(format!("Err {} occurred {} times", k, v));
            }
        }
    }

    pub fn print_statistics<'a, T: Statistics<'a>>(&self, data: &'a T, total_run_time: Duration)
    where
        <T as Statistics<'a>>::StatsOut: fmt::Display,
    {
        let statistics = data.statistics();
        self.info(format!(
            "Received {} within {} ms of total run time.",
            statistics,
            total_run_time.as_millis()
        ));
    }

    pub fn print_finished(&self) {
        if self.not_quiet() {
            self.finished();
        }
    }

    pub fn emphasize<T: fmt::Display>(&self, item: T) {
        println!("{}", Fmt::emph(item))
    }

    pub fn info<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", &*INFO_PREFIX, str.as_ref());
    }

    pub fn attention<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::attention(&*ATTENTION_PREFIX), str.as_ref());
    }

    pub fn finished(&self) {
        self.emphasize(format!("{} Finished.", &*FINISHED_PREFIX));
    }

    pub fn caption<T: AsRef<str>>(&self, str: T) {
        self.emphasize(format!("{} {}", &*CAPTION_PREFIX, str.as_ref()));
    }

    pub fn failed<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::error(&*ERROR_PREFIX), str.as_ref());
    }

    pub fn error<T: AsRef<str>>(&self, str: T) {
        eprintln!("{} {}", Fmt::error(&*ERROR_PREFIX), str.as_ref());
    }

    pub fn ok<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::ok(&*OK_PREFIX), str.as_ref());
    }

    pub fn itemize<T: AsRef<str>>(&self, str: T) {
        println!(" {} {}", &*ITEMAZATION_PREFIX, str.as_ref());
    }

    pub fn not_quiet(&self) -> bool {
        !self.opts.quiet
    }

    /** Check if partial results should be printed
     *
     * This is true, `partial_results` is set, independent of `quiet`
     */
    pub fn show_partial_results(&self) -> bool {
        self.opts.partial_results
    }

    /** Check if headers and footers for partial steps should be printed
     *
     * This is true, if `quiet` is not set and `partial_results` is set.
     */
    pub fn show_partial_headers(&self) -> bool {
        !self.opts.quiet && self.opts.partial_results
    }

    /** Check if detailed error counts should be printed
     *
     * This is true, if `quiet` is not set and `show_errors` is set.
     */
    pub fn show_errors(&self) -> bool {
        !self.opts.quiet && self.opts.show_errors
    }
}

pub struct Fmt {}

impl Fmt {
    pub fn emph<T: fmt::Display>(item: T) -> Paint<T> {
        styles::EMPH.paint(item)
    }

    pub fn attention<T: fmt::Display>(item: T) -> Paint<T> {
        styles::ATTENTION.paint(item)
    }

    pub fn error<T: fmt::Display>(item: T) -> Paint<T> {
        styles::ERROR.paint(item)
    }

    pub fn ok<T: fmt::Display>(item: T) -> Paint<T> {
        styles::OK.paint(item)
    }
}
