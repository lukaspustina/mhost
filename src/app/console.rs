use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use yansi::Paint;

use crate::app::output::styles::{
    self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, FINISHED_PREFIX, INFO_PREFIX, ITEMAZATION_PREFIX, OK_PREFIX,
};
use crate::app::output::OutputConfig;
use crate::app::{output, AppConfig};
use crate::estimate::Estimate;
use crate::resolver::{self, Lookups, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::services::server_lists::ServerListSpec;
use crate::services::whois;
use crate::statistics::Statistics;

#[derive(Debug)]
pub struct Console {
    quiet: bool,
    show_errors: bool,
    partial_results: bool,
}

impl Default for Console {
    fn default() -> Console {
        Console {
            quiet: false,
            show_errors: false,
            partial_results: false,
        }
    }
}

impl Console {
    pub fn new(app_config: &AppConfig) -> Console {
        Console {
            quiet: app_config.quiet,
            show_errors: app_config.show_errors,
            ..Default::default()
        }
    }

    pub fn with_partial_results(app_config: &AppConfig, partial_results: bool) -> Console {
        Console {
            quiet: app_config.quiet,
            show_errors: app_config.show_errors,
            partial_results,
        }
    }

    pub fn print_opts(&self, group_opts: &ResolverGroupOpts, opts: &ResolverOpts) {
        self.caption(format!(
            "{}: concurrent nameservers={}, max. nameservers={}, concurrent requests={}, retries={}, timeout={}s, ndots={}{}{}{}",
            Fmt::emph("Options"),
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

    pub fn print_estimates_lookups(&self, resolvers: &ResolverGroup, query: &resolver::MultiQuery) {
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

    pub fn print_estimates_downloads(&self, server_list_specs: &[ServerListSpec]) {
        self.info(format!("Downloading {} server lists.", server_list_specs.len()));
    }

    pub fn print_error_counts(&self, lookups: &Lookups) {
        let mut counts: HashMap<String, usize> = HashMap::new();

        for err in lookups.iter().map(|l| l.result().err()).flatten() {
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

    pub fn print_estimates_whois(&self, query: &whois::MultiQuery) {
        let num_resources = query.resources().len();
        let num_queries = query.query_types().len();
        let num_calls = num_resources * num_queries;

        println!(
            "{} Sending up to {} requests for {} query types of {} resources.",
            &*INFO_PREFIX, num_calls, num_queries, num_resources
        );
    }

    pub fn emphazise<T: fmt::Display>(&self, item: T) {
        println!("{}", Fmt::emph(item))
    }

    pub fn info<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", &*INFO_PREFIX, str.as_ref());
    }

    pub fn attention<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::attention(&*ATTENTION_PREFIX), str.as_ref());
    }

    pub fn finished(&self) {
        self.emphazise(format!("{} Finished.", &*FINISHED_PREFIX));
    }

    pub fn caption<T: AsRef<str>>(&self, str: T) {
        self.emphazise(format!("{} {}", &*CAPTION_PREFIX, str.as_ref()));
    }

    pub fn failed<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::attention(&*ERROR_PREFIX), str.as_ref());
    }

    pub fn error<T: AsRef<str>>(&self, str: T) {
        eprintln!("{} {}", Fmt::attention(&*ERROR_PREFIX), str.as_ref());
    }

    pub fn ok<T: AsRef<str>>(&self, str: T) {
        println!("{} {}", Fmt::ok(&*OK_PREFIX), str.as_ref());
    }

    pub fn itemize<T: AsRef<str>>(&self, str: T) {
        println!(" {} {}", &*ITEMAZATION_PREFIX, str.as_ref());
    }

    pub fn not_quiet(&self) -> bool {
        !self.quiet
    }

    /** Check if partial results should be printed
     *
     * This is true, `partial_results` is set, independent of `quiet`
     */
    pub fn show_partial_results(&self) -> bool {
        self.partial_results
    }

    /** Check if headers and footers for partial steps should be printed
     *
     * This is true, if `quiet` is not set and `partial_results` is set.
     */
    pub fn show_partial_headers(&self) -> bool {
        !self.quiet && self.partial_results
    }

    /** Check if detailed error counts should be printed
     *
     * This is true, if `quiet` is not set and `show_errors` is set.
     */
    pub fn show_errors(&self) -> bool {
        !self.quiet && self.show_errors
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

    pub fn ok<T: fmt::Display>(item: T) -> Paint<T> {
        styles::OK.paint(item)
    }
}

pub fn print_partial_results(
    console: &Console,
    output_config: &OutputConfig,
    lookups: &Lookups,
    total_run_time: Duration,
) -> anyhow::Result<()> {
    if console.show_partial_headers() {
        console.print_statistics(lookups, total_run_time);
    }
    if console.show_partial_results() {
        output::output(output_config, lookups)?;
    }
    if console.show_errors() {
        console.print_error_counts(lookups);
    }

    Ok(())
}
