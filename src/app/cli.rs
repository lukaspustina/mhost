use std::collections::HashMap;
use std::time::Duration;

use crate::estimate::Estimate;
use crate::nameserver::predefined;
use crate::output::{styles::EMPH, CAPTION_PREFIX, INFO_PREFIX, ITEMAZATION_PREFIX};
use crate::resolver::{self, Lookups, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::services::ripe_stats;
use crate::statistics::Statistics;

pub fn list_predefined_nameservers() {
    println!("List of predefined servers:");
    for ns in predefined::nameserver_configs() {
        println!("{} {}", ITEMAZATION_PREFIX, ns);
    }
}

pub fn print_opts(group_opts: &ResolverGroupOpts, opts: &ResolverOpts) {
    println!(
        "{} {}: concurrent nameservers={}, max. nameservers={}, concurrent requests={}, retries={}, timeout={} s{}{}{}",
        EMPH.paint(CAPTION_PREFIX),
        EMPH.paint("Options"),
        group_opts.max_concurrent,
        group_opts.limit.unwrap(), // Safe unwrap, because of Clap's default value
        opts.max_concurrent_requests,
        opts.retries,
        opts.timeout.as_secs(),
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
    )
}

pub fn print_estimates_lookups(resolvers: &ResolverGroup, query: &resolver::MultiQuery) {
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
        format!("{} record types", num_names)
    } else {
        "1 name".to_string()
    };

    println!(
        "{} Sending {} to {} for {} of {}.",
        INFO_PREFIX, queries_str, namesservers_str, record_types_str, names_str
    )
}

pub fn print_estimates_whois(query: &ripe_stats::MultiQuery) {
    let num_resources = query.resources().len();
    let num_queries = query.query_types().len();
    let num_calls = num_resources * num_queries;

    println!(
        "{} Sending up to {} requests for {} query types of {} resources.",
        INFO_PREFIX, num_calls, num_queries, num_resources
    );
}

pub fn print_statistics<'a, T: Statistics<'a>>(data: &'a T, total_run_time: Duration) {
    let statistics = data.statistics();
    println!(
        "{} Received {} within {} ms of total run time.",
        INFO_PREFIX,
        statistics,
        total_run_time.as_millis()
    );
}

pub fn print_error_counts(lookups: &Lookups) {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for err in lookups.iter().map(|l| l.result().err()).flatten() {
        let key = format!("{:?}", err);
        let val = counts.entry(key).or_insert(0);
        *val += 1;
    }

    println!("{} Error counts", INFO_PREFIX);
    if counts.is_empty() {
        println!("{} No errors occurred.", ITEMAZATION_PREFIX)
    } else {
        for (k, v) in counts.iter() {
            println!("{} Err {} occurred {} times", ITEMAZATION_PREFIX, k, v);
        }
    }
}
