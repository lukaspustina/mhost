// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub mod ct_logs;
pub mod permutation;
pub mod srv_probing;
pub mod txt_mining;
pub mod wordlist;

use std::collections::HashSet;

use rand::distr::Alphanumeric;
use rand::Rng;
use tracing::{debug, info};

use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookup, Lookups};

pub use ct_logs::query_ct_logs;
pub use permutation::generate_permutations;
pub use srv_probing::{well_known_srv_probes, SrvProbe};
pub use txt_mining::{extract_dmarc_domains, extract_spf_domains, well_known_txt_subdomains};
pub use wordlist::Wordlist;

/// Generate random subdomain labels for wildcard detection.
///
/// Produces `number` random alphanumeric strings of length `len`.
/// These are used to probe whether a domain has wildcard DNS resolution.
pub fn rnd_names(number: usize, len: usize) -> Vec<String> {
    info!(
        "Generating {} number of random domain names with length {}",
        number, len
    );
    let mut rng = rand::rng();
    (0..number)
        .map(|_| (&mut rng).sample_iter(Alphanumeric).take(len).map(char::from).collect())
        .inspect(|x| debug!("Generated random domain name: '{}'", x))
        .collect()
}

/// Filter lookups that match wildcard resolutions.
pub fn filter_wildcard_responses(wildcard_lookups: &Option<Lookups>, lookups: Lookups) -> Lookups {
    if let Some(ref wildcards) = wildcard_lookups {
        let wildcard_records = wildcards.records();
        let wildcard_resolutions = wildcard_records.iter().unique().iter().map(|x| x.data()).collect();

        let lookups = lookups
            .into_iter()
            .filter(|lookup: &Lookup| {
                let records = lookup.records();
                let set: HashSet<_> = records.iter().unique().iter().map(|x| x.data()).collect();
                set.is_disjoint(&wildcard_resolutions)
            })
            .collect();
        Lookups::new(lookups)
    } else {
        lookups
    }
}
