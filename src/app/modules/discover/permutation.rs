// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;

use tracing::debug;

static SUFFIXES: &[&str] = &[
    "-dev",
    "-staging",
    "-test",
    "-prod",
    "-old",
    "-new",
    "-internal",
    "-v2",
    "2",
    "1",
];

static PREFIXES: &[&str] = &["dev-", "staging-", "test-", "prod-", "api-"];

/// Generate permutations of discovered subdomain labels with common prefixes and suffixes.
///
/// Takes discovered first-level labels (e.g., "www", "mail", "api") and produces variations
/// like "www-dev", "dev-www", "mail-staging", etc. Results already present in `discovered_labels`
/// are excluded.
pub fn generate_permutations(discovered_labels: &HashSet<String>) -> HashSet<String> {
    let mut permutations = HashSet::new();

    for label in discovered_labels {
        for suffix in SUFFIXES {
            let permuted = format!("{label}{suffix}");
            if !discovered_labels.contains(&permuted) {
                permutations.insert(permuted);
            }
        }
        for prefix in PREFIXES {
            let permuted = format!("{prefix}{label}");
            if !discovered_labels.contains(&permuted) {
                permutations.insert(permuted);
            }
        }
    }

    debug!(
        "Generated {} permutations from {} labels",
        permutations.len(),
        discovered_labels.len()
    );
    permutations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_permutation() {
        let discovered: HashSet<String> = vec!["www".to_string()].into_iter().collect();

        let result = generate_permutations(&discovered);

        assert!(result.contains("www-dev"));
        assert!(result.contains("www-staging"));
        assert!(result.contains("www-test"));
        assert!(result.contains("dev-www"));
        assert!(result.contains("staging-www"));
        assert!(!result.contains("www")); // Original not in permutations
    }

    #[test]
    fn empty_input() {
        let discovered: HashSet<String> = HashSet::new();

        let result = generate_permutations(&discovered);

        assert!(result.is_empty());
    }

    #[test]
    fn excludes_already_discovered() {
        let discovered: HashSet<String> = vec!["www".to_string(), "www-dev".to_string()].into_iter().collect();

        let result = generate_permutations(&discovered);

        // www-dev should be excluded since it's already discovered
        assert!(!result.contains("www-dev"));
        // But other permutations of www should be present
        assert!(result.contains("www-staging"));
    }

    #[test]
    fn multiple_labels() {
        let discovered: HashSet<String> = vec!["api".to_string(), "mail".to_string()].into_iter().collect();

        let result = generate_permutations(&discovered);

        assert!(result.contains("api-dev"));
        assert!(result.contains("mail-dev"));
        assert!(result.contains("dev-api"));
        assert!(result.contains("dev-mail"));
    }
}
