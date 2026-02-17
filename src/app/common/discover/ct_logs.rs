// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, info};

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn query_ct_logs(domain: &str) -> Result<HashSet<String>> {
    info!("Querying Certificate Transparency logs at crt.sh for '{}'", domain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client for CT log query")?;

    let response = client
        .get("https://crt.sh/")
        .query(&[("q", format!("%.{domain}")), ("output", "json".to_string())])
        .header("User-Agent", "mhost DNS discovery tool")
        .send()
        .await
        .context("Failed to query crt.sh")?;

    if !response.status().is_success() {
        anyhow::bail!("crt.sh returned HTTP {}", response.status());
    }

    // Limit response size to 50 MB to prevent memory exhaustion on popular domains
    const MAX_CT_RESPONSE_SIZE: u64 = 50 * 1024 * 1024;
    if let Some(len) = response.content_length() {
        if len > MAX_CT_RESPONSE_SIZE {
            anyhow::bail!(
                "crt.sh response too large: {} bytes (limit: {} bytes)",
                len,
                MAX_CT_RESPONSE_SIZE
            );
        }
    }

    let body = response.text().await.context("Failed to read crt.sh response body")?;
    if body.len() as u64 > MAX_CT_RESPONSE_SIZE {
        anyhow::bail!(
            "crt.sh response too large: {} bytes (limit: {} bytes)",
            body.len(),
            MAX_CT_RESPONSE_SIZE
        );
    }
    parse_ct_response(&body, domain)
}

fn parse_ct_response(body: &str, domain: &str) -> Result<HashSet<String>> {
    if body.is_empty() || body == "[]" {
        debug!("Empty CT log response");
        return Ok(HashSet::new());
    }

    let entries: Vec<CrtShEntry> = match serde_json::from_str(body) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to parse crt.sh JSON response: {}", e);
            return Ok(HashSet::new());
        }
    };

    let names = extract_names_from_entries(&entries, domain);
    info!("Found {} unique names from CT logs", names.len());
    Ok(names)
}

fn extract_names_from_entries(entries: &[CrtShEntry], domain: &str) -> HashSet<String> {
    entries
        .iter()
        .flat_map(|entry| entry.name_value.split('\n'))
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
        .filter(|name| !name.contains('*'))
        .filter(|name| name.ends_with(domain))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_json() {
        let body = r#"[
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "api.example.com\ncdn.example.com"}
        ]"#;

        let result = parse_ct_response(body, "example.com").unwrap();

        assert!(result.contains("www.example.com"));
        assert!(result.contains("mail.example.com"));
        assert!(result.contains("api.example.com"));
        assert!(result.contains("cdn.example.com"));
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn parse_empty_response() {
        let result = parse_ct_response("[]", "example.com").unwrap();
        assert!(result.is_empty());

        let result = parse_ct_response("", "example.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_malformed_response() {
        let result = parse_ct_response("not valid json", "example.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn wildcard_filtering() {
        let body = r#"[
            {"name_value": "*.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "*.sub.example.com"}
        ]"#;

        let result = parse_ct_response(body, "example.com").unwrap();

        assert!(!result.iter().any(|n| n.contains('*')));
        assert!(result.contains("www.example.com"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filters_unrelated_domains() {
        let body = r#"[
            {"name_value": "www.example.com"},
            {"name_value": "www.other.com"}
        ]"#;

        let result = parse_ct_response(body, "example.com").unwrap();
        assert!(result.contains("www.example.com"));
        assert!(!result.contains("www.other.com"));
    }

    #[test]
    fn deduplicates_entries() {
        let body = r#"[
            {"name_value": "www.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "WWW.EXAMPLE.COM"}
        ]"#;

        let result = parse_ct_response(body, "example.com").unwrap();
        assert_eq!(result.len(), 1);
    }
}
