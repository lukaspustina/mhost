//! Repository wiring of the documentation site: ignore rules, `just` recipes, and the guarantee
//! that the crate package does not grow by anything under `website/`.

use std::fs;
use std::path::{Path, PathBuf};

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The recipe starting at the line `header`: that line plus its indented body lines.
fn recipe(justfile: &str, header: &str) -> Option<Vec<String>> {
    let mut lines = justfile.lines();
    lines.find(|l| *l == header)?;
    let mut block = vec![header.to_string()];
    for l in lines {
        if l.starts_with("    ") {
            block.push(l.to_string());
        } else {
            break;
        }
    }
    Some(block)
}

fn has_recipe(justfile: &str, name: &str) -> bool {
    justfile.lines().any(|l| {
        l.strip_prefix(name)
            .is_some_and(|rest| rest.starts_with(':') || rest.starts_with(' ') && rest.contains(':'))
    })
}

#[test]
fn gitignore_ignores_site_build_artifacts() {
    let gitignore = read(".gitignore");
    for dir in ["website/node_modules", "website/build", "website/.docusaurus"] {
        let found = gitignore
            .lines()
            .map(str::trim)
            .any(|l| l == dir || l == format!("{dir}/") || l == format!("/{dir}") || l == format!("/{dir}/"));
        assert!(found, ".gitignore lacks a line for {dir}/");
    }
}

#[test]
fn justfile_has_site_recipes() {
    let justfile = read("justfile");
    for name in ["site-install", "site-build", "site-serve"] {
        assert!(has_recipe(&justfile, name), "justfile lacks recipe {name}");
    }
    let install = recipe(&justfile, "site-install:").expect("recipe site-install: not found");
    let body = install[1..].join("\n");
    assert!(
        body.contains("npm ci"),
        "site-install must run `npm ci`, body: {body:?}"
    );
    assert!(
        body.contains("website"),
        "site-install must run in website/, body: {body:?}"
    );
}

#[test]
fn justfile_gate_recipes_are_unchanged() {
    let justfile = read("justfile");
    assert!(
        justfile.lines().any(|l| l == "adlc-verify: lint test-offline test-doc"),
        "the adlc-verify line changed"
    );
    assert_eq!(
        recipe(&justfile, "lint: clippy fmt-check").unwrap(),
        vec!["lint: clippy fmt-check"]
    );
    assert_eq!(
        recipe(&justfile, "test-doc:").unwrap(),
        vec!["test-doc:", "    {{cargo}} test --doc {{all_features}}"]
    );
    assert_eq!(
        recipe(&justfile, "test-offline:").unwrap(),
        vec![
            "test-offline:",
            "    {{cargo}} test --lib {{all_features}} -- \\",
            "        --skip services::whois::service::tests::geo_location \\",
            "        --skip services::whois::service::tests::network_info \\",
            "        --skip services::whois::service::tests::whois \\",
            "        --skip services::whois::tests::test_1_1_1_1 \\",
            "        --skip services::whois::tests::test_5x_1_1_1_1 \\",
            "        --skip nameserver::parser::test::dns_google \\",
            "        --skip nameserver::parser::test::tls_cloudflare_dns_com_tls_auth_name",
        ]
    );
}

#[test]
// Cargo reads `include` like .gitignore: an unanchored `README.md` also matches
// `website/README.md` and every README, LICENSE and CHANGELOG in `website/node_modules`.
fn cargo_include_list_is_anchored_at_the_crate_root() {
    let cargo = read("Cargo.toml");
    let start = cargo.find("include = [").expect("Cargo.toml has no include list") + "include = [".len();
    let end = start + cargo[start..].find(']').expect("include list not closed");
    let items: Vec<&str> = cargo[start..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        items,
        [
            "/README.md",
            "/LICENSE-APACHE",
            "/LICENSE-MIT",
            "/CHANGELOG.md",
            "**/*.rs",
            "/Cargo.toml",
            "!/src/website_tests/*.rs"
        ]
    );
}

#[test]
fn website_holds_nothing_the_crate_package_would_include() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("website");
    assert!(root.is_dir(), "website/ does not exist");

    let skipped = ["node_modules", "build", ".docusaurus"];
    let mut offenders: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if !skipped.contains(&name.as_str()) {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") || name == "Cargo.toml" {
                offenders.push(path);
            }
        }
    }
    assert!(offenders.is_empty(), "cargo package would pick up: {offenders:?}");
}
