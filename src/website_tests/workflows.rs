//! Phase 2 wiring: the deploy workflow for the site, the `paths-ignore` on CI, and the guarantee
//! that the release workflow stays untouched. No YAML parser is available, so the few keys needed
//! are read by indentation-aware line scanning.

use std::fs;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A non-blank, comment-free line: its indentation and trimmed text.
type Line = (usize, String);

fn lines(text: &str) -> Vec<Line> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            (!t.is_empty() && !t.starts_with('#')).then(|| (l.len() - l.trim_start().len(), t.to_string()))
        })
        .collect()
}

/// The key line `key:` among the first-level lines of `block` plus everything nested below it.
/// Returns the text after the colon on the key line, and the nested lines.
fn child<'a>(block: &'a [Line], key: &str) -> Option<(String, &'a [Line])> {
    let base = block.first()?.0;
    let start = block
        .iter()
        .position(|(i, t)| *i == base && t.strip_prefix(key).is_some_and(|r| r.starts_with(':')))?;
    let rest = block[start].1[key.len() + 1..].trim().to_string();
    let end = block[start + 1..]
        .iter()
        .position(|(i, _)| *i <= base)
        .map_or(block.len(), |p| start + 1 + p);
    Some((rest, &block[start + 1..end]))
}

/// First-level key names of `block`.
fn keys(block: &[Line]) -> Vec<String> {
    let Some(base) = block.first().map(|l| l.0) else {
        return vec![];
    };
    block
        .iter()
        .filter(|(i, t)| *i == base && !t.starts_with('-'))
        .map(|(_, t)| t.split(':').next().unwrap().trim().to_string())
        .collect()
}

/// The list values of `key` in `block`, from inline `[a, b]` or `- a` list form, unquoted.
fn entries(block: &[Line], key: &str) -> Vec<String> {
    let (rest, nested) = child(block, key).unwrap_or_else(|| panic!("no key {key}"));
    let mut raw = vec![rest];
    raw.extend(nested.iter().map(|(_, t)| t.clone()));
    raw.iter()
        .flat_map(|t| {
            t.trim_start_matches("- ")
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn on_block(all: &[Line]) -> Vec<Line> {
    let top: Vec<Line> = all.to_vec();
    child(&top, "on").expect("workflow has no `on:` block").1.to_vec()
}

fn has_line(all: &[Line], wanted: &str) -> bool {
    all.iter().any(|(_, t)| t.trim_start_matches("- ") == wanted)
}

#[test]
fn website_workflow_deploys_on_version_tags_and_manual_dispatch_only() {
    let all = lines(&read(".github/workflows/website.yml"));
    let on = on_block(&all);
    assert_eq!(
        keys(&on),
        ["push", "workflow_dispatch"],
        "`on:` must hold exactly push and workflow_dispatch"
    );
    let (_, push) = child(&on, "push").unwrap();
    assert_eq!(keys(push), ["tags"], "push must carry only a tags filter");
    assert_eq!(entries(push, "tags"), ["v*"]);
}

#[test]
fn website_workflow_builds_in_website_and_publishes_to_pages() {
    let all = lines(&read(".github/workflows/website.yml"));
    assert!(
        all.iter().any(|(_, t)| t.contains("uses: actions/setup-node")),
        "setup-node not used"
    );
    assert!(
        has_line(&all, "node-version-file: website/.nvmrc"),
        "node-version-file must be website/.nvmrc"
    );
    let text: Vec<&str> = all.iter().map(|(_, t)| t.as_str()).collect();
    let in_website = text
        .iter()
        .any(|t| t.trim_start_matches("- ") == "working-directory: website")
        || text.iter().any(|t| t.contains("cd website"));
    assert!(in_website, "npm steps must run in website/");
    assert!(text.iter().any(|t| t.ends_with("npm ci")), "no `npm ci` step");
    assert!(
        text.iter().any(|t| t.ends_with("npm run build")),
        "no `npm run build` step"
    );
    assert!(text.iter().any(|t| t.contains("uses: actions/upload-pages-artifact")));
    assert!(
        has_line(&all, "path: website/build"),
        "artifact path must be website/build"
    );
    assert!(text.iter().any(|t| t.contains("uses: actions/deploy-pages")));
}

#[test]
fn website_workflow_has_pages_permissions_and_non_cancelling_concurrency() {
    let all = lines(&read(".github/workflows/website.yml"));
    for want in ["contents: read", "pages: write", "id-token: write"] {
        assert!(has_line(&all, want), "permissions lack `{want}`");
    }
    assert!(
        all.iter().any(|(_, t)| t.starts_with("concurrency:")),
        "no concurrency block"
    );
    assert!(
        has_line(&all, "cancel-in-progress: false"),
        "cancel-in-progress must be false"
    );
}

#[test]
fn ci_workflow_ignores_website_paths_and_keeps_its_filters() {
    let all = lines(&read(".github/workflows/ci.yml"));
    let on = on_block(&all);
    let (_, push) = child(&on, "push").expect("ci has no push trigger");
    let (_, pr) = child(&on, "pull_request").expect("ci has no pull_request trigger");
    assert_eq!(entries(push, "paths-ignore"), ["website/**"], "push paths-ignore");
    assert_eq!(entries(pr, "paths-ignore"), ["website/**"], "pull_request paths-ignore");
    assert_eq!(entries(push, "tags"), ["!v*"], "push tags filter");
    assert!(
        entries(push, "branches").contains(&"master".to_string()),
        "push branches lacks master"
    );
    assert!(
        entries(pr, "branches").contains(&"master".to_string()),
        "pull_request branches lacks master"
    );
}

#[test]
fn release_workflow_is_unchanged() {
    let bytes = read(".github/workflows/release.yml").into_bytes();
    assert_eq!(bytes.len(), 2847, "release.yml length changed");
    assert_eq!(fnv1a64(&bytes), 0xc7d3_9901_a6a8_022d, "release.yml content changed");
}
