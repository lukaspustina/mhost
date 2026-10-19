//! `website/docusaurus.config.js` points the site at the mhost repository, not at the retired
//! `mhost.pustina.de` one.

use std::path::Path;

/// The config with every quote style folded to `'` and all whitespace removed.
fn normalized_config() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("website/docusaurus.config.js");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| if c == '"' { '\'' } else { c })
        .collect()
}

#[test]
fn project_name_is_mhost() {
    let config = normalized_config();
    assert!(config.contains("projectName:'mhost',"), "projectName must be 'mhost'");
    assert!(
        !config.contains("projectName:'mhost.pustina.de'"),
        "old projectName is still set"
    );
}

#[test]
fn edit_url_points_at_website_dir_of_mhost_repo() {
    let config = normalized_config();
    assert!(
        config.contains("editUrl:'https://github.com/lukaspustina/mhost/edit/master/website/'"),
        "editUrl must be the mhost repo's website/ directory"
    );
    assert!(
        !config.contains("github.com/lukaspustina/mhost.pustina.de/edit"),
        "old editUrl is still set"
    );
}

#[test]
fn site_url_is_unchanged() {
    let config = normalized_config();
    assert!(
        config.contains("url:'https://mhost.pustina.de',"),
        "url must stay https://mhost.pustina.de"
    );
}

// Docusaurus 3.10 renders an empty blog list page even without posts; the site never had a blog.
#[test]
fn blog_plugin_is_disabled() {
    assert!(
        normalized_config().contains("blog:false,"),
        "the preset must set blog: false"
    );
}
