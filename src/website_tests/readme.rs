//! `website/README.md` names the toolchain, the three site recipes and the deploy workflow, and
//! carries no trace of the superseded deploy path.

use std::path::Path;

fn readme() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("website/README.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn readme_names_docusaurus_3_the_site_recipes_and_the_deploy_workflow() {
    let text = readme();
    assert!(text.contains("Docusaurus 3"), "README must name Docusaurus 3");
    for recipe in ["just site-install", "just site-build", "just site-serve"] {
        assert!(text.contains(recipe), "README must name the recipe `{recipe}`");
    }
    assert!(
        text.contains("website.yml"),
        "README must name the deploy workflow .github/workflows/website.yml"
    );
}

#[test]
fn readme_has_no_legacy_deploy_path_and_no_docusaurus_2() {
    let text = readme();
    for forbidden in ["npm run deploy", "USE_SSH", "gh-pages", "Docusaurus 2", "Docusaurus v2"] {
        assert!(!text.contains(forbidden), "README must not contain `{forbidden}`");
    }
}
