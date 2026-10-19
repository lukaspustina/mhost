//! `website/package.json`, `website/package-lock.json` and `website/.nvmrc`: exact pins, Docusaurus 3,
//! React 19, Node 24, no `deploy` script.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn website(file: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("website")
        .join(file)
}

fn package_json() -> Value {
    let path = website("package.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("package.json is valid JSON")
}

/// All (name, version) pairs from dependencies and devDependencies.
fn all_deps(pkg: &Value) -> Vec<(String, String)> {
    ["dependencies", "devDependencies"]
        .iter()
        .filter_map(|section| pkg.get(*section).and_then(Value::as_object))
        .flat_map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("version is a string").to_string()))
        })
        .collect()
}

#[test]
fn dependency_versions_are_exact_pins() {
    let deps = all_deps(&package_json());
    assert!(!deps.is_empty(), "no dependencies declared");
    let ranged: Vec<_> = deps
        .iter()
        .filter(|(_, v)| v.starts_with('^') || v.starts_with('~'))
        .collect();
    assert!(ranged.is_empty(), "ranged versions: {ranged:?}");
}

#[test]
fn docusaurus_packages_are_3x_and_react_is_19x() {
    let deps = all_deps(&package_json());
    let docusaurus: Vec<_> = deps.iter().filter(|(n, _)| n.starts_with("@docusaurus/")).collect();
    assert!(!docusaurus.is_empty(), "no @docusaurus/* packages declared");
    for (name, version) in &docusaurus {
        assert!(version.starts_with("3."), "{name} is {version}, expected 3.x");
    }
    for react in ["react", "react-dom"] {
        let version = deps
            .iter()
            .find(|(n, _)| n == react)
            .unwrap_or_else(|| panic!("{react} not declared"));
        assert!(version.1.starts_with("19."), "{react} is {}, expected 19.x", version.1);
    }
}

#[test]
fn engines_node_is_at_least_24() {
    let pkg = package_json();
    assert_eq!(pkg["engines"]["node"], ">=24");
}

#[test]
fn scripts_drop_deploy_and_keep_build_start_serve() {
    let pkg = package_json();
    let scripts = pkg["scripts"].as_object().expect("scripts is an object");
    assert!(!scripts.contains_key("deploy"), "deploy script still present");
    for name in ["build", "start", "serve"] {
        assert!(scripts.contains_key(name), "script {name} missing");
    }
}

#[test]
fn package_lock_exists() {
    let path = website("package-lock.json");
    assert!(path.is_file(), "{} missing", path.display());
}

#[test]
fn nvmrc_pins_node_24() {
    let path = website(".nvmrc");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(text.trim(), "24");
}
