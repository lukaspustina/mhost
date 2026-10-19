//! The site's sources are the old site repo's, carried over unchanged (old repo at commit ccc96d5).
//! Fingerprints are (byte length, 64-bit FNV-1a) of each file as it was there.

use std::fs;
use std::path::{Path, PathBuf};

fn website() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("website")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

const DOC_PAGES: [&str; 4] = [
    "about.md",
    "attributions_images.md",
    "installation.md",
    "usage_examples.md",
];

const IDENTICAL: &[(&str, usize, u64)] = &[
    ("babel.config.js", 89, 0x0f1d6763d600f4dd),
    ("docs/about.md", 5116, 0x34e8908d58b61dd0),
    ("docs/attributions_images.md", 1420, 0xfb99841f2a87c6b7),
    ("docs/installation.md", 929, 0xb8eea64b2d2e4cdf),
    ("docs/usage_examples.md", 10269, 0x673e3dd07af2c383),
    ("sidebars.js", 264, 0xee9d9317e14db13c),
    ("src/css/custom.css", 3976, 0x301a774bf46f5647),
    ("src/pages/index.js", 5101, 0x5b6bbca938448f21),
    ("src/pages/styles.module.css", 3962, 0x2ef6836b2c18c22d),
    ("static/.nojekyll", 0, 0xcbf29ce484222325),
    ("static/CNAME", 17, 0xb9f2c9547c98cabb),
    ("static/img/api.svg", 3104, 0x463c7ef2e381f1da),
    ("static/img/api_blue.svg", 3104, 0x822bfee860e8f2ab),
    ("static/img/check-github.png", 984550, 0x577b4f0aea3c86c6),
    ("static/img/classic_modern.svg", 661, 0x7a72b678fc5eab7d),
    ("static/img/classic_modern_blue.svg", 661, 0x0b4d10f33f1f0caa),
    (
        "static/img/default-lookup-all-protocols-github.png",
        308436,
        0x198dabb341f2d7e7,
    ),
    ("static/img/default-lookup-github.png", 244596, 0x879323bc404204af),
    (
        "static/img/default-lookup-predefined-servers-github.png",
        285626,
        0xcd60b18812f6586f,
    ),
    (
        "static/img/default-lookup-servers-list-github.png",
        991792,
        0x36eb28b6506ca419,
    ),
    ("static/img/discover-as-github.png", 1169280, 0x35710c7e2a68da6e),
    ("static/img/discover-github.png", 325027, 0x786826f0f7fc3860),
    ("static/img/discover.svg", 4227, 0x6315bc43c92d11d0),
    ("static/img/discover_blue.svg", 4227, 0x56d1dad09e80d8eb),
    ("static/img/fast_reliable.svg", 5472, 0x1520f3134b623a25),
    ("static/img/fast_reliable_blue.svg", 5472, 0xa272c3d1ccb2bfb8),
    ("static/img/favicon.ico", 3626, 0xe2d1f33bdae44ad7),
    ("static/img/human_machine_friendly.svg", 1915, 0x06ee2a4c80a51889),
    ("static/img/human_machine_friendly_blue.svg", 1915, 0xc2f0fe161f15c622),
    ("static/img/index_example.png", 110477, 0x8cddaac442d511d5),
    ("static/img/lint.svg", 2157, 0x15c77c2d81b34e75),
    ("static/img/lint_blue.svg", 2157, 0x0ed4c7a179bef58b),
    ("static/img/logo.svg", 3162, 0x01bc1a0197dbc707),
    ("static/img/logo_blue.svg", 3162, 0x4b2d2aca299aba4a),
    (
        "static/img/multi-lookup-all-records-github.png",
        993294,
        0xe31563f04b5f8659,
    ),
];

#[test]
fn copied_files_are_byte_identical_to_the_old_site() {
    let mut wrong = Vec::new();
    for (rel, len, hash) in IDENTICAL {
        match fs::read(website().join(rel)) {
            Ok(bytes) if bytes.len() == *len && fnv1a64(&bytes) == *hash => {}
            Ok(bytes) => wrong.push(format!("{rel}: differs ({} bytes)", bytes.len())),
            Err(e) => wrong.push(format!("{rel}: {e}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "files not carried over unchanged:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn docusaurus_config_is_carried_over() {
    assert!(website().join("docusaurus.config.js").is_file());
}

#[test]
fn docs_holds_exactly_the_four_pages() {
    let mut found: Vec<String> = fs::read_dir(website().join("docs"))
        .expect("website/docs must exist")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, DOC_PAGES);
}

#[test]
fn website_has_no_makefile() {
    assert!(website().is_dir(), "website/ must exist");
    assert!(!website().join("Makefile").exists());
}
