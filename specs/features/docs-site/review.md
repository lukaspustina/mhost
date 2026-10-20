
## 74241607bde2b3819bdf0e8d73d50bfa2ff97936..290a1067e9384d33fffd09c7ca4c93ee5591d5ec

#### Reader

COUNTS blockers=0 majors=0 minors=4
LENSES Engineering, Security, Testing
MINOR | src/website_tests/repo.rs:126 | The guard for "the crate package gains nothing from website/" skips `node_modules`, which is the directory the include-anchoring amendment exists to protect, so it passes while `cargo package` ships files from there. | In a scratch copy of END with `website/node_modules/x/src/a.rs` added, `cargo package --list --allow-dirty` lists `website/node_modules/x/src/a.rs` because the unanchored `**/*.rs` matches it, yet `website_holds_nothing_the_crate_package_would_include` reports ok. Today's lockfile installs no `.rs` file, so the package list is currently identical to the merge base.
MINOR | src/website_tests/package.rs:39 | `dependency_versions_are_exact_pins` refuses only the `^` and `~` prefixes, so ranges that are not exact pins still pass. | With `"clsx": "*"` and `"@docusaurus/core": "3.x"` in website/package.json, all 26 website tests pass. `npm ci` also accepts both against the committed lock.
MINOR | src/website_tests/workflows.rs:115 | "npm steps must run in website/" is satisfied by any one `working-directory: website` line anywhere in the file, so the check never ties that line to the `npm ci` step. | With `working-directory: website` removed from the "Install dependencies" step only, all 26 tests pass, but on GitHub that step runs `npm ci` at the repo root, which has no package.json, so the deploy fails.
MINOR | src/website_tests/copy.rs:105 | `docs_holds_exactly_the_four_pages` reads the working tree's directory listing, dotfiles included, so a file that is globally gitignored and can never be committed fails the gate while the commit is fine. | `touch website/docs/.DS_Store` (Finder does this on macOS; `~/.gitignore_global:2` ignores it) makes `just test-offline` fail with left `[".DS_Store", "about.md", ...]`.

```quote src/website_tests/repo.rs:126
    let skipped = ["node_modules", "build", ".docusaurus"];
```

```quote src/website_tests/package.rs:39
        .filter(|(_, v)| v.starts_with('^') || v.starts_with('~'))
```

```quote src/website_tests/workflows.rs:115
        .any(|t| t.trim_start_matches("- ") == "working-directory: website")
```

```quote src/website_tests/copy.rs:105
    let mut found: Vec<String> = fs::read_dir(website().join("docs"))
```

Checked and found sound: crate package list at END equals the merge base with and without `website/node_modules`; the negation takes effect; the packaged crate builds its lib tests without the justfile; all 26 website tests, fmt and clippy pass; `website/` byte-identical to ccc96d5 apart from the intended changes; lockfile consistent with integrity hashes; site routes are `/`, `/docs/`, `/docs/installation/`, `/docs/usage_examples/`, `/docs/attributions_images/`, no `/blog`; every action tag and input exists.

#### Spec reader

COUNTS blockers=0 majors=0 minors=1
REQUIREMENTS met=11 partial=0 missed=0 contradicted=0
MINOR | .github/workflows/website.yml:41 | The build job runs an extra step, `actions/configure-pages@v6`, which Requirement 9 does not list among the steps. It does nothing the deploy needs, but it makes the build fail whenever Pages is not enabled on the repository. | Requirement 9 names five steps (setup-node, `npm ci`, `npm run build`, upload-pages-artifact, deploy-pages). Case: a `v*` tag pushed after Phases 1-2 reach master but before the Phase 3 cutover fails at "Configure Pages" (Pages answers 404), and the upload and deploy steps never run. report.md records this as DEFERRED.

```quote .github/workflows/website.yml:39
      - name: Configure Pages
        uses: actions/configure-pages@v6
```

```quote specs/features/docs-site/spec.md:81
9. `.github/workflows/website.yml` runs only on push of tags `v*` and on `workflow_dispatch`; it
   uses `actions/setup-node` with `node-version-file: website/.nvmrc`, runs `npm ci` and
   `npm run build` in `website/`, uploads `website/build` with `actions/upload-pages-artifact` and
   deploys with `actions/deploy-pages`, with `permissions` `contents: read`, `pages: write`,
```

Traced R1–R11 at END: copy identical, config diff limited to projectName/editUrl/blog, exact pins and engines, recipes added only, offline build succeeds without `/blog`, package lists identical, workflows match R9/R10, release.yml outside the range.

### Refuted

none: no BLOCKER or MAJOR was reported, so no refuter ran.

### Calibration

none: the refuter answered no finding.

### Summary

Before and after refutation: reader 0/0/4, spec reader 0/0/1 (`REQUIREMENTS met=11 partial=0 missed=0 contradicted=0`); total 0 blockers, 0 majors, 5 minors. verified 0, held 0. Roll call: skipped, `adlc.toml` declares no principles.

## 290a1067e9384d33fffd09c7ca4c93ee5591d5ec..7381f26a0c49292e09d7439954554ea7f1737db8

#### Reader

COUNTS blockers=0 majors=2 minors=0
LENSES Engineering, Testing
MAJOR | specs/features/docs-site/report.md:132 | The report says the old build "stays reachable" under lukaspustina.github.io/mhost.pustina.de, but the copy that the amendment leaves live is broken: the URL answers 200 and nothing on the page loads or links correctly. | Fetched on 2026-10-20: `https://lukaspustina.github.io/mhost.pustina.de/` and `/docs/installation/` both answer 200. The served HTML was built with `baseUrl: '/'` (`website/docusaurus.config.js:6`), so it references `/assets/css/styles.b23c02a4.css`, `/assets/js/main.c3831c09.js` and links such as `/docs/installation`. Those resolve against `https://lukaspustina.github.io/`, and each answers 404 there. The page renders unstyled under Docusaurus' "Current configured baseUrl = /" error banner. The README pushed to the archived repository (eebbbb6, before the 422) also still says "This repository is archived and no longer deployed", which is false now that its Pages stays on.
MAJOR | specs/features/docs-site/spec.md:153 | The amendment changed Requirement 13 and its scenario but left the Phase 3 step list and the Context saying the old Pages is switched off, which is the step GitHub refuses. | Following Phase 3 "in this order" means `gh api -X DELETE repos/lukaspustina/mhost.pustina.de/pages`, which answered 422 "Deactivating GitHub pages for this repository is not allowed." (report.md:149-150). The amended Requirement 13 (spec.md:97-98) instead requires `cname: null` with Pages left on. spec.md:50 has the same stale statement.

```quote specs/features/docs-site/report.md:132
Amendment during the phase: `DELETE repos/lukaspustina/mhost.pustina.de/pages` answered 422 "Deactivating GitHub pages for this repository is not allowed." The operator chose to remove the custom domain instead; Requirement 13 and its scenario were amended. The old build stays reachable under lukaspustina.github.io/mhost.pustina.de in the archived repository.
```

```quote website/docusaurus.config.js:6
  baseUrl: '/',
```

```quote specs/features/docs-site/spec.md:153
Pages off, new Pages on (`build_type: workflow`, custom domain, HTTPS), `workflow_dispatch` of
```

```quote specs/features/docs-site/spec.md:50
- The old site's Pages is switched off first so the custom domain can move (`intent.md`, Proposed
```

```quote specs/features/docs-site/report.md:149
$ gh api -X DELETE repos/lukaspustina/mhost.pustina.de/pages
```

```quote specs/features/docs-site/spec.md:97
13. With approval, the custom domain is removed from the Pages of `lukaspustina/mhost.pustina.de`
```

Checked and sound: old repository archived; https://mhost.pustina.de/docs/installation/ answers 200 with the mhost edit link; eebbbb6 sits on ccc96d5 and links mhost/tree/master/website; the 0/0/5 block-review count matches review.md; `test-unwritable` is a closed status. Not verified: the Pages API state (404 unauthenticated).

#### Spec reader

COUNTS blockers=0 majors=0 minors=1
REQUIREMENTS met=5 partial=0 missed=0 contradicted=0
LENSES requirements 12-16 (Phase 3 Cutover), against the report's record and live state read without changes
MINOR | specs/features/docs-site/report.md:132 | The README commit in the old repository says it is "no longer deployed", but its legacy Pages still serves the old build. No requirement asks for that claim and it is false. | R12 asks only for a pointer. `curl https://lukaspustina.github.io/mhost.pustina.de/docs/installation/` returns 200, and the page links `github.com/lukaspustina/mhost.pustina.de/edit/master/docs/installation.md`. The report says so itself.

```quote specs/features/docs-site/report.md:132
Amendment during the phase: `DELETE repos/lukaspustina/mhost.pustina.de/pages` answered 422 "Deactivating GitHub pages for this repository is not allowed." The operator chose to remove the custom domain instead; Requirement 13 and its scenario were amended. The old build stays reachable under lukaspustina.github.io/mhost.pustina.de in the archived repository.
```

```quote specs/features/docs-site/spec.md:95
12. With approval, `lukaspustina/mhost.pustina.de` gets one README commit pointing to
```

Traced: R12 met (live README links mhost/tree/master/website; eebbbb6 has one parent and changes only README.md); R13 met as amended (github-pages policies master/branch and v*/tag; http 301 to https; Pages endpoints read from report.md); R14 met (run 39372917264 workflow_dispatch on master at 290a106, success; /, /docs/, /docs/installation/ 200, /blog 404; edit link into mhost/website); R15 met (archived true, updated after the run finished); R16 met (CNAME lukaspustina.github.io.). The original spec-reader anchor for the README line pointed into the old repository (`lukaspustina/mhost.pustina.de:README.md:6`), outside this tree; it is re-anchored on report.md, which records the same fact.

### Refuted

none: the refuter confirmed both majors.

### Calibration

| finding | refuter answer | confidence | outcome | command |
|---|---|---|---|---|
| report.md:132 legacy copy "stays reachable" but broken; old README says "no longer deployed" | CONFIRMED | 8 | held | `curl https://lukaspustina.github.io/mhost.pustina.de/` → 200; its `/assets/css/...` on lukaspustina.github.io → 404 |
| spec.md:153 and spec.md:50 still say the old Pages is switched off | CONFIRMED | 9 | held | `sed -n '50p;153p' specs/features/docs-site/spec.md` |

### Summary

Before and after refutation: reader 0/2/0, spec reader 0/0/1 (`REQUIREMENTS met=5 partial=0 missed=0 contradicted=0`); total 0 blockers, 2 majors, 1 minor. verified 2, held 2. Roll call: skipped, `adlc.toml` declares no principles.
