# Report: docs-site

## Phase 1 — Sources in website/

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | R1: website/ holds the copied docs/, src/, static/, sidebars.js, babel.config.js, docusaurus.config.js of ccc96d5, pages byte-identical; no Makefile | green | src/website_tests/copy.rs |
| C2 | R2: package.json pins exact Docusaurus 3.x and React 19, engines.node >=24, no deploy script; lockfile committed | green | src/website_tests/package.rs |
| C3 | R3: website/.nvmrc contains 24 | green | src/website_tests/package.rs |
| C4 | R4: config projectName mhost, editUrl into mhost/edit/master/website/, url unchanged | green | src/website_tests/config.rs |
| C5 | R5: website/README.md names Docusaurus 3, just site-* recipes and the deploy workflow; no manual deploy instruction | green | src/website_tests/readme.rs |
| C6 | R6: .gitignore ignores website/node_modules/, build/, .docusaurus/ | green | src/website_tests/repo.rs |
| C7 | R7: justfile has site-install, site-build, site-serve; adlc-verify unchanged | green | src/website_tests/repo.rs |
| C8 | R8: just site-install && just site-build exits 0 | test-unwritable (npm ci needs the network, the gate runs offline; checked under Behavioural verification) | — |
| C9 | R11 (amended): release.yml unchanged; Cargo.toml include anchored; cargo package lists nothing under website/ | green | src/website_tests/repo.rs |
| C10 | S: docs/ of the copy equals the source's docs/ | green | src/website_tests/copy.rs |
| C11 | S: website/Makefile does not exist | green | src/website_tests/copy.rs |
| C12 | S: no dependency version starts with ^ or ~; Docusaurus 3.x, React 19.x | green | src/website_tests/package.rs |
| C13 | S: no deploy script; build, start, serve remain | green | src/website_tests/package.rs |
| C14 | S: README has no npm run deploy, USE_SSH, gh-pages | green | src/website_tests/readme.rs |
| C15 | S: clean checkout, site-install + site-build → exit 0, website/build/index.html exists | test-unwritable (as C8) | — |
| C16 | S: after a build, git status lists nothing under the ignored website dirs | green | src/website_tests/repo.rs |
| C17 | S: just --show adlc-verify equals the recipe before this block | already_implemented (guard) | src/website_tests/repo.rs |
| C18 | S: cargo package --list has no path under website/ | green | src/website_tests/repo.rs |

Test layout: the checks are library tests under `src/website_tests/` (gated on `app-lib`), since `just adlc-verify` runs only `cargo test --lib` and `--doc`. One writer per test file rather than per criterion, so parallel writers never shared a file.

Amendment during the phase: `Cargo.toml` `include` is read with gitignore semantics, so the unanchored entries packaged `website/README.md` and, with a local `npm ci`, 1127 files from `website/node_modules`. The operator chose to anchor the entries; Requirement 11 and its guard test were amended (217b34a).

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 | 3 | sonnet | 28460 | 36 |
| G2 | 1 | sonnet | 30554 | 93 |
| G3–G5 | 1 | sonnet | 33267 | 23 |
| G6 (Cargo.toml anchoring, after amendment) | — | orchestrator | — | — |
| G7 | — | check only | — | — |

G2 pinned React 19.2.9; the registry's `latest` is 19.3.1, so the orchestrator re-pinned `react`/`react-dom` to 19.3.1.

Review fixes (second pass through 7, 58aaa55 tests): `!/src/website_tests/*.rs` in `Cargo.toml` `include`, `cfg(mhost_repo)` from `build.rs` when a `justfile` sits beside `Cargo.toml` (gates `mod website_tests`), `blog: false` in `website/docusaurus.config.js`. Requirements 4 and 11 amended in the spec.

### Review

| class | finding | outcome |
|---|---|---|
| BLOCKER | `src/website_tests/*.rs` entered the crate package via `**/*.rs`; the published crate's lib tests failed without `website/` | fixed: include exclusion + `cfg(mhost_repo)`; package list identical to master, packaged crate builds its tests |
| BLOCKER | Docusaurus 3.10.2 adds an empty `/blog` page and sitemap entry | fixed: `blog: false`, test `blog_plugin_is_disabled` |
| NIT | `build.rs` has no rerun trigger for the `justfile`, so `cfg(mhost_repo)` can stay stale after a build without it; a lone `rerun-if-changed=justfile` would break the default rerun the completions rely on | listed, not acted on |
| DEFERRED | `npm audit`: 45 findings (15 critical) in transitive build-time dependencies of Docusaurus 3.10.2 (braces, micromatch, serialize-javascript, tinypool); no fix without a Docusaurus release | listed |

### Behavioural verification

```
$ rm -rf website/node_modules && just site-install && just site-build
[SUCCESS] Generated static files in "build".          (exit 0)
$ ls website/build/index.html website/build/docs/index.html website/build/docs/installation/index.html
all three exist; no website/build/blog/
$ grep -o 'mhost/edit/master/website/docs/installation.md' website/build/docs/installation/index.html
mhost/edit/master/website/docs/installation.md
$ git status --porcelain -uall | grep -E 'node_modules|website/build|\.docusaurus'
(empty)
$ cargo package --list --allow-dirty  vs  the same on `git archive master`
package list identical to master
```

`just site-install` needs `npm_config_cache` pointed at a writable directory inside this sandbox (`~/.npm` holds root-owned files); outside it the recipe runs as written.
