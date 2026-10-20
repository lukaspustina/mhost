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
| C8 | R8: just site-install && just site-build exits 0 — npm ci needs the network and the gate runs offline; checked under Behavioural verification | test-unwritable | — |
| C9 | R11 (amended): release.yml unchanged; Cargo.toml include anchored; cargo package lists nothing under website/ | green | src/website_tests/repo.rs |
| C10 | S: docs/ of the copy equals the source's docs/ | green | src/website_tests/copy.rs |
| C11 | S: website/Makefile does not exist | green | src/website_tests/copy.rs |
| C12 | S: no dependency version starts with ^ or ~; Docusaurus 3.x, React 19.x | green | src/website_tests/package.rs |
| C13 | S: no deploy script; build, start, serve remain | green | src/website_tests/package.rs |
| C14 | S: README has no npm run deploy, USE_SSH, gh-pages | green | src/website_tests/readme.rs |
| C15 | S: clean checkout, site-install + site-build → exit 0, website/build/index.html exists — as C8 | test-unwritable | — |
| C16 | S: after a build, git status lists nothing under the ignored website dirs | green | src/website_tests/repo.rs |
| C17 | S: just --show adlc-verify equals the recipe before this block — a guard, true before the phase | already_implemented | src/website_tests/repo.rs |
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

## Phase 2 — Deploy workflow

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | R9: website.yml on v* tags and workflow_dispatch only; setup-node from website/.nvmrc, npm ci and build in website/, upload-pages-artifact of website/build, deploy-pages; permissions contents read, pages write, id-token write; non-cancelling concurrency | green | src/website_tests/workflows.rs |
| C2 | R10: ci.yml ignores pushes and pull requests that change only website/**; other paths still run it; tag filter stays | green | src/website_tests/workflows.rs |
| C3 | S: website.yml `on:` is exactly push.tags ['v*'] and workflow_dispatch; no branches, no pull_request | green | src/website_tests/workflows.rs |
| C4 | S: setup-node reads website/.nvmrc; uploaded path is website/build | green | src/website_tests/workflows.rs |
| C5 | S: website.yml concurrency has cancel-in-progress false | green | src/website_tests/workflows.rs |
| C6 | S: ci.yml push and pull_request both carry paths-ignore ['website/**']; push tag filter !v* still present | green | src/website_tests/workflows.rs |
| C7 | S: a commit touching website/ and src/ still runs ci.yml — asserted as paths-ignore holding only website/**, which GitHub applies only when every changed path matches | green | src/website_tests/workflows.rs |
| C8 | S: release.yml unchanged against the merge base — a guard, true before the phase | already_implemented | src/website_tests/workflows.rs |

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 | 1 | sonnet | 30489 | 21 |
| G2 | 1 | sonnet | 25714 | 13 |

The planner was not spawned: two groups, two files, no shared code. G1 picked action majors from memory, one behind each; the orchestrator raised them to the current tags read with `git ls-remote` (checkout v7, setup-node v7, configure-pages v6, upload-pages-artifact v5, deploy-pages v5).

### Review

| class | finding | outcome |
|---|---|---|
| AMENDMENT | Phase 3 never adds a `v*` tag rule to the `github-pages` environment; its default rule admits only the default branch, so `deploy` is rejected on every release tag; no Phase 3 scenario covers the tag path. affected_phase: 3, repaired_in_phase: no | halts the block with `amendment-forward` |
| DEFERRED | A `v*` tag pushed after Phases 1–2 reach master but before Phase 3 enables Pages fails at Configure Pages (Pages answers 404) | cutover ordering: Phase 3 runs before the next release |
| DEFERRED | `paths-ignore` lets a website-only push or PR skip CI, while CI's `cargo test --lib` compiles the `website_tests`; a website-only breakage surfaces on the next push touching `src/` | the local gate still runs them |
| NIT | With a path filter, a push that changes no files no longer starts CI | listed |

### Behavioural verification

skipped: a workflow runs only on GitHub; nothing here executes it (no `actionlint`, no `act`). The structure is asserted by `website_tests::workflows`, the action tags were read with `git ls-remote`, and the reviewer ran `npm ci --dry-run` offline against the lockfile.

## Phase 3 — Cutover

### Criteria

Every criterion is a live check against GitHub, HTTPS or DNS; the gate runs offline, so none is a test in the suite. Each is checked under Behavioural verification with its command and output.

| id | criterion | status | test file |
|---|---|---|---|
| C1 | R12: the old repository gets one README commit pointing to mhost/tree/master/website, pushed to master | test-unwritable | — |
| C2 | R13 (amended): old custom domain removed before new Pages on (build_type workflow, cname mhost.pustina.de, HTTPS enforced); github-pages gets a v* tag policy | test-unwritable | — |
| C3 | R14: after a workflow_dispatch run on master, / and /docs/installation/ return 200 and the docs page links mhost/edit/master/website/ | test-unwritable | — |
| C4 | R15: the old repository is archived only after R14 holds | test-unwritable | — |
| C5 | R16: the DNS CNAME of mhost.pustina.de is unchanged | test-unwritable | — |
| C6 | S: the old repository's README links lukaspustina/mhost/tree/master/website | test-unwritable | — |
| C7 | S (amended): GET repos/lukaspustina/mhost.pustina.de/pages has cname null | test-unwritable | — |
| C8 | S: GET repos/lukaspustina/mhost/pages has build_type workflow, cname mhost.pustina.de, https_enforced true | test-unwritable | — |
| C9 | S: github-pages deployment-branch-policies list v* of type tag | test-unwritable | — |
| C10 | S: curl / and /docs/installation/ return 200; the page contains lukaspustina/mhost/edit/master/website/ | test-unwritable | — |
| C11 | S: before the live check passes the repository is not archived; after it, archived is true | test-unwritable | — |
| C12 | S: dig +short CNAME mhost.pustina.de answers lukaspustina.github.io. | test-unwritable | — |

Before the cutover, the operator had origin/master fast-forwarded to 290a106 (Phases 1–2), since `workflow_dispatch` and the `github-pages` rule act on the default branch only. The pre-push gate required a recorded review: the block review of 7424160..290a106 ran first (0/0/5, `review.md`). The gate also refuses a dirty tree, and `review.md` stays uncommitted for finish, so it was set aside for the receipt and restored.

Amendment during the phase: `DELETE repos/lukaspustina/mhost.pustina.de/pages` answered 422 "Deactivating GitHub pages for this repository is not allowed." The operator chose to remove the custom domain instead; Requirement 13 and its scenario were amended. The old build stays reachable under lukaspustina.github.io/mhost.pustina.de in the archived repository.

### Runs

No coder: every step is a GitHub setting, push or check, run by the orchestrator behind its own approval.

### Review

skipped: no production file changed in this phase; the block review covers 7424160..290a106.

### Behavioural verification

```
$ git push origin 290a106:refs/heads/master
   7424160..290a106  290a106 -> master
$ (old repo) git commit README.md && git push origin master
   ccc96d5..eebbbb6  master -> master            # README links lukaspustina/mhost/tree/master/website
$ gh api -X DELETE repos/lukaspustina/mhost.pustina.de/pages
   422 Deactivating GitHub pages for this repository is not allowed.
$ gh api -X PUT repos/lukaspustina/mhost.pustina.de/pages  (cname null)
   {"build_type":"legacy","cname":null,"https_enforced":true}
$ gh api -X POST repos/lukaspustina/mhost/pages -f build_type=workflow; PUT cname=mhost.pustina.de
   {"build_type":"workflow","cname":"mhost.pustina.de","https_enforced":true,"https_certificate":{"state":"approved"}}
$ gh api repos/lukaspustina/mhost/environments/github-pages/deployment-branch-policies
   before: [{"name":"master","type":"branch"}]
   after POST name=v* type=tag: [{"name":"master","type":"branch"},{"name":"v*","type":"tag"}]
$ gh workflow run website.yml --ref master   -> run 39372917264 on 290a106: Build site ✓, Deploy to GitHub Pages ✓
$ curl -s -o /dev/null -w '%{http_code}' https://mhost.pustina.de{/,/docs/,/docs/installation/,/blog}
   200 200 200 404
$ curl -s https://mhost.pustina.de/docs/installation/ | grep -o 'lukaspustina/mhost/edit/master/website/docs/installation.md'
   lukaspustina/mhost/edit/master/website/docs/installation.md
$ gh api repos/lukaspustina/mhost.pustina.de --jq .archived   -> false; PATCH archived=true -> true
$ dig +short CNAME mhost.pustina.de @1.1.1.1   (before and after)
   lukaspustina.github.io.
```

The tag path (a `v*` push deploying) is configured but not yet exercised; the next release is its first run.
