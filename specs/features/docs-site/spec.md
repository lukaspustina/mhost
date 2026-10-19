# Spec: docs-site

Status: Ready for Implementation
Created: 2026-10-19

## Goal

The sources of the mhost documentation site live in `website/` of this repository, build with the
newest stable Docusaurus 3.x on React 19 and Node 24, and are deployed to GitHub Pages only by
`.github/workflows/website.yml` (release tags `v*` and manual dispatch). `https://mhost.pustina.de`
serves that build, the repository `lukaspustina/mhost.pustina.de` is archived with a pointer to
`website/`, and DNS, the crate package and the release workflow are unchanged.

## Non-goals

- Reviewing or correcting the page content against the CLI 0.12.1 — a later block.
- Versioned documentation per release.
- Carrying over the git history of `lukaspustina/mhost.pustina.de`.
- Building the site in `just adlc-verify`.
- Any change to DNS (`terraform-pustina.de/ns-1/pustina.de.tf`).
- New screenshots or images.

## Context and constraints

- Source of the copy: local checkout `~/Documents/src/mhost.pustina.de`, `master` at `ccc96d5`, in
  sync with `origin/master`. Contents: `docs/` (`about.md`, `installation.md`,
  `usage_examples.md`, `attributions_images.md`, 409 lines), `src/css/custom.css`,
  `src/pages/{index.js,styles.module.css}`, `static/CNAME`, `static/img/*`, `sidebars.js`,
  `babel.config.js`, `docusaurus.config.js`, `package.json`, `package-lock.json`, `README.md`,
  `Makefile` (source: `ls` of the checkout).
- Old `package.json`: `@docusaurus/core` and `preset-classic` `^3.9.2`, `react`/`react-dom`
  `^18.3.1`, `engines.node >=18.0`; deploy via `Makefile` `USE_SSH=true npm run deploy`.
- Old `docusaurus.config.js`: `url: 'https://mhost.pustina.de'`, `projectName: 'mhost.pustina.de'`,
  `editUrl: 'https://github.com/lukaspustina/mhost.pustina.de/edit/master/'`,
  `onBrokenLinks: 'throw'`.
- `docs/` of this repository holds ADRs, `records.md`, `verify.sdd.md` — the site does not go there
  (intent).
- `Cargo.toml` `include` is a whitelist (`README.md`, licences, `CHANGELOG.md`, `**/*.rs`,
  `Cargo.toml`): `website/` stays out of the crate as long as it holds no `.rs` file.
- `.github/workflows/ci.yml` runs on push to `master` (tags `!v*`) and on pull requests to `master`;
  `.github/workflows/release.yml` runs on tags `v*`. No workflow touches Pages today.
- `adlc.toml` `[exceptions] no-ci`: the gate is `just adlc-verify` locally; the Pages workflow is a
  deploy, not the gate.
- `CLAUDE.md:12`: no real domains other than example.com in test data, docs or commits; recipes
  through `just` (`CLAUDE.md`, Build & Test). The copied pages keep their existing examples and new
  text follows the rule (`intent.md`, Constraints). The project's own domains are exempt (Decision
  log).
- The old site's Pages is switched off first so the custom domain can move (`intent.md`, Proposed
  outcome). Assumed from GitHub's Pages documentation, not verified in this sandbox: with
  `build_type: workflow` the custom domain is set in the Pages settings and a `CNAME` file in the
  artifact is not read, and a custom domain is bound to one repository at a time. `static/CNAME`
  is copied anyway (Requirement 1) and is harmless.
- `docs/about.md` sets `slug: /`, so it builds to `/docs/`; the four routes are `/docs/`,
  `/docs/installation/`, `/docs/usage_examples/`, `/docs/attributions_images/` (old checkout's
  `gh-pages` tree; live `/docs/about/` answers 404).
- Every push, Pages setting change and archive needs the operator's approval (intent).
- Live checks of the GitHub API and the npm registry were not possible from the authoring sandbox;
  the exact Docusaurus 3.x and React 19 versions are fixed at implementation time.

## Requirements

1. `website/` contains the copied `docs/`, `src/`, `static/`, `sidebars.js`, `babel.config.js` and
   `docusaurus.config.js` of `mhost.pustina.de` at `ccc96d5`, page content byte-identical; the
   old `Makefile` is not copied.
2. `website/package.json` pins exact versions (no `^`/`~`) of the newest stable Docusaurus 3.x
   packages and of `react`/`react-dom` 19, declares `engines.node` `>=24`, and drops the `deploy`
   script; `website/package-lock.json` is regenerated and committed.
3. `website/.nvmrc` contains `24`.
4. `website/docusaurus.config.js` sets `projectName: 'mhost'` and
   `editUrl: 'https://github.com/lukaspustina/mhost/edit/master/website/'`; `url` stays
   `https://mhost.pustina.de`.
5. `website/README.md` names Docusaurus 3, the `just site-*` recipes and the deploy workflow, and
   contains no manual deploy instruction (`npm run deploy`, `USE_SSH`, `gh-pages`).
6. `.gitignore` ignores `website/node_modules/`, `website/build/` and `website/.docusaurus/`.
7. The `justfile` gains `site-install` (`npm ci` in `website/`), `site-build` and `site-serve`;
   `adlc-verify` and every existing recipe stay unchanged.
8. `just site-install && just site-build` completes with exit 0 and no broken-link error.
9. `.github/workflows/website.yml` runs only on push of tags `v*` and on `workflow_dispatch`; it
   uses `actions/setup-node` with `node-version-file: website/.nvmrc`, runs `npm ci` and
   `npm run build` in `website/`, uploads `website/build` with `actions/upload-pages-artifact` and
   deploys with `actions/deploy-pages`, with `permissions` `contents: read`, `pages: write`,
   `id-token: write` and a `concurrency` group that does not cancel a running deploy.
10. `.github/workflows/ci.yml` ignores pushes and pull requests that change only `website/**`
    (`paths-ignore`); a change touching any other path still runs it, and its tag filter stays.
11. `release.yml` and `Cargo.toml` are unchanged; `cargo package --list --allow-dirty` lists no
    path under `website/`.
12. With approval, `lukaspustina/mhost.pustina.de` gets one README commit pointing to
    `https://github.com/lukaspustina/mhost/tree/master/website`, pushed to `master`.
13. With approval, Pages of `lukaspustina/mhost.pustina.de` is switched off before Pages of
    `lukaspustina/mhost` is set to `build_type: workflow` with custom domain `mhost.pustina.de` and
    HTTPS enforced.
14. After a `workflow_dispatch` run of `website.yml` on `master`, `https://mhost.pustina.de/` and
    `https://mhost.pustina.de/docs/installation/` return 200, and the docs page links its edit URL into
    `lukaspustina/mhost/edit/master/website/`.
15. With approval, and only after 14 holds, `lukaspustina/mhost.pustina.de` is archived.
16. The DNS record of `mhost.pustina.de` (CNAME `lukaspustina.github.io`) is not changed.

## Phases

## Phase 1 — Sources in website/

**Depends on:** none
**Requirements:** 1, 2, 3, 4, 5, 6, 7, 8, 11

Copy the site into `website/`, upgrade `package.json`/lockfile, pin Node, retarget the config, rewrite
the README, extend `.gitignore` and the `justfile`.

### Test Scenarios

GIVEN the copy WHEN `diff -r ~/Documents/src/mhost.pustina.de/docs website/docs` runs THEN it reports no difference.
GIVEN the copy WHEN `website/Makefile` is looked up THEN it does not exist.
GIVEN `website/package.json` WHEN its dependency versions are read THEN none starts with `^` or `~`, Docusaurus is 3.x and React is 19.x.
GIVEN `website/package.json` WHEN its scripts are read THEN there is no `deploy` script, and `build`, `start`, `serve` remain.
GIVEN `website/README.md` WHEN grepped for `npm run deploy|USE_SSH|gh-pages` THEN nothing matches.
GIVEN a clean checkout WHEN `just site-install && just site-build` runs THEN it exits 0 and `website/build/index.html` exists.
GIVEN the build WHEN `git status --porcelain` runs THEN nothing under `website/node_modules`, `website/build` or `website/.docusaurus` is listed.
GIVEN the justfile WHEN `just --show adlc-verify` runs THEN it equals the recipe before this block.
GIVEN the crate WHEN `cargo package --list --allow-dirty` runs THEN no path starts with `website/`.

## Phase 2 — Deploy workflow

**Depends on:** Phase 1
**Requirements:** 9, 10

Add `.github/workflows/website.yml`; add `paths-ignore: ['website/**']` to `ci.yml`'s push and
pull_request triggers.

### Test Scenarios

GIVEN `website.yml` WHEN its `on:` block is parsed THEN it holds exactly `push.tags: ['v*']` and `workflow_dispatch`, and no `branches` or `pull_request`.
GIVEN `website.yml` WHEN its steps are read THEN setup-node reads `website/.nvmrc` and the uploaded path is `website/build`.
GIVEN `website.yml` WHEN its `concurrency` is read THEN `cancel-in-progress` is `false`.
GIVEN `ci.yml` WHEN its push and pull_request triggers are parsed THEN both carry `paths-ignore: ['website/**']` and the push tag filter `!v*` is still present.
GIVEN a commit touching `website/docs/about.md` and `src/lib.rs` WHEN pushed to master THEN `ci.yml` runs (paths-ignore excludes only when every path matches).
GIVEN `release.yml` WHEN diffed against the merge base THEN it is unchanged.

## Phase 3 — Cutover

**Depends on:** Phase 2
**Requirements:** 12, 13, 14, 15, 16

Operator-approved steps against GitHub, in this order: README pointer in the old repository, old
Pages off, new Pages on (`build_type: workflow`, custom domain, HTTPS), `workflow_dispatch` of
`website.yml`, live check, archive. Requires Phases 1–2 merged to `master` and pushed.

### Test Scenarios

GIVEN the old repository WHEN `gh api repos/lukaspustina/mhost.pustina.de/readme` is read THEN its content links `lukaspustina/mhost/tree/master/website`.
GIVEN the cutover WHEN `gh api repos/lukaspustina/mhost.pustina.de/pages` runs THEN it answers 404.
GIVEN the cutover WHEN `gh api repos/lukaspustina/mhost/pages` runs THEN `build_type` is `workflow`, `cname` is `mhost.pustina.de` and `https_enforced` is `true`.
GIVEN a successful dispatch run WHEN `curl -sI https://mhost.pustina.de/` and `/docs/installation/` run THEN both return 200, and the docs page contains `lukaspustina/mhost/edit/master/website/`.
GIVEN the live check has not passed WHEN the archive step is reached THEN the repository is not archived.
GIVEN the live check passed WHEN `gh api repos/lukaspustina/mhost.pustina.de` runs THEN `archived` is `true`.
GIVEN the cutover WHEN `dig +short CNAME mhost.pustina.de` runs THEN it answers `lukaspustina.github.io.` as before.

## Decision log

- `website/` over `site/`: Docusaurus convention, unambiguous beside `docs/` (operator, 2026-10-19).
- Deploy on release tags `v*` over every push to master touching the site: the site matches the
  last release; doc fixes wait for the next release (operator, 2026-10-19).
- Tags plus `workflow_dispatch` over tags only: the cutover and emergency redeploys need no release
  (operator, 2026-10-19).
- Content review against 0.12.1 in a later block over in this block: this block is a move
  (operator, 2026-10-19).
- `paths-ignore: website/**` in `ci.yml` over leaving it unchanged: a site-only push starts no Rust
  jobs (operator, 2026-10-19).
- Node 24 over Node 22: Node 22 is maintenance-only until April 2027 (operator, 2026-10-19).
- Newest stable Docusaurus 3.x with React 19 over a 4.x major or keeping 3.9/React 18: current
  without an unknown migration (operator, 2026-10-19).
- Site build in own recipes outside `adlc-verify` over inside the gate: `npm ci` needs the network
  (operator, 2026-10-19).
- README pointer commit before archiving over description only: visitors of the old repository see
  where the sources went (operator, 2026-10-19).
- The project's own domains (`mhost.pustina.de`, `github.com/lukaspustina/*`) exempt from
  `CLAUDE.md:12` over rewriting them: they are configuration and identity, not example data; new
  example text still uses example.com (operator, 2026-10-19).
- `site-install`/`site-build`/`site-serve` over `website-*`: short, grouped in `just --list`, no
  clash with the existing `docs` recipe (operator, 2026-10-19).

## Open decisions

None.

## Out of scope

- DNS for `mhost.pustina.de`: `terraform-pustina.de/ns-1/pustina.de.tf`.
- The public-web consolidation as a whole (blocks other than E): `netray-ops/specs/handoff/pdt-public.md`.
- Content drift of the pages against the CLI: a later block in this repository.
- The `gh-pages` branch of the archived repository: stays as it is, read-only with the archive.
