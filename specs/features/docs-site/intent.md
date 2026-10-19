# Intent: docs-site

Block E of the public-web consolidation decided on 2026-10-19 (handoff in
`netray-ops/specs/handoff/pdt-public.md`): the website mhost.pustina.de leaves its own repository
and lives beside the code it documents.

## Problem

The documentation site for mhost is a separate public repository, `lukaspustina/mhost.pustina.de`
(Docusaurus `^3.9.2`, React 18, `node >=18`, 14 commits, last 2026-03-11). It is built and deployed
by hand from a local checkout (`USE_SSH=true npm run deploy` into its `gh-pages` branch; Pages
`build_type: legacy`, CNAME `mhost.pustina.de` in `static/CNAME`). Its four pages (`about`,
`installation`, `usage_examples`, `attributions_images`, 409 lines) drift from the code because
nothing in mhost's release touches them, and its README still describes Docusaurus 2.

## Proposed outcome

- The site's sources live in this repository in their own directory (not `docs/`, which holds
  ADRs, `records.md` and `verify.sdd.md`), on current Docusaurus, React and an LTS Node pin.
- A GitHub Actions workflow builds and deploys it to GitHub Pages (`build_type: workflow`);
  no local deploy step remains.
- `https://mhost.pustina.de` serves the site from this repository; the DNS CNAME
  `lukaspustina.github.io` (NS1, `terraform-pustina.de/ns-1/pustina.de.tf`) stays unchanged.
- `lukaspustina/mhost.pustina.de` is archived; its Pages site is switched off first so the custom
  domain can move.

## Affected users and systems

Readers of mhost.pustina.de; this repository (new directory, new workflow, recipes in the
justfile); the repository `mhost.pustina.de` (archived); GitHub Pages settings of both
repositories. Not affected: the crate, the binaries, the release workflow, DNS.

## Constraints

- History: plain copy, the old repository is archived (precedent `pdt/specs/features/monorepo/`).
- Recipes through `just`, no Makefile; the site build must not enter `just adlc-verify` unless it
  stays offline and fast.
- This repository is public and its rules forbid real domains other than example.com in docs and
  test data: the copied pages keep their existing examples, new text follows the rule.
- `[exceptions] no-ci`: the Pages workflow is a deploy, not the gate.
- Every push, Pages setting change and archive needs the operator's approval.

## Open questions

- Directory name: `website/` or `site/`.
- Deploy trigger: every push to master that touches the site, or release tags only.
- Whether the content is reviewed against the current CLI (0.12.1) in this block or later.
