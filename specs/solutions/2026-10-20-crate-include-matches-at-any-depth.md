---
class: check-passes-without-observing
repeat-of: none
---
# A guard on website/ passed while cargo package shipped 1128 files from it

**What failed.** Requirement 11 of `specs/features/docs-site/spec.md` was guarded by "no `.rs` or
`Cargo.toml` under `website/`", which held. `cargo package --list --allow-dirty` still listed
`website/README.md` and, after `npm ci`, 1127 READMEs, LICENSEs and CHANGELOGs from
`website/node_modules`: `Cargo.toml` `include` is read with gitignore semantics, so the unanchored
`"README.md"`, `"CHANGELOG.md"` and the licence entries match at any depth. The check observed the
tree, not the package.
**What worked.** Anchor every entry but `**/*.rs` at the crate root (`"/README.md"`, …), exclude the
repository-only tests (`"!/src/website_tests/*.rs"`), and compare `cargo package --list` with the
same list on `git archive master` (identical, 190 files).
**How to notice next time.** A new directory beside the crate holds a file named like an `include`
entry, or a `**` pattern, and nothing ran `cargo package --list`.
**Check to build.** `src/website_tests/repo.rs`: compare `cargo package --list` (or a walk that does
not skip `website/node_modules`) against the expected file set instead of looking only for `.rs`
and `Cargo.toml` under `website/`.
