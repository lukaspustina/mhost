---
class: neighbour-artefact-left-inconsistent
repeat-of: none
---
# A new error mode in the dnssec walk left the renderer still printing the old verdict

**What failed.** Under `--no-tcp-fallback`, `RawError::Truncated` reached `walk_trust_chain`
(`src/app/mhost/modules/dnssec/chain.rs`). The first fix (e11f40d) added a Warning finding to the
level, and its tests covered only the new helpers. But `write_level`
(`src/app/mhost/modules/dnssec/mod.rs`) never printed `level.findings`, and it still ran
`classify_ds_binding` on the empty child key set, so the summary kept showing
"chain of trust is broken" in red. The same fix also missed two neighbours: a lame server's `Ok`
REFUSED next to a truncated answer, and child queries issued past the `--max-hops` cut. Closing it
took three review rounds.
**What worked.** e08445f: `DelegationLevel.dnskeys_unknown` (`#[serde(skip)]`) lets the renderer
skip the DS binding and print the truncation findings. A raw result now counts as usable only when
it is `Ok`, NOERROR and carries the queried type. Child zones are taken from `zones[..walk_len]`.
**How to notice next time.** A fix that changes what the walk *knows* has no test asserting on the
rendered summary, streamed or full.
