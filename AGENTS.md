# Working in mhost

<!-- adlc:begin -->
## Working under adlc

This repository is gated: a change counts as verified when `adlc gate` says so, from git state
and a receipt alone. Four verbs keep a work block inside that gate.

1. **Verify before you push.** `adlc verify` runs the contract (the `adlc-verify` recipe) and
   writes the receipt the gate reads. A push without a receipt for the current tree is refused.
2. **Commit failing tests first.** Record the tests of a work block while they still fail, with the
   trailer `ADLC-Baseline: <sha of the previous HEAD>`. From that commit on they are protected.
3. **Explain a deleted or changed test.** A protected test that is removed, renamed or weakened
   needs the trailer `ADLC-Test-Change: <path> -- <reason>` in the commit that changes it, or in a
   later commit of the same branch. A skip marker is refused whatever the reason.
4. **Record the independent review.** After a reviewer with no model of the change has read the
   range, append the result with `adlc record review ...`; finishing needs a review with no blockers.

A feature's documents live in `specs/features/<name>/`: `intent.md` (optional), `spec.md`, `plan.p<N>.md` (one per phase), and
what its work leaves, `report.md` and `review.md`.

A branch carries one feature with all its phases, and `adlc next` reports `complete` only
after the last phase is built, reviewed and finished.

A fresh checkout runs `just adlc-setup` first: it installs the pinned tools the contract calls.

Two commands answer where a work block stands: `adlc explain <term>` defines any word the tool
prints, and `adlc next` names the due step (spec, implement, verify, review, finish), which the skill
`/adlc-process:cycle` runs until a decision halts it; `adlc feature finish` lands a `feature/<name>` branch.

The product's requirements live in `specs/prd.md`: `/adlc-process:discover` writes and updates it, run by
hand and never named by `adlc next`; `/adlc-process:outcome` judges a row whose measuring window has
closed: you call it when `adlc next` or `adlc status` prints an `outcome due` line.

Every command exits 0 verified, 1 refuted, 2 could not check. A 2 is never turned into a 0.
<!-- adlc:end -->
