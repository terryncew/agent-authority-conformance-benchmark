# Agent Authority Conformance Benchmark — v0.3.0 release notes

**Version:** 0.3.0. **Status:** experimental suite for public review.
**Contract frozen:** 2026-09-29T19:09:13Z, before any implementation ran
against it (see FREEZE.md). **Released:** 2026-09-29.

## Central question

When permissions change, does the system still let the right actions
happen and stop the wrong ones?

The suite drives any implementation through the same 15-step lifecycle
sequence — delegation → revocation → restart → replay → owner-key
replacement — and checks every asserted step against pre-declared
expected outcomes (4 expected ALLOW, 4 expected DENY). Only ASSERTION
rows are scored.

## Observation boundary (read this first)

The harness reads the adapter-exposed effects log **separately from**
the returned decisions: it snapshots the driver's read-only
`effects()` log before and after each attempt and computes the delta
itself, then checks verdict, semantic reason, and observed effect-delta
all match expected. It never trusts the ALLOW/DENY string alone.

This tests **consistency within the supplied apparatus** — that the
candidate's reported decisions and its exposed effects agree with the
pre-declared expectations. It does **not** establish tamper-resistant
observation of arbitrary external effects: the effects under test are
the ones the adapter exposes through the harness interface, and the
adapter contract forbids adapters from implementing authorization
behavior the candidate lacks — but the harness cannot see effects the
candidate does not expose. For details see NEUTRALITY-AUDIT.md and
AUDIT-2026-09-29.md §2.

## How to read the scoring

Three agreements are reported **separately**, then full conformance:

- **Verdict agreement:** returned ALLOW/DENY vs expected.
- **Semantic-reason agreement:** returned reason vs expected, from the
  closed vocabulary `ALLOW / REVOKED / STALE_OWNER / REPLAY` (generic
  authorization terms; no OpenLine-specific wording anywhere in the
  harness or drivers).
- **Effect agreement:** observed effect-delta vs expected (ALLOW steps
  must produce exactly one harmless effect receipt, +1; DENY steps must
  produce none, +0).
- **Full conformance:** the conjunction — all 4 ALLOW steps correct AND
  all 4 DENY steps correct → CONFORMANT; otherwise NOT CONFORMANT.

A single "n/8" figure may appear only beside the half-split, never
alone.

### The deny-all explanation

A deny-everything driver matches the four DENY verdicts but scores
**0/4 + 0/4, NOT CONFORMANT**: its returned reason (`"DENY"`) is
outside the closed reason vocabulary so no DENY row is per-step
correct, and the ALLOW half is 0/4 because the required harmless effect
never appears — either half at 0 fails the conjunction. Blocking
everything fails conformance by design: a system that never permits
useful work is not a conformant authority system. Full eight-row table
in AUDIT-2026-09-29.md §1.

## Prominent caveats

- **Eight checked lifecycle assertions.** The suite checks 8 assertion
  steps of one composed lifecycle; it is not a full authorization
  suite.
- **Internally operated reference implementations and review.** The two
  conformant drivers, all seven fault variants, the harness, and the
  review passes were built and run by internally operated workers.
  Nothing here is independent external validation.
- **Bounded external-library integration.** One bounded attempt was
  made against an existing external library (pymacaroons 0.13.0); it
  was an internally operated test of external code, scored 4/8 in the
  signature-only shape, and is fit-assessment-only evidence — see
  EXTERNAL-INTEGRATION-ADDENDUM-2026-09-29.md.
- **No independent external validation, no production certification, no
  universal security claim.** The suite makes no timing,
  sandbox-safety, or universal-security claims. It is an experimental
  review instrument, not a certification.

## Corrections included (addenda only — the frozen candidate is unmodified)

1. The harness sequence has **15 rows (S1–S15), not 13** as the 002
   scout report described; "8 checked steps" stands. (CORRECTIONS.md)
2. Scoring prose note: SCORING.md says a deny-everything driver "fails
   reason checks on the DENY half" — true of that control, not entailed
   by the rule. Wording observation, not a semantic change.
   (AUDIT-2026-09-29.md §1)
3. Pymacaroons reframing: "corroborating the gap from outside" is
   withdrawn; the exercise was an internally operated test of external
   code. (EXTERNAL-INTEGRATION-ADDENDUM-2026-09-29.md)

## Provenance

All runs internally operated. The conformant drivers and all fault
variants are internally authored — testing-only, never independence or
adoption. The comparison matrix scopes the novelty statement to the
suites and versions actually inspected: "we found no equivalent in this
comparison," not "none exists." No contact, no outreach, zero spending.

## Package contents

Everything is covered by `MANIFEST.sha256` (full SHA256, release
level). Frozen contract (hashes in FREEZE.md): CONTRACT.md, VECTORS.md,
EXPECTED-003.md, SCORING.md, CORRECTIONS.md. Harness and 9 drivers
(2 conformant + 7 fault variants, stdlib-only, zero OpenLine code).
Neutrality audit, comparison matrix, external-integration record and
its dated reframing addendum, fit-assessment adapter (fit-assessment
only). Release audit (this release), release notes, reproduction
script, deterministic per-driver evidence.

## Reproduction

```bash
./reproduce.sh
```

System Python 3, standard library only — no pip, no network. Step 1
verifies the four frozen contract hashes against FREEZE.md; step 2 runs
all 9 drivers; step 3 prints the reconciled conformance table and
asserts every row against the expected outcomes in run-results.md.
A separate uncoached internal review ran this from a clean shell:
PASSED, exit 0. Label: internally operated.

## License

Apache-2.0 (see LICENSE).
