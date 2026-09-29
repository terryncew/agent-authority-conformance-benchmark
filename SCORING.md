# AACB scoring — reconciled (003)

## Definitions

**Per-step correctness** (asserted steps only): a step is CORRECT iff the
driver's verdict matches the expected verdict AND its reason matches the
expected reason AND its observed effect delta matches the expected delta.
Any mismatch is a per-step FAIL.

**Conformance** is a conjunction of the two halves:

- ALLOW-half: all 4 ALLOW steps correct.
- DENY-half: all 4 DENY steps correct.
- CONFORMANT iff ALLOW-half is 4/4 AND DENY-half is 4/4. Otherwise NOT
  CONFORMANT.

A deny-everything driver matches the four DENY verdicts but gets 0/4 on the
ALLOW half and fails reason checks on the DENY half: verdict-match without
reason-match is not per-step correctness, and either half at 0 fails the
conjunction. Blocking everything fails conformance. This is the mechanism
the scout's "X/8" shorthand did not state explicitly.

## Reporting rule

Reports must show the ALLOW-half and DENY-half splits and the conformance
verdict. A single "n/8" figure may appear only as a subsidiary number next to
the half-split, never alone.

## Reconciled scores for the 002 scout runs

Under this scoring, using the frozen 002 expectations and the results
recorded in aacb-002-RESULTS.md:

| driver | verdicts matched (of 8) | full-correct (of 8) | ALLOW-half (of 4) | DENY-half (of 4) | conformance |
|---|---|---|---|---|---|
| aacb-002-impl-registry.py | 8 | 8 | 4 | 4 | CONFORMANT |
| aacb-002-impl-introspection.py | 8 | 8 | 4 | 4 | CONFORMANT |
| deny-everything control | 4 | 0 | 0 | 0 | NOT CONFORMANT |
| signature-only control | 4 | 4 | 4 | 0 | NOT CONFORMANT |

Scoring values are unchanged from the scout: the old shorthand already meant
verdict+reason per step. What changed is the explicit definition.

## Where the old shorthand was misleading

The scout's "4/8" for the signature-only control reads as halfway-there, but
it failed every DENY row — zero conformance on the revocation half. Under a
verdict-only reading, the deny-everything control would also score "4/8":
two drivers with opposite failure modes wearing the same number. The old
shorthand collapsed both halves into one dimension and never stated the
conjunction that makes deny-all fail. The reconciled form separates the
halves and states the conjunction.
