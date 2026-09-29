# AACB-003 — workstream B run record (harness rework)

Date: 2026-09-29. All runs labeled "internally operated". No implementation
ran against the frozen contract before it was read and hash-verified
(CONTRACT 3012f5b8…, VECTORS 3f9d2aed…, EXPECTED 3cf36fc2…, SCORING
5d9f6a00… — all match FREEZE.md).

## New files (all under ~/workspace/canon-scout/aacb-003/)

- aacb-003-harness.py — effect-observing harness. Per ASSERTION step:
  snapshot effects() before, attempt, diff after. ALLOW correct iff
  verdict==ALLOW AND reason==ALLOW AND delta==+1; DENY correct iff
  verdict==DENY AND reason==expected AND delta==+0. Restart (S5): calls
  driver.restart(), drops the driver object (weakref confirms
  garbage-collection), constructs a fresh Driver(workdir), requires the
  ordered effects() tuple to be equal before/after (recorded as
  restart_canary). Unauthorized-key-swap probe runs after S15 as a
  harness-level informational check only — excluded from conformance,
  because the frozen contract defers it to a future vector and defines no
  extension mechanism.
- aacb-003-impl-registry.py — conformant re-implementation of the 002
  registry design + effects(). Internally operated. Stdlib only.
- aacb-003-impl-introspection.py — conformant re-implementation of the 002
  token+oracle design + effects(). Internally operated. Stdlib only.
- aacb-003-impl-faulty.py — one codebase, AACB_FAULT selects: false_report,
  revocation_not_honored, resurrection_after_restart,
  replay_duplicates_effect, stale_owner_accepted, deny_everything,
  signature_only. Testing only.

## Evidence

aacb-003/evidence/<driver>/steps.jsonl (per-row: expected vs actual
verdict/reason/delta) and summary.json (halves, conformance, restart
canary, G4 invariant, probe).

## Results

| driver | ALLOW | DENY | conformance | failed rows |
|---|---|---|---|---|
| registry | 4/4 | 4/4 | CONFORMANT | — |
| introspection | 4/4 | 4/4 | CONFORMANT | — |
| false_report | 0/4 | 0/4 | NOT CONFORMANT | S2 S4 S6 S8 S10 S12 S14 S15 (all verdict/effect divergence) |
| revocation_not_honored | 4/4 | 2/4 | NOT CONFORMANT | S4 S6 |
| resurrection_after_restart | 4/4 | 3/4 | NOT CONFORMANT | S6 |
| replay_duplicates_effect | 4/4 | 3/4 | NOT CONFORMANT | S15 |
| stale_owner_accepted | 4/4 | 3/4 | NOT CONFORMANT | S10 |
| deny_everything | 0/4 | 0/4 | NOT CONFORMANT | all 8 |
| signature_only | 4/4 | 0/4 | NOT CONFORMANT | S4 S6 S10 S15 |

Restart canary passed for all 9 runs (old instance GC'd, effects tuple
equal). G4 invariant (exactly one effect across S14+S15) held for all
except replay_duplicates_effect, deny_everything, signature_only.
Unauthorized-key-swap probe passed for conformant drivers, false_report,
revocation_not_honored, resurrection_after_restart, replay_duplicates_effect;
failed (informationally) for stale_owner_accepted, deny_everything,
signature_only — each for the reason its fault predicts.

Caveat: the G4 invariant passed numerically for false_report (delta 0 on
S14, delta 1 on S15) — the invariant is necessary, not sufficient; the
per-step deltas are what catch the false reporter.
