# Agent Authority Conformance Benchmark (AACB) — release candidate

Central question: when permissions change, does the system still let the
right actions happen and stop the wrong ones?

The suite drives any implementation through the same 15-step sequence —
delegation → revocation → restart → owner-key replacement → single-use
replay — and checks every asserted step against pre-declared expected
outcomes. Contract version: **v0.3.0**, frozen 2026-09-29T19:09:13Z
(see FREEZE.md) before any implementation ran against it.

## The sequence (S1–S15)

SETUP / STIMULUS rows arrange state; only ASSERTION rows are scored.

- S1 SETUP: owner-A delegates grant G1 (read-sensor) to worker-W
- S2 ASSERTION: attempt G1 → **ALLOW**
- S3 STIMULUS: revoke G1
- S4 ASSERTION: attempt G1 → **DENY / REVOKED**
- S5 STIMULUS: restart (harness drops the driver object; a fresh instance
  must reload persisted state)
- S6 ASSERTION: attempt G1 → **DENY / REVOKED** (nothing resurrected)
- S7 SETUP: owner-A delegates grant G2
- S8 ASSERTION: attempt G2 → **ALLOW** (useful work continues)
- S9 STIMULUS: replace owner key (owner-A → owner-B)
- S10 ASSERTION: attempt G2 → **DENY / STALE_OWNER**
- S11 SETUP: owner-B delegates grant G3
- S12 ASSERTION: attempt G3 → **ALLOW**
- S13 SETUP: owner-B delegates single-use grant G4 (spend-10)
- S14 ASSERTION: attempt G4 → **ALLOW**
- S15 ASSERTION: attempt G4 again → **DENY / REPLAY** (no duplicate effect)

## How to run

```bash
./reproduce.sh
```

One command: verifies the four frozen hashes against FREEZE.md, runs all
9 drivers (2 conformant + 7 fault variants incl. the false-reporting
driver), and prints the reconciled conformance table with an assertion
against the expected outcomes. System Python 3, stdlib only — no pip, no
network. Evidence lands in `evidence/<driver>/{steps.jsonl,summary.json}`.

## How to read the scoring

**Per-step correctness** (asserted steps only): verdict AND reason AND
observed effect delta must all match. The harness observes effects via the
driver's read-only `effects()` log — ALLOW steps must produce exactly one
new effect receipt (+1), DENY steps none (+0). It never trusts the verdict
string alone.

**Conformance** is a conjunction: all 4 ALLOW steps correct AND all 4 DENY
steps correct → CONFORMANT; otherwise NOT CONFORMANT. A deny-everything
driver matches the 4 DENY verdicts but scores 0/4 on the ALLOW half (and
fails reason checks), so blocking everything fails conformance. Reports
always show the two halves separately; a bare "n/8" may only appear as a
subsidiary figure.

## The adapter contract (brief)

Adapters translate transport and serialization only. They must never
implement missing authorization behavior: no adapter-side revocation
lists, no fabricated restart persistence, no invented supersession or
consumption state, no weakened candidates, no precomputed outcomes. If a
step's verdict cannot come from the candidate's own code paths, the step
is UNSUPPORTED / UNTESTED — never passed, never adapter-rescued.
Full contract: NEUTRALITY-AUDIT.md.

## Applicability limits

The suite can test only implementations that natively provide all of:
P1 delegation, P2 durable owner-initiated revocation, P3 restartable
persistent state, P4 owner-key rotation with the standing/history split
(old-key artifacts stay verifiable as history but lose standing),
P5 single-use consumption, P6 continued delegation after every change
(useful work keeps working). Systems lacking a prerequisite get those
steps reported as unsupported, never as passes. The suite makes no
timing, sandbox-safety, or universal-security claims.

## Scoped novelty

We found no equivalent in this comparison: none of the suites inspected
provides the composed delegation → revocation → restart → replay →
owner-key-replacement lifecycle as one portable, implementation-agnostic
sequence with frozen ALLOW and DENY expectations. This statement is
scoped to the suites and versions named in COMPARISON-MATRIX.md. It is
not a claim that no equivalent exists anywhere.

## Provenance

All runs internally operated. The two conformant drivers and all fault
variants are internally authored — testing-only, never independence or
adoption. The pymacaroons adapter under `fit-assessment/` is
fit-assessment-only evidence from the bounded external-integration
attempt (it scored 4/8, like the signature-only control); it is not part
of the tested suite. No contact, no outreach, no publication, zero
spending.
