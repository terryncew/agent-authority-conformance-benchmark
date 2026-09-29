# AACB-003 — Neutrality Audit: the adapter contract

Date: 2026-09-29. Workstream C of AUTHORITY-CONFORMANCE-003.

An adapter connects a candidate implementation to the benchmark's driver
protocol (`delegate` / `revoke` / `replace_owner_key` / `restart` /
`attempt`). The candidate's authorization behavior must be the candidate's
own. The adapter is a translator, not a co-implementer.

## What adapters may do

- Translate transport and serialization: wire format, API shape, calling
  convention, artifact encoding (e.g., JSON grant objects to macaroon
  caveats), and error mapping into the coarse reason vocabulary
  (ALLOW / REVOKED / STALE_OWNER / REPLAY).
- Persist and restore the candidate's own operational state so `restart()`
  is a genuine process-death simulation: key material, stores and
  registries the candidate itself maintains. The adapter may not invent
  state the candidate would not keep.
- Present the candidate's own authorization decision to the harness,
  unmodified in substance.

## What adapters must not do (forbidden, with examples)

1. Add a revocation check the candidate lacks. Example: an adapter that
   keeps its own revoked-token list for a bearer-token library and returns
   DENY on list membership. The DENY would come from the adapter, not the
   candidate.
2. Fabricate persistence across restart. Example: an adapter that re-seeds
   "revoked" entries from its own log instead of the candidate's durable
   store, making a restart look durable when the candidate would have
   resurrected the grant.
3. Invent supersession semantics. Example: an adapter that records "old
   owner key retired" and returns DENY / STALE_OWNER for old-key artifacts
   the candidate itself would still honor.
4. Implement consumption or replay state the candidate lacks. Example: an
   adapter-side used-nonce set producing DENY / REPLAY for a mechanism
   with no single-use primitive.
5. Weaken the candidate to manufacture passes. Example: mapping the
   candidate's refusal into ALLOW, or swallowing errors to match an
   expected reason string.
6. Precompute outcomes. The adapter must drive the candidate live on every
   step. No verdict may be decided from the frozen expectations file.

General rule: if a step's expected verdict cannot be produced by the
candidate's own code paths, as the candidate's maintainers would recognize
them, the step is UNSUPPORTED / UNTESTED — never passed, never
adapter-rescued.

## Required semantics (capability prerequisites)

A candidate is testable against the full sequence only if it natively
provides all of:

- P1 Delegation: mint a grant-like artifact binding issuer, holder,
  action, and single-use-ness.
- P2 Revocation: an owner-initiated revoke that changes the candidate's
  own authorization decision for that artifact, durably.
- P3 Restartable persistent state: process death loses only in-memory
  state; revocation and live grants survive via the candidate's store.
- P4 Owner-key rotation with the standing/history split: rotate the
  issuing key, retain the ability to verify old artifacts' signatures
  (history preserved), and treat old-key artifacts as non-current
  (standing lost). Both halves are required.
- P5 Consumption: a single-use artifact presented twice is refused the
  second time by the candidate's own state.
- P6 Continued delegation: after every change, fresh grants under current
  authority still authorize. (The useful-work rule: blocking everything
  fails.)

## Applicability limits

The suite cannot test systems that lack any prerequisite. Phrased as
capability prerequisites, not judgments:

- No durable revocation: pure bearer/offline-verified tokens with no
  standing oracle (self-contained JWTs validated by signature only,
  macaroons). Steps requiring REVOKED are UNSUPPORTED.
- No owner-key concept distinct from current signing-key validity, or no
  supersession semantics. STALE_OWNER steps are UNSUPPORTED.
- No consumable-artifact primitive. REPLAY steps are UNSUPPORTED.
- No restartable store (authorization state purely in-memory). Restart
  steps are UNSUPPORTED.
- Authorization decided at a layer the driver protocol cannot reach.

## Unsupported-capability rule

Unsupported capabilities are reported as UNSUPPORTED / UNTESTED, never
counted as passes. Per-step evidence shows them as skipped-not-passed.
A candidate that passes every runnable step but skips some receives a
qualified score (X of Y runnable passed, Z skipped), never a full pass.

## Observation for the harness worker (not this workstream's lane)

The 002 harness trusts the driver's `(verdict, reason)` strings. The 003
harness must observe effects, not trust strings, and needs a
skipped-not-passed channel so external candidates can report capability
gaps instead of failing. Stated here as a handoff note; the rework is the
harness worker's.
