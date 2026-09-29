# AACB-003 — Bounded external integration attempt

Date: 2026-09-29. Workstream C of AUTHORITY-CONFORMANCE-003.
Bound: one candidate, ~1 hour of investigation. No contact, no outreach,
no publication, zero spending.

## Candidate

**pymacaroons 0.13.0** (PyPI; the Python port of Google's macaroon
construction). An existing non-OpenLine delegation/authorization system
developed outside this project. Chosen because it is the canonical
bearer-delegation mechanism and installs in minutes — the bounded choice.
Heavier candidates (django-oauth-toolkit as a full authorization server,
biscuit-auth revocation lists, Keycloak) would each cost a multi-hour
setup and were not attempted within the bound.

## Method

Thin adapter per the AACB-003 adapter contract (NEUTRALITY-AUDIT.md):
`/tmp/aacb3-ext/pymac_adapter.py` (scratch; not a release artifact).
Native mappings only:

- `delegate` → `Macaroon` with first-party caveats
  (`owner` / `worker` / `action` / `single_use` / `nonce`).
- `attempt` → `Verifier` with exact caveats; worker and action pinned to
  the request, owner pinned to a root key the receiver actually holds;
  issuer assertions with no verifier-side state satisfied from the
  artifact's own values.
- `replace_owner_key` → root-key rotation with old-key retention (history
  preserved). The mechanism has no supersession semantics.
- `restart` → key material persisted to the workdir; in-memory state
  dropped. Genuine process-death simulation.

Deliberately unimplemented — no native expression in the mechanism, and
adding them would violate the adapter contract:

- `revoke` is a strict no-op (no revocation list added).
- No single-use consumption state (no used-nonce set added).
- No owner-key supersession logic (old-key macaroons keep verifying).

Run against the CURRENT (002) harness only, as a fit assessment. The 002
harness has no UNSUPPORTED channel, so capability gaps appear as failures;
they are labeled correctly here.

Process note: the first run failed 0/8 on an adapter defect (the verifier
did not satisfy the artifact's own non-request caveats). Fixed; the final
fit result below is from the corrected adapter. The 0/8 run was discarded
as an adapter bug, not candidate evidence.

## Results (002 harness, 8 checked steps)

| Step | Expected | Actual | Reading |
|---|---|---|---|
| attempt G1 (baseline) | ALLOW / ALLOW | ALLOW / ALLOW | pass |
| attempt G1 after revoke | DENY / REVOKED | ALLOW / ALLOW | fail — no native revocation |
| attempt G1 after restart | DENY / REVOKED | ALLOW / ALLOW | fail — same |
| attempt G2 after restart | ALLOW / ALLOW | ALLOW / ALLOW | pass |
| attempt G2 under old owner key | DENY / STALE_OWNER | ALLOW / ALLOW | fail — no supersession semantics |
| attempt G3 under owner-B | ALLOW / ALLOW | ALLOW / ALLOW | pass |
| attempt G4 first use | ALLOW / ALLOW | ALLOW / ALLOW | pass |
| replay G4 second use | DENY / REPLAY | ALLOW / ALLOW | fail — no consumption primitive |

4/8. All four ALLOW steps pass; all four DENY steps fail as ALLOW/ALLOW.
The shape is identical to the scout's signature-only negative control
(4/8, failing exactly the four DENY rows).

## Outcome

The candidate does not fit the full lifecycle. It natively expresses the
delegation half and none of the standing-sensitive half. This is a
mechanism-level limitation, not an adapter defect: revocation,
consumption, and supersession have no expression in macaroons, and adding
them in the adapter is forbidden by the contract.

The result corroborates the scout's gap finding from the outside: the
canonical bearer-delegation mechanism passes useful work and fails every
row that requires current standing to be evaluated separately from
signature validity. That is exactly the composition the benchmark exists
to measure.

## Limitation, stated plainly

Within the bound, no off-the-shelf non-OpenLine system was found that
natively implements the full prerequisite set (P1–P6 in
NEUTRALITY-AUDIT.md). A fuller attempt would need a system with a native
standing oracle (revocation registry), durable restart, and
key-supersession semantics — i.e., essentially the architecture the
benchmark describes. That system was not found in the time available, and
was not built: building it would be authoring the candidate, not
integrating one.

## Labels

Internally operated. Fit assessment only — not validation of the 003
contract, which is still being frozen. Not independent implementation and
not external adoption.
