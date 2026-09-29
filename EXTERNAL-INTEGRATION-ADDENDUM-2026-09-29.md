# Addendum 2026-09-29 — reframing of EXTERNAL-INTEGRATION.md

Status: DOCUMENTATION ADDENDUM, outside the frozen v0.3.0 pin.
EXTERNAL-INTEGRATION.md (sha256 c240aa54…, recorded in RELEASE.md) is NOT
modified. This addendum corrects the framing of the pymacaroons exercise
and supersedes any sentence in EXTERNAL-INTEGRATION.md that reads as
external corroboration — including "The result corroborates the scout's gap
finding from the outside" and any equivalent claim. Those sentences are
withdrawn.

## What the pymacaroons exercise was

An INTERNALLY OPERATED test of external code (pymacaroons 0.13.0), run by
the same internally operated workers that authored the suite, using the
same harness, on the same machine. It is a fit assessment of one library
against the benchmark's prerequisite set. It is not independent
implementation, not external adoption, and not corroboration of the
benchmark's gap finding from outside the project. No authors were
contacted; no outreach was performed.

## (a) What pymacaroons 0.13.0 supplies natively

- HMAC-chained bearer tokens ("macaroons") with first-party caveats:
  construction (`Macaroon` with location / identifier / key) and exact-
  caveat verification (`Verifier`). This is attenuation of delegated
  authority via caveats, not standing.
- First-party caveats can carry owner, worker, action, and single_use
  flags inside the token; the verifier checks them cryptographically.
- No standing oracle: revocation lists, consumption registries, key
  supersession, and replay state are not part of the mechanism.

## (b) What the thin adapter supplies (and does NOT supply)

Supplies, per the AACB-003 adapter contract:

- `delegate` → a `Macaroon` with first-party caveats for
  owner / worker / action / single_use / nonce.
- `attempt` → a `Verifier` with exact caveats; worker and action pinned to
  the request, owner pinned to a root key the receiver actually holds;
  issuer assertions with no verifier-side state satisfied from the
  artifact's own values.
- `replace_owner_key` → root-key rotation with old-key retention (history
  preserved; the mechanism has no supersession semantics).
- `restart` → key material persisted to the workdir; in-memory state
  dropped. Genuine process-death simulation.

Does NOT supply (deliberately unimplemented — no native expression in the
mechanism, and adding them would violate the adapter contract):

- No revocation: `revoke()` is a strict no-op. No revocation list was
  added by the adapter.
- No single-use consumption state: no used-nonce set was added.
- No owner-key supersession: old-key macaroons keep verifying; the
  adapter did not retire them.

The adapter added NO authorization behavior the candidate lacks. All
authorization decisions in the exercise were the library's own.

## (c) Prerequisite support (P1–P6, per NEUTRALITY-AUDIT.md)

| prerequisite | pymacaroons 0.13.0 |
|---|---|
| P1 delegation | SUPPORTED natively (caveat-bearing macaroons) |
| P2 revocation | UNSUPPORTED (bearer token; no standing oracle) |
| P3 restartable persistent state | PARTIAL: key material persisted by the adapter; there is no candidate-side authorization store to survive process death. Revocation-sensitive steps are UNSUPPORTED regardless, because P2 is. |
| P4 owner-key rotation with standing/history split | HISTORY HALF ONLY: rotation with old-key retention works (old artifacts still verify = history preserved); supersession (old-key artifacts treated as non-current = standing lost) UNSUPPORTED |
| P5 consumption | UNSUPPORTED (no single-use consumption primitive) |
| P6 continued delegation | SUPPORTED (fresh grants under current authority still authorize) |

## Fit result, restated

4/8 on the 002 harness: all four ALLOW steps pass; all four DENY steps
fail as ALLOW/ALLOW — the signature-only negative-control shape. This is
a mechanism-level limitation (P2, P5, and the P4 standing half have no
expression in macaroons), not an adapter defect. Steps requiring REVOKED,
STALE_OWNER, or REPLAY are UNSUPPORTED by this candidate under the
applicability limits, and were reported as fit-assessment failures only
because the 002 harness had no UNSUPPORTED channel; they are not scored
evidence for or against the 003 contract.

## What this does not establish

- It does not establish that no other system fits. Within the ~1-hour
  bound, one candidate was tried; heavier systems (full authorization
  servers, biscuit-auth revocation lists, Keycloak) were not attempted.
- It does not constitute external validation of the benchmark. It is an
  internal exercise that happened to run third-party code.

Label: internally operated. Dated 2026-09-29.
