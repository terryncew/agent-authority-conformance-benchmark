# AACB v0.3.0 self-conformance run: openline-wallet + ReferenceGate

Date: 2026-09-30. One frozen run. Internally operated.
Harness: the frozen `aacb-003-harness.py` (v0.3.0), unmodified.
Adapter: `adapter-openline.py` in this directory (the only new code).
Evidence: `steps.jsonl` + `summary.json`, written by the harness itself.

## Score

- ALLOW-half: 4/4 (S2, S8, S12, S14)
- DENY-half: 2/4 (S4, S6 pass; S10, S15 fail)
- Conformance: NOT CONFORMANT
- Restart canary: PASS (revocation survived process death via the wallet's
  own disk store; new Driver instance reloaded persisted state)
- G4 effect invariant: FAIL (2 effects across S14+S15, expected 1)

## What the candidate does natively

Delegation (wallet.grant: signed mandate binding principal, subject, scopes),
owner-initiated revocation (wallet.revoke, root-signed, durable), restart
durability (state is the wallet's own disk store), continued delegation under
the current owner, and fail-closed refusal of an unauthorized owner-key swap
(ValueError; no successor installed; existing grants unaffected).

## The two gaps (both fail on the merits, neither adapter-rescued)

- S10 (expected DENY/STALE_OWNER, got ALLOW/ALLOW/+1): the candidate has no
  owner-key rotation or supersession primitive. Epoch certificates are
  sequence-1, root keys are never rotated, and the gate's pin_principal
  raises PINNED_ROOT_CONFLICT on a root change. The adapter's closest native
  operation is owner succession by new principal (fresh wallet); old-owner
  mandates keep their standing. There is no STALE_OWNER concept.
- S15 (expected DENY/REPLAY, got ALLOW/ALLOW/+1): mandates carry no
  single-use flag. Only gate challenges are one-use, and those are
  per-presentation, not per-mandate. A faithful driver issues a fresh
  challenge per attempt (what a real worker does), so the second
  presentation is ALLOWED by the candidate's own code.

## Disclosed translation

AACB grants are per-action; wallet mandates are per-subject with a scope
set, and the candidate natively refuses a second active mandate for one
subject (SUBJECT_ALREADY_HAS_ACTIVE_MANDATE; narrow() enforces
NARROW_SCOPE_EXPANDED). The driver namespaces subjects per grant
(worker-W.1, worker-W.2, ...) bound to the same worker keypair. No
unrequested owner operation, no altered authorization decision; every
attempt runs the candidate's real signature, scope, revocation, and expiry
checks. See the adapter docstring.

## Non-claims

This run tests the delegation -> revocation -> restart -> replay ->
owner-key-replacement lifecycle only. It does not certify the candidate
against attackers, concurrent writers, or any threat model outside the
frozen vectors. One run, one adapter, published as observed.
