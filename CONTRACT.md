# Agent Authority Conformance Benchmark — behavioral contract

Version: v0.3.0. Frozen before any implementation runs against it.

Central question: when permissions change, does the system still let the
right actions happen and stop the wrong ones?

## 1. Driver protocol

The harness knows nothing about implementation architecture. A driver
implements:

- `Driver(workdir)` — constructor. The driver persists durable state under
  `workdir`; `workdir` survives `restart()`.
- `delegate(owner, worker, action, single_use) -> str` — issues a grant;
  returns an opaque grant token. Carried over from 002, unchanged.
- `revoke(owner, grant_token) -> None` — withdraws the grant's standing.
  Unchanged.
- `replace_owner_key(old_owner, new_owner) -> None` — supersedes the owner's
  key. Unchanged.
- `restart() -> None` — drops all in-memory state; on return the driver must
  serve every subsequent call from persisted state. Unchanged.
- `attempt(worker, action, grant_token) -> (verdict, reason)` — asks whether
  this exact action is allowed now. `verdict` in {ALLOW, DENY}; `reason` in
  {ALLOW, REVOKED, STALE_OWNER, REPLAY}. Unchanged.
- `effects() -> tuple` — NEW in v0.3.0. Read-only, ordered list of opaque
  effect receipts: one receipt per action the driver actually executed after
  returning ALLOW. The harness diffs its length across each ASSERTION step
  to observe effects instead of trusting verdict strings. No other new
  affordances.

## 2. Required semantics (sharpened from 002)

- R1 signature != standing: artifact validity (signature, format) never
  implies current standing. A valid artifact that is revoked, or chained to
  a superseded owner key, MUST be DENY with the reason naming the standing
  defect (REVOKED, STALE_OWNER).
- R2 revocation sticks: after revoke, attempts are DENY / REVOKED.
- R3 restart durability: restart resurrects nothing revoked and loses
  nothing live. REVOKED stays REVOKED; live grants stay ALLOW.
- R4 replay: a consumed single-use artifact is DENY / REPLAY.
- R5 owner-key replacement: artifacts chained to the old key are DENY /
  STALE_OWNER; the new key delegates normally.
- R6 useful work: freshly-issued valid grants are ALLOW after every change.
  A driver that denies everything fails the ALLOW rows.

Unauthorized owner-key transitions are not stimulus-tested in v0.3.0;
candidate for a future vector.

## 3. Test vectors

VECTORS.md: the 15-row sequence (S1–S15), each row labeled SETUP, STIMULUS,
or ASSERTION. 8 asserted steps: 4 ALLOW, 4 DENY.

## 4. Expected outcomes

EXPECTED-003.md: per asserted step, expected verdict, expected reason, and
expected observable effect delta (+1 for ALLOW, +0 for DENY).

## 5. Scoring

SCORING.md governs. Per-step correctness = verdict AND reason AND effect
delta all match. Overall conformance = all 4 ALLOW steps correct AND all 4
DENY steps correct. Binary: CONFORMANT / NOT CONFORMANT. Blocking
everything fails conformance.

## 6. What this contract does not claim

No timing bounds. No sandbox-safety claims. No universal-security claims.
The sequence tests the delegation→revocation→restart→replay→owner-key-
replacement lifecycle only; it does not certify an implementation against
attackers, concurrent writers, or threat models outside the vectors.

## 7. Version history

- v0.2.0 (2026-09-29, scout): 8 checked expectations, verdict+reason,
  (verdict, reason) protocol, frozen in aacb-002-FREEZE.md.
- v0.3.0 (2026-09-29): reconciled scoring (per-step correctness vs
  conformance conjunction, halves reported separately); every vector row
  labeled SETUP/STIMULUS/ASSERTION; `effects()` read-only observation
  affordance added; expected outcomes extended with effect deltas. No
  vector changed semantics; no new asserted steps.
