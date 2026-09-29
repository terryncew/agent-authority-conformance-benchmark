# AACB-003 — frozen expected outcomes

For each asserted step: expected verdict, expected reason, expected
observable effect. Effect delta is the change in the driver's `effects()`
read-only log across the step: ALLOW steps produce exactly one new effect
receipt (+1); DENY steps produce none (+0). The harness worker implements
the observation mechanics.

| step | expected verdict | expected reason | expected effect delta |
|---|---|---|---|
| S2 | ALLOW | ALLOW | +1 |
| S4 | DENY | REVOKED | +0 |
| S6 | DENY | REVOKED | +0 |
| S8 | ALLOW | ALLOW | +1 |
| S10 | DENY | STALE_OWNER | +0 |
| S12 | ALLOW | ALLOW | +1 |
| S14 | ALLOW | ALLOW | +1 |
| S15 | DENY | REPLAY | +0 |

Reasons are closed-vocabulary: ALLOW, REVOKED, STALE_OWNER, REPLAY. On DENY
the reason must name the standing defect that caused the refusal; on ALLOW
the reason is ALLOW.

Identical for every implementation under test: the expectations are
behavioral, not architectural.
