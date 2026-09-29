# AACB-003 — test vectors (frozen)

Source: the SEQUENCE in aacb-002-harness.py, row-for-row. Each row carries a
role:

- SETUP: arranges state, no assertion.
- STIMULUS: invokes driver behavior, no assertion.
- ASSERTION: checked against EXPECTED-003.md and the scoring rule.

| id | role | op | inputs |
|---|---|---|---|
| S1 | SETUP | delegate | owner=owner-A, worker=worker-W, action=read-sensor, single_use=false → grant G1 |
| S2 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G1 |
| S3 | STIMULUS | revoke | owner=owner-A, grant=G1 |
| S4 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G1 |
| S5 | STIMULUS | restart | (no args) — driver drops in-memory state, serves from persisted state |
| S6 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G1 |
| S7 | SETUP | delegate | owner=owner-A, worker=worker-W, action=read-sensor, single_use=false → grant G2 |
| S8 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G2 |
| S9 | STIMULUS | replace_owner_key | old_owner=owner-A, new_owner=owner-B |
| S10 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G2 |
| S11 | SETUP | delegate | owner=owner-B, worker=worker-W, action=read-sensor, single_use=false → grant G3 |
| S12 | ASSERTION | attempt | worker=worker-W, action=read-sensor, grant=G3 |
| S13 | SETUP | delegate | owner=owner-B, worker=worker-W, action=spend-10, single_use=true → grant G4 |
| S14 | ASSERTION | attempt | worker=worker-W, action=spend-10, grant=G4 |
| S15 | ASSERTION | attempt | worker=worker-W, action=spend-10, grant=G4 |

8 asserted steps (S2, S4, S6, S8, S10, S12, S14, S15): 4 ALLOW, 4 DENY.
7 non-asserted rows: 4 SETUP, 3 STIMULUS.

Note on counting: the scout report described this sequence as 13 rows. The
harness SEQUENCE contains 15 rows (count verified from the frozen file). See
CORRECTIONS.md. This contract freezes all 15.
