# Corrections against the frozen 002 scout artifacts (dated 2026-09-29)

The frozen 002 files are not edited. Corrections live here.

## 1. The sequence has 15 rows, not 13

aacb-002-SCOUT-REPORT.md describes the harness sequence as a "13-step
scripted sequence". The SEQUENCE in the frozen aacb-002-harness.py contains
15 rows (verified by direct count of the frozen file): 4 delegate, 1 revoke,
1 restart, 1 replace_owner_key, and 8 attempt rows. The "8 checked steps"
claim in the report is correct. CONTRACT v0.3.0 freezes all 15 rows as
S1–S15.

## 2. Scoring shorthand clarified (no values changed)

The scout's "X/8" shorthand meant verdict+reason per step, but the report
never stated the conformance conjunction explicitly: a driver is CONFORMANT
only if all 4 ALLOW steps and all 4 DENY steps are correct. The reconciled
scoring in aacb-003/SCORING.md states this and requires the ALLOW-half and
DENY-half to be reported separately. The reconciled scores are numerically
identical to the scout's (registry 8/8, introspection 8/8, deny-everything
0/8, signature-only 4/8); what changed is definitional, not factual.
