# AACB-003 release candidate — pinned file inventory

Directory: `~/workspace/canon-scout/aacb-003/`
Contract v0.3.0, frozen 2026-09-29T19:09:13Z. Reproduction verified
2026-09-29: `./reproduce.sh` → frozen hashes OK, all 9 drivers match
expected outcomes, exit 0. All runs internally operated. System Python 3,
stdlib only; no pip, no network.

Frozen contract files (hashes also recorded in FREEZE.md; verify with
`./reproduce.sh` step 1/3):

| file | sha256 |
|---|---|
| ./CONTRACT.md | 3012f5b8eb5f5d97310a78a92b8b99758d07c8fae4e641f3c89aee5f955be8a3 |
| ./VECTORS.md | 3f9d2aedafda95414588a32960ad35b71dde0a97c3966bdee901911db2ee5576 |
| ./EXPECTED-003.md | 3cf36fc22779f96c4b1f8a4e4684c1a60c58e046b12391f7180ec17714b0cfcb |
| ./SCORING.md | 5d9f6a005f72862cc9bbad9fcd61852b234fa61beb0cf6f015aa693dd315b147 |
| ./FREEZE.md | 5c1cdaadbf4c3dfe44dd02dd00fce378dd4fcd1a79f94148d87aa1792e89b3c6 |
| ./CORRECTIONS.md | 275592b43ef9ee94af9c431669df31b7e654100130c4d369375bdb6dcb8957a4 |

Audit / comparison / integration record:

| file | sha256 |
|---|---|
| ./NEUTRALITY-AUDIT.md | a630359f1072f75d4090d2a90e0e8aa792d1a52ae25b64dcf8f8dbe1ef10c8e5 |
| ./COMPARISON-MATRIX.md | 46339909ae20b193a207cb333ac958769f24d2210de12afa09fc11e9abec45cb |
| ./EXTERNAL-INTEGRATION.md | c240aa547abadc6a25cf023c8f33c5a7294c5a25886e3527031f4a2c14c2a395 |

Harness and drivers (internally operated, testing-only, zero OpenLine code):

| file | sha256 |
|---|---|
| ./aacb-003-harness.py | 76ca72c14054bf7153ab6a807255a161530087231c8c741ad83386ac96bbee80 |
| ./aacb-003-impl-registry.py | 640a0b5757ee6f69ab6fa17a72d917920aab150137d97f32e5f615bb51721ac1 |
| ./aacb-003-impl-introspection.py | 92c2223523c492893285c0858ef4d5992be3d445f89e7fd037f589a581665c64 |
| ./aacb-003-impl-faulty.py | da1d108dacde72fc5174931af2a2000a56b7d9b236106b091d98ca17203f86e1 |

Release mechanics:

| file | sha256 |
|---|---|
| ./reproduce.sh | 93ae66e4d3bb907b3768e21d8d40fa78fb8eaab4d146c29f12c7d2c28f5f38b5 |
| ./README.md | ee7528a32e3f09cfe86b8d95f5f969ad0d09b435a045cd7291809a80f0bf5f2b |
| ./run-results.md | 23c9520fa32e8eb55a42d1ab2a5b7a633b634bcdffbd19c351e9f617b006e6c9 |

External fit assessment (fit-assessment-only; not part of the tested suite):

| file | sha256 |
|---|---|
| ./fit-assessment/pymac_adapter.fit-assessment-only.py | 176b87acec35ee3d7fe759c2ba6528b93587934ff050d73f48fd8c48a34f6b04 |

Per-step evidence (regenerated deterministically by `./reproduce.sh`;
timestamps in summary.json vary by run, verdicts do not):

| file | sha256 |
|---|---|
| ./evidence/registry/steps.jsonl | 43fa42e44aa31e97cbf28ccea67518c2d395d964f35548b109e8b95befeb071a |
| ./evidence/registry/summary.json | c9d209dcea1a3e7abf06fc9650ded99492c3d7dae69bceaf698a5b1be9d558eb |
| ./evidence/introspection/steps.jsonl | 43fa42e44aa31e97cbf28ccea67518c2d395d964f35548b109e8b95befeb071a |
| ./evidence/introspection/summary.json | f3e4be104ddab1396574741ad552b78d47d185f904988f046a21432cb15661e |
| ./evidence/fault-false_report/steps.jsonl | f45c5da5c56f80e64427bee4aab5f9a64a41483d7858c96f35fe6a3cddd04089 |
| ./evidence/fault-false_report/summary.json | 9fffc1ef4b86d6cf683611eae9d36a2267eb77e71529cc10efd1fbaf428ff4f3 |
| ./evidence/fault-revocation_not_honored/steps.jsonl | a529f0f22b55f2f80f012ebfd5296cc53ea9349744181cc0b31260dd63b343f4 |
| ./evidence/fault-revocation_not_honored/summary.json | 6b3f1585b2d2d730b8f90edb215ebb4ccf3370e4f97272120f0b46cde4142fcf |
| ./evidence/fault-resurrection_after_restart/steps.jsonl | e3cadca251112a2f30c761e5e775ba8f19d10fdc138ecedd738db17d01b9639 |
| ./evidence/fault-resurrection_after_restart/summary.json | 091b6698ddd8b1f488bbe085b591cbd5ef01d22295d11dfc5172cd9c7b22658e |
| ./evidence/fault-replay_duplicates_effect/steps.jsonl | 21e579f8e7288ffe1f039c4f3a9bf0489913432e6f79f402abe84ad67a9e5a76 |
| ./evidence/fault-replay_duplicates_effect/summary.json | 5e024c7adc097db50e40a5ff98e07c2c820d3a4ffdb68cf836b4bfdd8f7638b1 |
| ./evidence/fault-stale_owner_accepted/steps.jsonl | 534a0c0cab398f14c9ccb14f3e5bacc44d33a10ca698fc8b1669ae9b9695333f |
| ./evidence/fault-stale_owner_accepted/summary.json | b70d9dedb2717ceb7950e6938cc18821450e54559b4220597d7669dd992d5d95 |
| ./evidence/fault-deny_everything/steps.jsonl | f325078b027f9127a541fd9651e1995121c07852784e100bc6535df71697c9f1 |
| ./evidence/fault-deny_everything/summary.json | 84ff02d984f20caa91674d8e50dc6f876679362e6fd29aa8b03993c07e150e4e |
| ./evidence/fault-signature_only/steps.jsonl | 44ca0be3ae4e01ca63a0b9e72e5cb99833c950d6ffef5cc02f3e4026eaf7caf9 |
| ./evidence/fault-signature_only/summary.json | 03fc1c01055f7ff1732a734ea5edc4fee79ae2e8151da59b541ac74bbe9ee28b |

Excluded from the pin: `__pycache__/` (regenerated at run time).

Notes:
- Frozen contract files are DO-NOT-MODIFY: CONTRACT.md, VECTORS.md,
  EXPECTED-003.md, SCORING.md, FREEZE.md, CORRECTIONS.md.
- No aacb-002-* files are included; the 002 scout is superseded.
- The unauthorized-key-swap probe in the evidence summaries is
  informational only, excluded from the frozen conformance verdict.
