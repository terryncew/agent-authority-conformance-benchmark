# AACB-003 — Comparison matrix

Date: 2026-09-29. Workstream C of AUTHORITY-CONFORMANCE-003.
Inspected artifacts are named with exact refs. "Re-verified" = checked
against the live source on 2026-09-29. No timing, sandbox-safety, or
universal-security claims are made here.

## OpenLine's own suites

Inspected in `~/workspace/openline-receipt-gate`, main @
`31070c80ad254284227ce04263138ad52cc04dc9` unless noted.

| Suite / version | Covers | Does NOT cover | Redundancy verdict |
|---|---|---|---|
| receiver-rollback 001: `tests/test_receiver_rollback_001.py` (main; branch `research/receiver-rollback-001` @ `b05fded67042428e41f2b95648a79694ddbefae7`, merged PR #90) — T1–T10, M1–M6, subprocess restart, adv1–adv3 | revoke→restart→refuse; mandate revoke→restart; fresh-successor admit; stale-head refusal; revoked capability stays revoked after reopen; replay of superseded bytes refused; forked sibling refused; concurrent admits exactly-one-wins | The composed lifecycle in one portable sequence; frozen ALLOW expectations alongside the DENYs (no useful-work rule); owner-key replacement with history preservation; anything runnable outside OpenLine's mandate/ancestry/commit-gate vocabulary | Not redundant. Deny-oriented fragments, OpenLine-coupled. |
| receiver-rollback 002: branch `research/receiver-rollback-002` @ `d6103e61680f7249983fc03ed000dd6b1f48f979` (merged PR #91) — T1–T14 | durable ancestry op-log; restart monotonicity; write-failure→no-acknowledgement; clean first boot; duplicate lineage idempotent and non-widening; descendant evaluated only after restart | Same gaps as 001: composition, ALLOW half, owner-key supersession, portability | Not redundant. Same reason. |
| trust-root-succession: branch `study/trust-root-succession-001` @ `106f6fb51a25a3c1ea5df8a82211121f63f2263e`, terminal PASS | restart preserves the successor; superseded owner cannot return; history survives succession | individual grant revocation; replay; the full delegation→revocation→restart→replay→rotation sequence; portability | Not redundant. One lifecycle phase only. |
| owner-control: branch `study/owner-control-002` @ `86df1691dbf95d088f50214f683912323e369471`, terminal PASS | SIGNATURE_VALID alongside refusal — the standing/history split as a single observation | lifecycle composition; restart; replay; owner-key rotation; portability | Not redundant. Single observation, not a sequence. |
| stolen-authority: `STOLEN_AUTHORITY_001_CONTRACT.json` (main), schema `openline.stolen-authority-001.contract.v3`, base_sha `3ae2918d59125e13cf8f58147e482ebb940b6da6` | possession of another subject's valid portable COMMIT artifacts confers no execution authority; thief cannot burn the victim's one-use permission; replay rejected | revocation lifecycle; owner succession; restart; any cross-implementation portable sequence | Not redundant. Subject-binding, not permission-lifecycle. |
| temporal-authority: `benchmarks/temporal_authority_001/` (main; `FREEZE.json` frozen case expectations) | composed authority + execution-time revalidation + deadline arms around one exact action; relevant supersession narrows the mandate slot (expected effect 0); fresh owner successor admitted before selection (expected effect 1) | OpenLine-specific throughout (mandate slots, Authority Compiler, receiver-pinned owner); restart; replay; frozen ALLOW/DENY reason vocabulary portable across architectures; the five-phase lifecycle as one sequence | Not redundant. Closest to composition, but coupled and partial. |

## External facets (re-verified 2026-09-29)

| Suite / version | Covers | Does NOT cover | Redundancy verdict |
|---|---|---|---|
| OAuth token revocation / introspection: RFC 7009 §2.1 (revocation takes effect immediately), RFC 7662 §2.2 (introspection `active` boolean); incident evidence in `corpus-external-failure-modes.md` (GitHub 2022 OAuth token theft → RFC 7009 revocation as the ordinary fix; Okta session-revoke vs token decoupling; better-auth JWT revocation no-op notes) | facets: stolen/revoked token stops authorizing; revoked self-contained JWT stops authorizing — where the deployment uses introspection or denylists | composed lifecycle; restart durability; owner-key supersession; single-use replay; the ALLOW half. No single versioned "OAuth provider revocation test suite" was identified — the evidence is the standards plus provider behavior, recorded here as that and nothing more | Not redundant. Facet coverage only. |
| django-oauth-toolkit: fix PR #1818, commit `f797b8aff2fa605fc159f98fbda3dcb4703172c6`, issue #1816; shipped in 3.4.1 per the follow-up PR #1817 discussion (re-verified via GitHub 2026-09-29) | one facet: an explicitly revoked refresh token must not be re-issued inside `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` (superseded-by-rotation vs repudiated discriminator) | everything outside the refresh-token rotation window; restart; replay; owner-key rotation; portability | Not redundant. Single-facet fix test. |
| Kerberos ticket lifetime: Microsoft Learn, "Maximum lifetime for user ticket" (previous-versions, Windows 10; re-verified live 2026-09-29) — disabled users' pre-issued tickets authorize until expiry; recommended bound 10 hours; Protected Users group as mitigation | lifetime-bounded standing as ordinary, documented practice | instant revocation — knowingly traded for offline operation; any composed or portable sequence | Not redundant. Design-doc evidence, not a test suite. |
| chrome-agent-platform delegation design: `docs/AGENT-DELEGATION.md` @ `392579db2f555c9ce15df6b1694e98d89df9ced2` (re-verified live 2026-09-29); `tests/agent-delegation.test.ts` (16 KATs); `scripts/kat-agent-delegation.ts` | one lifecycle phase: replaced worker inherits no approvals (`approvalBinding: null`, fresh execution id) — existence proof that rebinding is ordinary practice in a shipping non-OpenLine framework | revocation; restart; replay; owner-key rotation; any portable cross-implementation sequence | Not redundant. One phase only. |

## Scoped novelty statement

We found no equivalent in this comparison: none of the suites inspected
provides the composed delegation → revocation → restart → replay →
owner-key-replacement lifecycle as one portable, implementation-agnostic
sequence with frozen ALLOW and DENY expectations. The pieces are tested;
the composition — including the ALLOW half, which is the sharp edge — is
not. This statement is scoped to the suites and versions above. It is not
a claim that no equivalent exists anywhere.

Falsifier linkage: redundancy would have required a suite asserting this
exact composed sequence with both ALLOW and DENY frozen expectations.
None was found.
