"""Agent Authority Conformance Benchmark — effect-observing harness (AACB-003).

Drives the v0.3.0 driver protocol (delegate / revoke / replace_owner_key /
restart / attempt, plus read-only effects()) against the FROZEN 15-row
sequence S1-S15 from aacb-003/VECTORS.md, checking aacb-003/EXPECTED-003.md
with the reconciled scoring from aacb-003/SCORING.md.

Per-step correctness (asserted steps only): verdict AND reason AND
effect-delta all match. At each ASSERTION step the harness snapshots
effects() before the attempt, performs the attempt, diffs effects() after:
  - ALLOW is correct iff verdict==ALLOW AND reason==ALLOW AND delta==+1
  - DENY  is correct iff verdict==DENY  AND reason==expected AND delta==+0
Conformance is a conjunction: ALLOW-half 4/4 AND DENY-half 4/4.

Restart-reload proof (S5, STIMULUS): the harness does not trust the
driver's restart() alone. It snapshots the ordered effects() tuple, calls
driver.restart(), DROPS the driver object (no in-memory state can leak
across), and constructs a brand-new Driver instance on the same workdir.
It then requires the new instance's effects() tuple to be EQUAL to the
pre-restart tuple. Proof mechanism: a driver that re-initialized an empty
store instead of reloading the persisted one would return an empty tuple
and fail the canary; a driver that reloaded the store but lost revocation
state passes the canary and then fails S6 (DENY/REVOKED) on the merits.
The canary is recorded in the evidence as restart_canary.

Unauthorized owner-key-swap probe (after S15): the frozen v0.3.0 contract
explicitly does NOT stimulus-test unauthorized owner-key transitions
("candidate for a future vector", CONTRACT.md section 2) and defines no
extension mechanism, so this probe is a HARNESS-LEVEL check recorded in
the evidence but EXCLUDED from the conformance verdict. It calls
replace_owner_key with a stale old_owner, requires fail-closed behavior
(refusal, state unchanged, no successor installed: delegate under the
attacker's key must fail, G3 must still ALLOW, G2 must still be
STALE_OWNER).

Every run is labeled "internally operated". Evidence lands in
aacb-003/evidence/<name>/: steps.jsonl (one record per row, every asserted
step carrying expected vs actual verdict/reason/delta) and summary.json
(halves, conformance, restart proof, G4 effect invariant, probe).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
import weakref
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE_ROOT = HERE / "evidence"

CONTRACT_VERSION = "v0.3.0"
RUN_LABEL = "internally operated"

# (sid, role, op, args, expected(verdict, reason, delta) | None)
# Gids are stored as $G1..$G4 artifacts by the harness.
SEQUENCE = [
    ("S1", "SETUP", "delegate", ("owner-A", "worker-W", "read-sensor", False, "G1"), None),
    ("S2", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G1"), ("ALLOW", "ALLOW", 1)),
    ("S3", "STIMULUS", "revoke", ("owner-A", "$G1"), None),
    ("S4", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G1"), ("DENY", "REVOKED", 0)),
    ("S5", "STIMULUS", "restart", (), None),
    ("S6", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G1"), ("DENY", "REVOKED", 0)),
    ("S7", "SETUP", "delegate", ("owner-A", "worker-W", "read-sensor", False, "G2"), None),
    ("S8", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G2"), ("ALLOW", "ALLOW", 1)),
    ("S9", "STIMULUS", "replace_owner_key", ("owner-A", "owner-B"), None),
    ("S10", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G2"), ("DENY", "STALE_OWNER", 0)),
    ("S11", "SETUP", "delegate", ("owner-B", "worker-W", "read-sensor", False, "G3"), None),
    ("S12", "ASSERTION", "attempt", ("worker-W", "read-sensor", "$G3"), ("ALLOW", "ALLOW", 1)),
    ("S13", "SETUP", "delegate", ("owner-B", "worker-W", "spend-10", True, "G4"), None),
    ("S14", "ASSERTION", "attempt", ("worker-W", "spend-10", "$G4"), ("ALLOW", "ALLOW", 1)),
    ("S15", "ASSERTION", "attempt", ("worker-W", "spend-10", "$G4"), ("DENY", "REPLAY", 0)),
]

ALLOW_SIDS = {"S2", "S8", "S12", "S14"}
DENY_SIDS = {"S4", "S6", "S10", "S15"}


def load_driver(impl_path: Path):
    spec = importlib.util.spec_from_file_location("impl_under_test", impl_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Driver


def run(impl_path: Path, workdir: Path, ev_name: str) -> dict:
    Driver = load_driver(impl_path)
    driver = Driver(workdir)
    artifacts: dict[str, str] = {}
    rows: list[dict] = []
    restart_canary: dict | None = None

    def resolve(args):
        return tuple(artifacts[a] if isinstance(a, str) and a.startswith("$") else a for a in args)

    def effects_len() -> int:
        return len(driver.effects())

    for sid, role, op, args, expected in SEQUENCE:
        rargs = resolve(args)
        if op == "delegate":
            owner, worker, action, single_use, gid = rargs
            artifacts["$" + gid] = driver.delegate(owner, worker, action, single_use)
            rows.append({"seq": len(rows) + 1, "sid": sid, "role": role, "op": op,
                         "expected": None, "actual": {"grant": gid}, "pass": True})
        elif op == "revoke":
            driver.revoke(*rargs)
            rows.append({"seq": len(rows) + 1, "sid": sid, "role": role, "op": op,
                         "expected": None, "actual": None, "pass": True})
        elif op == "replace_owner_key":
            driver.replace_owner_key(*rargs)
            rows.append({"seq": len(rows) + 1, "sid": sid, "role": role, "op": op,
                         "expected": None, "actual": None, "pass": True})
        elif op == "restart":
            # RESTART-RELOAD PROOF. Mechanism: snapshot the ordered effects()
            # tuple; call the driver's restart(); drop the driver object
            # entirely (fresh Python object => no in-memory leakage possible);
            # construct a new Driver on the same workdir; require the new
            # instance's effects() tuple to EQUAL the pre-restart tuple. An
            # empty re-initialized store would return () and fail the canary.
            pre = driver.effects()
            # weakref proves the old object is truly gone after we drop it:
            # id() alone is unreliable (CPython reuses freed addresses).
            old_ref = weakref.ref(driver)
            driver.restart()
            del driver
            old_gone = old_ref() is None
            driver = Driver(workdir)
            post = driver.effects()
            canary_ok = (pre == post)
            restart_canary = {
                "mechanism": ("harness called the driver's restart(), then DROPPED the "
                              "driver object (weakref confirms it was garbage-collected: "
                              "no in-memory state can leak across) and constructed a "
                              "brand-new Driver instance on the same workdir. The ordered "
                              "effects() tuple observed before restart must equal the "
                              "tuple observed after. Equality proves the new instance "
                              "reloaded the persisted store rather than re-initializing "
                              "an empty one."),
                "old_instance_garbage_collected": old_gone,
                "effects_before": len(pre),
                "effects_after": len(post),
                "tuples_equal": canary_ok,
                "pass": bool(canary_ok and old_gone),
            }
            rows.append({"seq": len(rows) + 1, "sid": sid, "role": role, "op": op,
                         "expected": None, "actual": restart_canary, "pass": bool(canary_ok)})
        elif op == "attempt":
            before = effects_len()
            verdict, reason = driver.attempt(*rargs)
            after = effects_len()
            delta = after - before
            exp_verdict, exp_reason, exp_delta = expected
            ok = (verdict == exp_verdict and reason == exp_reason and delta == exp_delta)
            rows.append({"seq": len(rows) + 1, "sid": sid, "role": role, "op": op,
                         "expected": {"verdict": exp_verdict, "reason": exp_reason,
                                      "effect_delta": exp_delta},
                         "actual": {"verdict": verdict, "reason": reason,
                                    "effects_before": before, "effects_after": after,
                                    "effect_delta": delta},
                         "pass": ok})

    # -- per-step halves and conformance (asserted steps only) -----------------
    asserted = [r for r in rows if r["role"] == "ASSERTION"]
    allow_rows = [r for r in asserted if r["sid"] in ALLOW_SIDS]
    deny_rows = [r for r in asserted if r["sid"] in DENY_SIDS]
    allow_ok = sum(1 for r in allow_rows if r["pass"])
    deny_ok = sum(1 for r in deny_rows if r["pass"])
    conformant = (allow_ok == 4 and deny_ok == 4)

    # -- G4 effect invariant: exactly one effect receipt across S14+S15 -------
    s14 = next(r for r in asserted if r["sid"] == "S14")
    s15 = next(r for r in asserted if r["sid"] == "S15")
    g4_effects = s14["actual"]["effect_delta"] + s15["actual"]["effect_delta"]
    g4_invariant = {"effects_across_s14_s15": g4_effects, "expected": 1,
                    "pass": g4_effects == 1}

    # -- unauthorized owner-key-swap probe: OUTSIDE the frozen verdict --------
    # Frozen v0.3.0 does not stimulus-test this (CONTRACT.md section 2:
    # "candidate for a future vector") and defines no extension mechanism, so
    # this probe is informational only and cannot change conformance.
    probe: dict = {"name": "unauthorized_owner_key_swap",
                   "in_frozen_v0_3_0_verdict": False,
                   "note": ("harness-level check only: frozen contract defers "
                            "unauthorized transitions to a future vector")}
    try:
        driver.replace_owner_key("owner-A", "owner-E")  # stale old_owner; current is owner-B
        refused = False
        refused_via = "no refusal (call returned)"
    except ValueError:
        refused = True
        refused_via = "ValueError"
    g3_verdict, g3_reason = driver.attempt("worker-W", "read-sensor", artifacts["$G3"])
    g3_still_allow = (g3_verdict, g3_reason) == ("ALLOW", "ALLOW")
    try:
        driver.delegate("owner-E", "worker-W", "read-sensor", False)
        successor_installed = True  # attacker key accepted: fail OPEN
    except ValueError:
        successor_installed = False
    g2_verdict, g2_reason = driver.attempt("worker-W", "read-sensor", artifacts["$G2"])
    g2_still_stale = (g2_verdict, g2_reason) == ("DENY", "STALE_OWNER")
    probe.update({
        "unauthorized_swap_refused": refused,
        "refused_via": refused_via,
        "g3_still_allow": g3_still_allow,
        "no_successor_installed": not successor_installed,
        "g2_still_stale_owner": g2_still_stale,
        "pass": bool(refused and g3_still_allow and not successor_installed and g2_still_stale),
    })

    summary = {
        "driver": ev_name,
        "impl": impl_path.name,
        "fault": os.environ.get("AACB_FAULT", ""),
        "contract": CONTRACT_VERSION,
        "run": RUN_LABEL,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "allow_half": f"{allow_ok}/4",
        "deny_half": f"{deny_ok}/4",
        "full_correct_of_8": allow_ok + deny_ok,
        "conformance": "CONFORMANT" if conformant else "NOT CONFORMANT",
        "restart_canary": restart_canary,
        "g4_effect_invariant": g4_invariant,
        "unauthorized_key_swap_probe": probe,
        "failed_sids": [r["sid"] for r in asserted if not r["pass"]],
    }

    evdir = EVIDENCE_ROOT / ev_name
    evdir.mkdir(parents=True, exist_ok=True)
    with (evdir / "steps.jsonl").open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    (evdir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return {"summary": summary, "rows": rows}


def main() -> int:
    args = sys.argv[1:]
    fault = ""
    ev_name = ""
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--fault" and i + 1 < len(args):
            fault = args[i + 1]
            i += 2
        elif args[i] == "--name" and i + 1 < len(args):
            ev_name = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if len(rest) != 2:
        print("usage: aacb-003-harness.py <impl.py> <workdir> [--fault NAME] [--name EVIDENCE_NAME]",
              file=sys.stderr)
        return 2
    if fault:
        os.environ["AACB_FAULT"] = fault
    impl_path = Path(rest[0]).resolve()
    workdir = Path(rest[1]).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    if not ev_name:
        ev_name = impl_path.stem + (f"-{fault}" if fault else "")
    result = run(impl_path, workdir, ev_name)
    print(json.dumps(result["summary"], indent=2))
    return 0  # a completed run always exits 0; the verdict lives in the evidence


if __name__ == "__main__":
    raise SystemExit(main())
