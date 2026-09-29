#!/usr/bin/env bash
# AACB-003 one-command reproduction.
#  1. Verifies the frozen contract hashes (CONTRACT.md, VECTORS.md,
#     EXPECTED-003.md, SCORING.md) against the hashes recorded in FREEZE.md.
#  2. Runs the full suite: both conformant drivers, all 7 fault variants,
#     and the false-reporting driver (which is the fault variant
#     "false_report").
#  3. Prints the reconciled conformance table (ALLOW-half / DENY-half /
#     verdict), asserts every row against the expected outcomes in
#     run-results.md, and exits nonzero on any mismatch.
#
# Requirements: system Python 3, standard library only. No pip, no network.

set -euo pipefail
cd "$(dirname "$0")"

echo "== AACB-003 reproduction: contract v0.3.0 =="
echo

echo "-- step 1/3: frozen-hash verification --"
# Build a checksums file from the hash table recorded in FREEZE.md and check it.
python3 - <<'EOF'
import re
rows = []
for line in open("FREEZE.md"):
    m = re.match(r"\|\s*(\S+\.md)\s*\|\s*([0-9a-f]{64})\s*\|", line)
    if m:
        rows.append((m.group(1), m.group(2)))
assert len(rows) == 4, f"expected 4 frozen hashes in FREEZE.md, found {len(rows)}"
with open(".checksums.frozen", "w") as f:
    for name, h in rows:
        f.write(f"{h}  {name}\n")
print("hashes pinned from FREEZE.md: " + ", ".join(n for n, _ in rows))
EOF
sha256sum -c .checksums.frozen
rm -f .checksums.frozen
echo "frozen hashes OK"
echo

echo "-- step 2/3: run the full suite (9 drivers) --"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

run() { # ev_name impl fault
    if [ -n "$3" ]; then
        python3 "aacb-003-harness.py" "aacb-003-impl-$2.py" \
            "$SCRATCH/work-$1" --fault "$3" --name "$1" > /dev/null
    else
        python3 "aacb-003-harness.py" "aacb-003-impl-$2.py" \
            "$SCRATCH/work-$1" --name "$1" > /dev/null
    fi
    echo "ran: $1"
}

run registry registry ""
run introspection introspection ""
run fault-false_report            faulty false_report
run fault-revocation_not_honored faulty revocation_not_honored
run fault-resurrection_after_restart faulty resurrection_after_restart
run fault-replay_duplicates_effect faulty replay_duplicates_effect
run fault-stale_owner_accepted   faulty stale_owner_accepted
run fault-deny_everything        faulty deny_everything
run fault-signature_only         faulty signature_only
echo

echo "-- step 3/3: reconciled conformance table + assertion --"
python3 - <<'EOF'
import json, sys

EXPECTED = {
    "registry":                     ("4/4", "4/4", "CONFORMANT",     []),
    "introspection":                ("4/4", "4/4", "CONFORMANT",     []),
    "fault-false_report":           ("0/4", "0/4", "NOT CONFORMANT", ["S2","S4","S6","S8","S10","S12","S14","S15"]),
    "fault-revocation_not_honored":  ("4/4", "2/4", "NOT CONFORMANT", ["S4","S6"]),
    "fault-resurrection_after_restart": ("4/4", "3/4", "NOT CONFORMANT", ["S6"]),
    "fault-replay_duplicates_effect":   ("4/4", "3/4", "NOT CONFORMANT", ["S15"]),
    "fault-stale_owner_accepted":   ("4/4", "3/4", "NOT CONFORMANT", ["S10"]),
    "fault-deny_everything":        ("0/4", "0/4", "NOT CONFORMANT", ["S2","S4","S6","S8","S10","S12","S14","S15"]),
    "fault-signature_only":         ("4/4", "0/4", "NOT CONFORMANT", ["S4","S6","S10","S15"]),
}

print(f"{'driver':<36}{'ALLOW':<8}{'DENY':<8}conformance")
failures = 0
for name, (e_allow, e_deny, e_conf, e_failed) in EXPECTED.items():
    s = json.load(open(f"evidence/{name}/summary.json"))
    actual = (s["allow_half"], s["deny_half"], s["conformance"], list(s["failed_sids"]))
    ok = actual == (e_allow, e_deny, e_conf, e_failed)
    failures += not ok
    mark = "OK " if ok else "MISMATCH"
    failed = " ".join(s["failed_sids"]) or "—"
    print(f"{mark} {name:<31}{s['allow_half']:<8}{s['deny_half']:<8}{s['conformance']:<16} failed: {failed}")

print()
if failures:
    print(f"REPRODUCTION FAILED: {failures} driver(s) diverged from expected outcomes.")
    sys.exit(1)
print("REPRODUCTION PASSED: all 9 drivers match the expected outcomes in run-results.md.")
print("All runs internally operated. Contract v0.3.0.")
EOF
