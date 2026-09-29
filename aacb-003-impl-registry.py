"""AACB-003 implementation 1: grant-registry design (no OpenLine code).

Re-implementation of the aacb-002-impl-registry.py design against the
v0.3.0 driver protocol: delegate / revoke / replace_owner_key / restart /
attempt are UNCHANGED; adds the read-only effects() affordance.

Architecture: the receiver keeps a DURABLE registry of grants. An attempt
verifies the artifact's signature against the issuing owner's key material,
then consults the registry for CURRENT standing (status, owner currency).
Signature validity and standing are separate lookups.

On every ALLOW, the driver EXECUTES the action and appends one opaque
effect receipt to its durable effects log. On DENY it appends nothing.
effects() returns the ordered tuple of receipts; it is read-only —
calling it never changes state.

Internally operated. Stdlib only. No OpenLine imports. Zero OpenLine code.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path


def _sig(secret: bytes, payload: str) -> str:
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


class Driver:
    """v0.3.0 driver protocol: delegate / revoke / replace_owner_key /
    restart / attempt, plus read-only effects()."""

    def __init__(self, workdir: Path):
        self._file = Path(workdir) / "registry-state.json"
        self._mem = None  # in-memory cache; restart() drops it
        if not self._file.exists():
            self._write({
                "owner_secrets": {"owner-A": hashlib.sha256(b"seed-owner-A").hexdigest()},
                "current_owner": "owner-A",
                "grants": {},
                "seq": 0,
                "eseq": 0,      # effect-receipt sequence; persisted with the store
                "effects": [],  # ordered opaque effect receipts, one per executed action
            })

    # -- durable store helpers -------------------------------------------------
    def _write(self, state: dict) -> None:
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        tmp.replace(self._file)
        self._mem = state

    def _read(self) -> dict:
        if self._mem is None:  # post-restart: rehydrate from durable store only
            self._mem = json.loads(self._file.read_text())
        return self._mem

    def _record_effect(self, st: dict, worker: str, action: str, gid: str) -> None:
        st["eseq"] += 1
        st["effects"].append({"eseq": st["eseq"], "gid": gid,
                              "worker": worker, "action": action})

    # -- driver protocol -------------------------------------------------------
    def delegate(self, owner: str, worker: str, action: str, single_use: bool) -> str:
        st = self._read()
        if owner != st["current_owner"]:
            raise ValueError("delegate by non-current owner")
        st["seq"] += 1
        gid = f"g{st['seq']:04d}"
        payload = json.dumps({"gid": gid, "owner": owner, "worker": worker,
                              "action": action, "single_use": single_use}, sort_keys=True)
        sig = _sig(bytes.fromhex(st["owner_secrets"][owner]), payload)
        st["grants"][gid] = {"owner": owner, "worker": worker, "action": action,
                             "status": "ACTIVE", "single_use": single_use,
                             "consumed": False}
        self._write(st)
        return json.dumps({"payload": payload, "sig": sig})

    def revoke(self, owner: str, grant_artifact: str) -> None:
        st = self._read()
        gid = json.loads(json.loads(grant_artifact)["payload"])["gid"]
        if gid in st["grants"]:
            st["grants"][gid]["status"] = "REVOKED"
            self._write(st)

    def replace_owner_key(self, old_owner: str, new_owner: str) -> None:
        st = self._read()
        if st["current_owner"] != old_owner:
            # Fail closed: only the CURRENT owner may install a successor.
            raise ValueError("not the current owner")
        # Old key material is RETAINED so old artifacts still signature-verify
        # (history preserved) while losing standing.
        st["owner_secrets"][new_owner] = hashlib.sha256(f"seed-{new_owner}".encode()).hexdigest()
        st["current_owner"] = new_owner
        self._write(st)

    def restart(self) -> None:
        self._mem = None  # simulate process death: in-memory state gone

    def effects(self) -> tuple:
        # Read-only: observing the effects log never changes state.
        return tuple(self._read()["effects"])

    def attempt(self, worker: str, action: str, grant_artifact: str) -> tuple[str, str]:
        st = self._read()
        try:
            art = json.loads(grant_artifact)
            payload = json.loads(art["payload"])
        except (ValueError, KeyError):
            return ("DENY", "MALFORMED")
        owner = payload.get("owner")
        secret = st["owner_secrets"].get(owner)
        if secret is None:
            return ("DENY", "UNKNOWN_OWNER")
        # 1) signature validity — historical/cryptographic fact
        if not hmac.compare_digest(_sig(bytes.fromhex(secret), art["payload"]), art["sig"]):
            return ("DENY", "BAD_SIGNATURE")
        if payload.get("worker") != worker or payload.get("action") != action:
            return ("DENY", "MISMATCH")
        # 2) current standing — separate lookup
        gid = payload.get("gid")
        grant = st["grants"].get(gid)
        if grant is None:
            return ("DENY", "UNKNOWN_GRANT")
        if grant["status"] == "REVOKED":
            return ("DENY", "REVOKED")
        if grant["owner"] != st["current_owner"]:
            return ("DENY", "STALE_OWNER")
        if grant["single_use"] and grant["consumed"]:
            return ("DENY", "REPLAY")
        # ALLOW: execute the action — exactly one effect receipt — then persist.
        if grant["single_use"]:
            grant["consumed"] = True
        self._record_effect(st, worker, action, gid)
        self._write(st)
        return ("ALLOW", "ALLOW")
