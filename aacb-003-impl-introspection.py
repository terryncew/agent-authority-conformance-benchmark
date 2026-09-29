"""AACB-003 implementation 2: self-contained token + standing oracle (no OpenLine code).

Re-implementation of the aacb-002-impl-introspection.py design against the
v0.3.0 driver protocol: delegate / revoke / replace_owner_key / restart /
attempt are UNCHANGED; adds the read-only effects() affordance.

Architecture: the worker carries a SELF-CONTAINED signed token (like an
OAuth access token). The receiver verifies the token's signature, then
consults a separate DURABLE standing oracle (revocation list, current owner
key, consumed nonces) — the RFC 7662 introspection pattern. Authority rides
in the token; standing is evaluated at use time. Deliberately different from
impl 1.

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


def _tid(token_body: dict) -> str:
    return hashlib.sha256(json.dumps(token_body, sort_keys=True).encode()).hexdigest()[:16]


class Driver:
    """v0.3.0 driver protocol: delegate / revoke / replace_owner_key /
    restart / attempt, plus read-only effects()."""

    def __init__(self, workdir: Path):
        self._file = Path(workdir) / "oracle-state.json"
        self._mem = None
        if not self._file.exists():
            self._write({
                "owner_secrets": {"owner-A": hashlib.sha256(b"seed-owner-A").hexdigest()},
                "current_owner": "owner-A",
                "revoked": [],
                "consumed_nonces": [],
                "seq": 0,
                "eseq": 0,      # effect-receipt sequence; persisted with the store
                "effects": [],  # ordered opaque effect receipts, one per executed action
            })

    def _write(self, state: dict) -> None:
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        tmp.replace(self._file)
        self._mem = state

    def _read(self) -> dict:
        if self._mem is None:  # post-restart: rehydrate from durable store only
            self._mem = json.loads(self._file.read_text())
        return self._mem

    def _record_effect(self, st: dict, worker: str, action: str, tid: str) -> None:
        st["eseq"] += 1
        st["effects"].append({"eseq": st["eseq"], "tid": tid,
                              "worker": worker, "action": action})

    def delegate(self, owner: str, worker: str, action: str, single_use: bool) -> str:
        st = self._read()
        if owner != st["current_owner"]:
            raise ValueError("delegate by non-current owner")
        st["seq"] += 1
        body = {"owner": owner, "worker": worker, "action": action,
                "single_use": single_use, "nonce": f"n{st['seq']:04d}"}
        sig = _sig(bytes.fromhex(st["owner_secrets"][owner]),
                   json.dumps(body, sort_keys=True))
        self._write(st)
        return json.dumps({"body": body, "sig": sig})

    def revoke(self, owner: str, grant_artifact: str) -> None:
        st = self._read()
        body = json.loads(grant_artifact)["body"]
        tid = _tid(body)
        if tid not in st["revoked"]:
            st["revoked"].append(tid)
            self._write(st)

    def replace_owner_key(self, old_owner: str, new_owner: str) -> None:
        st = self._read()
        if st["current_owner"] != old_owner:
            # Fail closed: only the CURRENT owner may install a successor.
            raise ValueError("not the current owner")
        # Old key material retained: old tokens still signature-verify (history
        # preserved) while losing standing.
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
            body = art["body"]
        except (ValueError, KeyError):
            return ("DENY", "MALFORMED")
        owner = body.get("owner")
        secret = st["owner_secrets"].get(owner)
        if secret is None:
            return ("DENY", "UNKNOWN_OWNER")
        # 1) signature validity — cryptographic fact about the token
        if not hmac.compare_digest(
                _sig(bytes.fromhex(secret), json.dumps(body, sort_keys=True)), art["sig"]):
            return ("DENY", "BAD_SIGNATURE")
        if body.get("worker") != worker or body.get("action") != action:
            return ("DENY", "MISMATCH")
        # 2) standing oracle — evaluated at use time, separate from the token
        tid = _tid(body)
        if tid in st["revoked"]:
            return ("DENY", "REVOKED")
        if body.get("owner") != st["current_owner"]:
            return ("DENY", "STALE_OWNER")
        if body.get("single_use") and body.get("nonce") in st["consumed_nonces"]:
            return ("DENY", "REPLAY")
        # ALLOW: execute the action — exactly one effect receipt — then persist.
        if body.get("single_use"):
            st["consumed_nonces"].append(body["nonce"])
        self._record_effect(st, worker, action, tid)
        self._write(st)
        return ("ALLOW", "ALLOW")
