"""AACB-003 negative-control driver: one conformant codebase, injected faults.

Selects a fault variant from the AACB_FAULT environment variable; the
module-level `Driver` factory returns the matching subclass instance. Each
variant breaks EXACTLY ONE property so the harness can pinpoint which
assertion rows fail. The base class is the registry design (same as
aacb-003-impl-registry.py); fault hooks override single behaviors.

Faults:
  false_report              — correct verdicts/reasons, but INVERTED effect
                              production: ALLOW produces no effect, DENY
                              produces an effect. The harness must flag the
                              verdict/effect divergence on every row.
  revocation_not_honored    — revoke() is a no-op; revoked grants stay live.
  resurrection_after_restart— restart() scrubs revocation markers from the
                              PERSISTED store, so revoked grants come back.
  replay_duplicates_effect  — single-use consumption is never recorded;
                              a replayed artifact ALLOWs again with an effect.
  stale_owner_accepted      — standing check ignores owner currency;
                              old-owner grants stay ALLOW after rotation.
  deny_everything           — every attempt is (DENY, "DENY"); the reason is
                              outside the closed vocabulary, so no DENY row
                              can be per-step correct either.
  signature_only            — standing checks skipped entirely; a valid
                              signature is treated as current permission.

Internally operated. Stdlib only. No OpenLine imports. Zero OpenLine code.
Testing only: these variants are deliberately broken and exist only to
prove the harness discriminates.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path


def _sig(secret: bytes, payload: str) -> str:
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


class _Base:
    """Conformant registry driver with fault-injection hooks."""

    def __init__(self, workdir: Path):
        self._file = Path(workdir) / "faulty-state.json"
        self._mem = None
        if not self._file.exists():
            self._write({
                "owner_secrets": {"owner-A": hashlib.sha256(b"seed-owner-A").hexdigest()},
                "current_owner": "owner-A",
                "grants": {},
                "seq": 0,
                "eseq": 0,
                "effects": [],
            })

    def _write(self, state: dict) -> None:
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        tmp.replace(self._file)
        self._mem = state

    def _read(self) -> dict:
        if self._mem is None:
            self._mem = json.loads(self._file.read_text())
        return self._mem

    # -- fault hooks: base behavior is conformant; variants override one ----
    def _allow_effect(self, st: dict, worker: str, action: str, gid: str) -> None:
        st["eseq"] += 1
        st["effects"].append({"eseq": st["eseq"], "gid": gid,
                              "worker": worker, "action": action})

    def _deny_effect(self, st: dict, worker: str, action: str, gid: str) -> None:
        pass  # conformant: a denied attempt executes nothing

    def _standing_defect(self, st: dict, grant: dict) -> str | None:
        if grant["status"] == "REVOKED":
            return "REVOKED"
        if grant["owner"] != st["current_owner"]:
            return "STALE_OWNER"
        if grant["single_use"] and grant["consumed"]:
            return "REPLAY"
        return None

    def _consume(self, st: dict, grant: dict) -> None:
        grant["consumed"] = True

    # -- driver protocol -----------------------------------------------------
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
            raise ValueError("not the current owner")
        st["owner_secrets"][new_owner] = hashlib.sha256(f"seed-{new_owner}".encode()).hexdigest()
        st["current_owner"] = new_owner
        self._write(st)

    def restart(self) -> None:
        self._mem = None

    def effects(self) -> tuple:
        return tuple(self._read()["effects"])

    def attempt(self, worker: str, action: str, grant_artifact: str) -> tuple[str, str]:
        st = self._read()
        try:
            art = json.loads(grant_artifact)
            payload = json.loads(art["payload"])
        except (ValueError, KeyError):
            self._deny_effect(st, worker, action, "?")
            return ("DENY", "MALFORMED")
        owner = payload.get("owner")
        secret = st["owner_secrets"].get(owner)
        if secret is None:
            self._deny_effect(st, worker, action, "?")
            return ("DENY", "UNKNOWN_OWNER")
        if not hmac.compare_digest(_sig(bytes.fromhex(secret), art["payload"]), art["sig"]):
            self._deny_effect(st, worker, action, "?")
            return ("DENY", "BAD_SIGNATURE")
        if payload.get("worker") != worker or payload.get("action") != action:
            self._deny_effect(st, worker, action, "?")
            return ("DENY", "MISMATCH")
        gid = payload.get("gid")
        grant = st["grants"].get(gid)
        if grant is None:
            self._deny_effect(st, worker, action, "?")
            return ("DENY", "UNKNOWN_GRANT")
        defect = self._standing_defect(st, grant)
        if defect is not None:
            self._deny_effect(st, worker, action, gid)
            return ("DENY", defect)
        if grant["single_use"]:
            self._consume(st, grant)
        self._allow_effect(st, worker, action, gid)
        self._write(st)
        return ("ALLOW", "ALLOW")


# -- fault variants: each overrides exactly one behavior ---------------------

class _FalseReport(_Base):
    """Verdicts and reasons are correct; effect production is inverted:
    ALLOW executes nothing, DENY executes the action. The harness must flag
    the verdict/effect divergence on every asserted row."""

    def _allow_effect(self, st, worker, action, gid):
        pass  # says ALLOW, produces no effect

    def _deny_effect(self, st, worker, action, gid):
        st["eseq"] += 1
        st["effects"].append({"eseq": st["eseq"], "gid": gid,
                              "worker": worker, "action": action,
                              "note": "effect-despite-DENY"})
        self._write(st)


class _RevocationNotHonored(_Base):
    """revoke() accepts the call but persists nothing."""

    def revoke(self, owner: str, grant_artifact: str) -> None:
        self._read()  # touches state; the revocation is silently dropped


class _ResurrectionAfterRestart(_Base):
    """restart() scrubs revocation markers from the PERSISTED store before
    dropping in-memory state, so revoked grants resurrect on reload."""

    def restart(self) -> None:
        st = self._read()
        for grant in st["grants"].values():
            grant["status"] = "ACTIVE"  # scrubbed from durable state
        self._write(st)
        self._mem = None


class _ReplayDuplicates(_Base):
    """Single-use consumption is never recorded; replay ALLOWs again and
    produces a second effect."""

    def _consume(self, st: dict, grant: dict) -> None:
        pass  # consumed flag never set


class _StaleOwnerAccepted(_Base):
    """Standing check ignores owner currency; old-key grants stay live."""

    def _standing_defect(self, st: dict, grant: dict) -> str | None:
        if grant["status"] == "REVOKED":
            return "REVOKED"
        if grant["single_use"] and grant["consumed"]:
            return "REPLAY"
        return None  # STALE_OWNER never raised


class _DenyEverything(_Base):
    """Every attempt is denied. The reason is deliberately outside the
    closed vocabulary so no DENY row can be per-step correct either."""

    def attempt(self, worker: str, action: str, grant_artifact: str) -> tuple[str, str]:
        return ("DENY", "DENY")


class _SignatureOnly(_Base):
    """Valid signature alone counts as current permission; all standing
    checks skipped."""

    def _standing_defect(self, st: dict, grant: dict) -> str | None:
        return None


_FAULTS = {
    "false_report": _FalseReport,
    "revocation_not_honored": _RevocationNotHonored,
    "resurrection_after_restart": _ResurrectionAfterRestart,
    "replay_duplicates_effect": _ReplayDuplicates,
    "stale_owner_accepted": _StaleOwnerAccepted,
    "deny_everything": _DenyEverything,
    "signature_only": _SignatureOnly,
}


def Driver(workdir):
    """Factory: selects the fault variant from AACB_FAULT."""
    fault = os.environ.get("AACB_FAULT", "")
    cls = _FAULTS.get(fault)
    if cls is None:
        raise ValueError(f"AACB_FAULT must be one of {sorted(_FAULTS)}; got {fault!r}")
    return cls(workdir)
