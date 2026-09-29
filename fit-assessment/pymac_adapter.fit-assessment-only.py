"""AACB-003 external-integration candidate: pymacaroons 0.13.0 adapter.

THIN ADAPTER PER THE AACB-003 ADAPTER CONTRACT (see NEUTRALITY-AUDIT.md):
- Translates transport/serialization only (macaroon wire format, caveat
  encoding). Persists the candidate's own state (root key material) so
  restart() is meaningful — no fabricated authz state.
- Deliberately does NOT add: a revocation list, single-use consumption
  state, or owner-key supersession logic. The macaroon mechanism has none
  of these natively; adding them would be implementing missing
  authorization behavior for the candidate and is forbidden.
- revoke() is therefore a strict no-op: the candidate's actual behavior
  is that revocation does nothing. Steps requiring revocation, replay
  rejection, or supersession fail honestly.

Fit-assessment only. Run against the CURRENT (002) harness. Not validation
of the 003 contract. Internally operated.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import MacaroonInvalidSignatureException


def _cav_id(cav) -> str:
    cid = cav.caveat_id
    return cid.decode() if isinstance(cid, bytes) else str(cid)


class Driver:
    """Neutral driver protocol: delegate / revoke / replace_owner_key / restart / attempt."""

    def __init__(self, workdir: Path):
        self._file = Path(workdir) / "pymac-state.json"
        self._mem = None
        if not self._file.exists():
            self._write({
                "owner_keys": {"owner-A": secrets.token_bytes(32).hex()},
                "current_owner": "owner-A",
                "seq": 0,
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

    def _caveats(self, m: Macaroon) -> dict:
        out = {}
        for cav in m.caveats:
            cid = _cav_id(cav)
            if "=" in cid:
                k, v = cid.split("=", 1)
                out[k] = v
        return out

    # -- driver protocol -------------------------------------------------------
    def delegate(self, owner: str, worker: str, action: str, single_use: bool) -> str:
        st = self._read()
        if owner != st["current_owner"]:
            raise ValueError("delegate by non-current owner")
        st["seq"] += 1
        gid = f"g{st['seq']:04d}"
        m = Macaroon(
            location="aacb3",
            identifier=gid,
            key=bytes.fromhex(st["owner_keys"][owner]),
        )
        m.add_first_party_caveat(f"owner={owner}")
        m.add_first_party_caveat(f"worker={worker}")
        m.add_first_party_caveat(f"action={action}")
        m.add_first_party_caveat(f"single_use={single_use}")
        m.add_first_party_caveat(f"nonce=n{st['seq']:04d}")
        self._write(st)
        return m.serialize()

    def revoke(self, owner: str, grant_artifact: str) -> None:
        # No-op by design: the macaroon mechanism has no native revocation.
        # The adapter contract forbids adding a revocation list the
        # candidate lacks. Steps requiring revocation therefore fail
        # honestly, as the mechanism itself would fail them.
        return None

    def replace_owner_key(self, old_owner: str, new_owner: str) -> None:
        st = self._read()
        if st["current_owner"] != old_owner:
            raise ValueError("not the current owner")
        # Root-key rotation IS native (new key id + new key). Old key material
        # is retained so old artifacts still signature-verify (history
        # preserved) — the mechanism has no supersession semantics, so
        # old-key artifacts keep authorizing. That gap is the candidate's.
        st["owner_keys"][new_owner] = secrets.token_bytes(32).hex()
        st["current_owner"] = new_owner
        self._write(st)

    def restart(self) -> None:
        self._mem = None  # simulate process death: in-memory state gone

    def attempt(self, worker: str, action: str, grant_artifact: str) -> tuple[str, str]:
        st = self._read()
        try:
            m = Macaroon.deserialize(grant_artifact)
        except Exception:
            return ("DENY", "MALFORMED")
        cavs = self._caveats(m)
        owner = cavs.get("owner")
        key_hex = st["owner_keys"].get(owner)
        if key_hex is None:
            return ("DENY", "UNKNOWN_OWNER")
        cavs = self._caveats(m)
        owner = cavs.get("owner")
        key_hex = st["owner_keys"].get(owner)
        if key_hex is None:
            return ("DENY", "UNKNOWN_OWNER")
        # Substantive verifier policy: worker and action are pinned to the
        # request; the owner is pinned to a root key the receiver actually
        # holds (the trust decision). The remaining first-party caveats
        # (single_use, nonce) are issuer assertions with no verifier-side
        # state — the mechanism cannot enforce them, so they are satisfied
        # from the artifact's own values. Consumption/replay state would be
        # adapter-added authz behavior and is forbidden.
        v = Verifier()
        v.satisfy_exact(f"worker={worker}")
        v.satisfy_exact(f"action={action}")
        v.satisfy_exact(f"owner={owner}")
        if "single_use" in cavs:
            v.satisfy_exact(f"single_use={cavs['single_use']}")
        if "nonce" in cavs:
            v.satisfy_exact(f"nonce={cavs['nonce']}")
        try:
            v.verify(m, bytes.fromhex(key_hex))
        except MacaroonInvalidSignatureException:
            return ("DENY", "BAD_SIGNATURE")
        return ("ALLOW", "ALLOW")
