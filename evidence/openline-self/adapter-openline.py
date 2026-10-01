"""AACB-003 driver: openline-wallet (owner side) + ReferenceGate (receiver side).

The candidate under test is the OpenLine wallet/receiver pair from
terryncew/openline-wallet, driven exclusively through its own public code
paths, in the exact composition the repo's demo.py uses:

    wallet.grant / wallet.revoke (owner timeline, durable on disk)
      -> wallet.export_bundle
      -> gate.pin_principal / gate.admit_bundle (receiver admission)
      -> gate.issue_challenge -> create_presentation (worker-signed)
      -> gate.evaluate -> ALLOWED / STOPPED signed action receipt

Run: python3 aacb-003-harness.py aacb-003-impl-openline.py <workdir> --name openline-self
The harness is the frozen v0.3.0 file; this adapter is the only new code.

Native mappings (candidate's own behavior, unmodified in substance):
- delegate(owner, worker, action, single_use) -> wallet.grant(...),
  returning the mandate_id as the opaque grant token. The wallet binds
  issuer (principal), holder (subject_id + subject_public_key), and action
  (scopes) in a signed, hash-chained timeline event.
- revoke(owner, grant) -> wallet.revoke(mandate_id). Signed by the owner's
  root key, appended to the durable timeline, visible to the gate through
  the next bundle export. This is the candidate's real revocation path.
- attempt(worker, action, grant) -> fresh bundle export, fresh gate,
  pin + admit + challenge + worker-signed presentation + evaluate.
  ALLOWED -> (ALLOW, ALLOW); the gate's signed ALLOWED action receipt is
  appended to effects(). STOPPED -> (DENY, reason) with the closed
  vocabulary mapping MANDATE_REVOKED -> REVOKED and
  PRESENTATION_REPLAYED -> REPLAY. Any other STOPPED reason raises
  loudly: the closed vocabulary has no mapping for it, and inventing one
  would be adapter overreach (NEUTRALITY-AUDIT.md rule 5).
- effects() -> the gate's own signed ALLOWED action receipts, persisted
  under the workdir so the harness's restart canary observes the
  candidate's real durability (wallet state on disk), not a re-seeded log.
- restart() -> drop all cached wallets and gates; subsequent calls re-open
  the wallet from its own disk store. The candidate keeps no revocation or
  grant state in memory that it would not keep itself.

Deliberately unimplemented (NEUTRALITY-AUDIT.md: UNSUPPORTED, never
adapter-rescued; these steps are expected to fail on the merits, honestly):
- P4 owner-key rotation with the standing/history split. The wallet has no
  rotation API (epoch certificates are sequence-1, root keys are never
  rotated) and the gate's pin_principal raises PINNED_ROOT_CONFLICT on a
  root change. The closest native operation is owner succession by new
  principal: a fresh wallet for the new owner. Old-owner mandates remain
  valid under the old pin -- the candidate has no STALE_OWNER concept.
  S10 is therefore expected to return (ALLOW, ALLOW, +1) instead of
  (DENY, STALE_OWNER, +0). replace_owner_key with an old_owner that is not
  the current owner raises ValueError: fail-closed, no phantom succession.
- P5 single-use consumption. Mandates carry no single-use flag; only gate
  challenges are one-use, and those are per-presentation, not per-mandate.
  A faithful driver issues a fresh challenge per attempt (that is what a
  real worker does), so presenting the same mandate twice is ALLOWED twice
  by the candidate's own code. S15 is therefore expected to return
  (ALLOW, ALLOW, +1) instead of (DENY, REPLAY, +0). The single_use flag on
  delegate() is recorded in the driver's grant registry and otherwise
  ignored: it changes nothing about candidate behavior.

Grant-model translation (disclosed, not hidden): AACB grants are per-action
(worker-W can hold read-sensor and spend-10 as independent grants); wallet
mandates are per-subject with a scope set, and the candidate natively
refuses a second active mandate for the same subject
(SUBJECT_ALREADY_HAS_ACTIVE_MANDATE; narrow() enforces NARROW_SCOPE_EXPANDED,
so there is no native "add a capability" operation). The driver therefore
namespaces subjects per grant -- worker-W.1, worker-W.2, ... -- all bound to
the same worker keypair (same holder, cryptographically). This is driver-side
bookkeeping, like the grant registry itself: it performs no unrequested
owner operation (no invented revocation), alters no authorization decision,
and every attempt still runs the candidate's real signature, scope,
revocation, and expiry checks. The alternative -- revoke-then-regrant inside
delegate() -- would put words in the owner's mouth.

What the adapter must not do (and does not): keep its own revocation list,
re-seed state across restart from its own log, invent supersession or
consumption semantics, weaken the candidate, or precompute outcomes. Every
attempt drives the candidate live.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

WALLET_SRC = Path("/home/hatch/workspace/closure-audit/repos/openline-wallet/src")
sys.path.insert(0, str(WALLET_SRC))

from openline_wallet.clock import utc_now  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from openline_wallet.errors import WalletError  # noqa: E402
from openline_wallet.receiver import (  # noqa: E402
    ReferenceGate,
    create_presentation,
)
from openline_wallet.wallet import Wallet  # noqa: E402

REASON_MAP = {
    "MANDATE_REVOKED": "REVOKED",
    "PRESENTATION_REPLAYED": "REPLAY",
}


def _load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def _save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class Driver:
    """AACB-003 driver protocol over the OpenLine wallet + ReferenceGate."""

    def __init__(self, workdir: str | Path):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._wallets: dict[str, Wallet] = {}
        self._workers: dict[str, str] = _load_json(self.workdir / "workers.json", {})
        self._grants: dict[str, dict] = _load_json(self.workdir / "grants.json", {})
        self._effects: list = _load_json(self.workdir / "effects.json", [])
        meta = _load_json(self.workdir / "meta.json", {})
        self._current_owner: str | None = meta.get("current_owner")

    # -- driver-local persistence -------------------------------------------
    def _save_meta(self) -> None:
        _save_json(self.workdir / "meta.json", {"current_owner": self._current_owner})

    def _save_effects(self) -> None:
        _save_json(self.workdir / "effects.json", self._effects)

    # -- candidate access ----------------------------------------------------
    def _wallet(self, owner: str) -> Wallet:
        if owner not in self._wallets:
            self._wallets[owner] = Wallet.open(self.workdir / "wallets" / owner)
        return self._wallets[owner]

    def _worker_key(self, worker: str) -> Ed25519PrivateKey:
        hexkey = self._workers.get(worker)
        if hexkey is None:
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex()
            self._workers[worker] = raw
            _save_json(self.workdir / "workers.json", self._workers)
            return key
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hexkey))

    # -- driver protocol ------------------------------------------------------
    def delegate(self, owner: str, worker: str, action: str, single_use: bool) -> str:
        if self._current_owner is None:
            self._current_owner = owner
            self._save_meta()
        if owner != self._current_owner:
            raise ValueError(f"delegate: {owner!r} is not the current owner")
        wallet_dir = self.workdir / "wallets" / owner
        if owner not in self._wallets:
            wallet = Wallet.create(wallet_dir, label=f"AACB self-conformance ({owner})")
            self._wallets[owner] = wallet
        else:
            wallet = self._wallets[owner]
        worker_key = self._worker_key(worker)
        # Per-grant subject namespace: the candidate allows one active
        # mandate per subject; AACB grants are per-action. All subjects of
        # one worker share the worker's keypair (same holder).
        seq = sum(1 for r in self._grants.values() if r.get("worker") == worker) + 1
        subject = f"{worker}.{seq}"
        event = wallet.grant(
            subject_id=subject,
            subject_public_key=public_key_hex(worker_key),
            scopes=[action],
            expires_at=utc_now() + timedelta(days=1),
        )
        mandate_id = event["data"]["mandate_id"]
        self._grants[mandate_id] = {
            "owner": owner,
            "worker": worker,
            "subject": subject,
            "action": action,
            "single_use_requested": bool(single_use),
            # No native single-use mandate primitive exists; recorded only.
            "single_use_native": False,
        }
        _save_json(self.workdir / "grants.json", self._grants)
        return mandate_id

    def revoke(self, owner: str, grant_token: str) -> None:
        if owner != self._current_owner:
            raise ValueError(f"revoke: {owner!r} is not the current owner")
        self._wallet(owner).revoke(grant_token)

    def replace_owner_key(self, old_owner: str, new_owner: str) -> None:
        # No native key-rotation/supersession primitive exists. Closest native
        # operation: owner succession by new principal (fresh wallet). Old-owner
        # mandates keep their standing: the candidate has no STALE_OWNER.
        if old_owner != self._current_owner:
            raise ValueError(
                f"replace_owner_key: {old_owner!r} is not the current owner; "
                "refusing phantom succession"
            )
        wallet_dir = self.workdir / "wallets" / new_owner
        new_wallet = Wallet.create(wallet_dir, label=f"AACB self-conformance ({new_owner})")
        self._wallets[new_owner] = new_wallet
        self._current_owner = new_owner
        self._save_meta()

    def restart(self) -> None:
        # Drop every in-memory handle. Wallets re-open from their own disk
        # store; the gate is rebuilt per attempt from fresh bundle exports.
        self._wallets = {}

    def attempt(self, worker: str, action: str, grant_token: str) -> tuple[str, str]:
        record = self._grants.get(grant_token)
        if record is None:
            raise ValueError(f"attempt: unknown grant {grant_token!r}")
        owner = record["owner"]
        subject = record["subject"]
        worker = record["worker"]
        wallet = self._wallet(owner)
        bundle = wallet.export_bundle()
        gate = ReferenceGate("aacb-self-gate")
        gate.pin_principal(wallet.principal_id, wallet.root_public_key)
        gate.admit_bundle(bundle)
        challenge = gate.issue_challenge(
            principal_id=wallet.principal_id,
            subject_id=subject,
            action=action,
        )
        presentation = create_presentation(
            bundle=bundle,
            mandate_id=grant_token,
            subject_id=subject,
            subject_key=self._worker_key(worker),
            action=action,
            receiver_challenge=challenge,
        )
        receipt = gate.evaluate(presentation, expected_action=action)
        decision = receipt.get("decision")
        if decision == "ALLOWED":
            self._effects.append(receipt)
            self._save_effects()
            return ("ALLOW", "ALLOW")
        if decision == "STOPPED":
            reasons = receipt.get("reason_codes") or []
            native = reasons[0] if reasons else "UNKNOWN"
            mapped = REASON_MAP.get(native)
            if mapped is None:
                raise WalletError(
                    "ADAPTER_REASON_UNMAPPABLE",
                    f"candidate stopped with {native!r}; closed vocabulary has no "
                    "mapping and inventing one is forbidden",
                )
            return ("DENY", mapped)
        raise WalletError("ADAPTER_DECISION_UNKNOWN", f"candidate decided {decision!r}")

    def effects(self) -> tuple:
        # The gate's own signed ALLOWED action receipts, reloaded from the
        # workdir so the harness's restart canary observes persisted state.
        self._effects = _load_json(self.workdir / "effects.json", [])
        return tuple(self._effects)
