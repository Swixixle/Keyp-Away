"""Cryptographic receipts for credential events (Ed25519, local append-only logs)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import keyring
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


KEYRING_USERNAME_PREFIX = "receipt-signing-key:"


class ReceiptSigner:
    """Sign credential events with Ed25519."""

    def __init__(self, project_name: str) -> None:
        self.project_name = project_name
        self.private_key = self._load_or_generate_key()
        self.public_key_hex = (
            self.private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
        )

    def _username(self) -> str:
        return f"{KEYRING_USERNAME_PREFIX}{self.project_name}"

    def _load_or_generate_key(self) -> ed25519.Ed25519PrivateKey:
        service = keysmith_keyring_service()
        pem_str = keyring.get_password(service, self._username())
        if pem_str:
            key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
            if isinstance(key, ed25519.Ed25519PrivateKey):
                return key
            raise TypeError("Expected Ed25519 private key in keychain receipt slot")
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        keyring.set_password(service, self._username(), pem.decode("utf-8"))
        return private_key

    def sign_event(
        self,
        event_type: str,
        handle: str,
        metadata: dict[str, Any],
        *,
        actor: str | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now_iso()

        event: dict[str, Any] = {
            "event_type": event_type,
            "handle": handle,
            "metadata": metadata,
            "timestamp": timestamp,
            "project": self.project_name,
        }
        if actor:
            event["actor"] = actor
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")

        receipt = dict(event)
        receipt["signature"] = self.private_key.sign(canonical).hex()
        receipt["signing_scheme"] = "ed25519-sha256canonical-v1"
        receipt["public_key"] = self.public_key_hex
        return receipt

    def verify_receipt(self, receipt: dict[str, Any]) -> bool:
        """Verify using the public key embedded in the receipt (supports old receipts after signer init)."""
        try:
            signature_hex = receipt["signature"]
            public_key_hex = receipt["public_key"]
            allowed = frozenset(
                {"event_type", "handle", "metadata", "timestamp", "project", "actor"}
            )
            event = {k: v for k, v in receipt.items() if k in allowed}
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )

            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pubkey.verify(bytes.fromhex(signature_hex), canonical)
            return True
        except Exception:
            return False


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def keysmith_keyring_service() -> str:
    """Keychain umbrella service — same ``keysmith`` broker service, separate account names."""
    return "keysmith"


class ReceiptLog:
    """Append-only JSONL log keyed by scanned project slug."""

    def __init__(self, project_name: str) -> None:
        self.project_name = project_name
        self.log_path = Path.home() / ".keysmith" / "receipts" / f"{project_name}.jsonl"

    def append(self, receipt: dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt, ensure_ascii=False) + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        receipts: list[dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                receipts.append(json.loads(line))
        return receipts

    def verify_all(self, signer: ReceiptSigner) -> tuple[int, int]:
        receipts = self.read_all()
        valid = 0
        invalid = 0
        for receipt in receipts:
            if signer.verify_receipt(receipt):
                valid += 1
            else:
                invalid += 1
        return valid, invalid


class TeamReceiptLog:
    """Checked-in team audit log under ``.keysmith-receipts/events.jsonl``."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.log_path = self.project_root / ".keysmith-receipts" / "events.jsonl"

    def append(self, receipt: dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt, ensure_ascii=False) + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows
