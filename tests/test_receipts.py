"""Tests for Ed25519 receipt signing."""

from __future__ import annotations

from pathlib import Path

import pytest

from keysmith.receipts.signing import ReceiptSigner, ReceiptLog


@pytest.fixture
def memory_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict[str, str] = {}

    def gp(service: str, name: str) -> str | None:
        return store.get(f"{service}::{name}")

    def sp(service: str, name: str, pwd: str) -> None:
        store[f"{service}::{name}"] = pwd

    monkeypatch.setattr("keysmith.receipts.signing.keyring.get_password", gp)
    monkeypatch.setattr("keysmith.receipts.signing.keyring.set_password", sp)


def test_sign_and_verify_receipt(memory_keyring: None) -> None:
    signer = ReceiptSigner("demo_proj")
    r = signer.sign_event(
        "credential_connected",
        "sec://demo_proj/x/api-key",
        {"fingerprint": "abc", "action": "store"},
    )
    assert r["public_key"]
    assert r["signature"]
    assert signer.verify_receipt(r) is True

    tampered = dict(r)
    tampered["metadata"] = {"nope": True}
    assert signer.verify_receipt(tampered) is False


def test_receipt_jsonl_roundtrip(memory_keyring: None, tmp_path: Path) -> None:
    signer = ReceiptSigner("p2")
    log = ReceiptLog("p2")
    log.log_path = tmp_path / "z.jsonl"

    rec = signer.sign_event("credential_injected", "sec://p2/foo/api-key", {"target_env": "X"})
    log.append(rec)
    loaded = log.read_all()
    assert len(loaded) == 1
    signer_check = ReceiptSigner("p2")
    assert signer_check.verify_receipt(loaded[0]) is True
