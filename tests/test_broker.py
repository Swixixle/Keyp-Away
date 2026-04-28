"""Tests for credential broker."""

import os

import pytest

from keysmith.broker.vault import CredentialBroker


@pytest.fixture
def fake_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "keysmith.broker.vault.keyring.get_password",
        lambda service, uri: "supersecret-value" if "fec/api-key" in uri else None,
    )


def test_verify_returns_handle_not_secret(fake_secret: None) -> None:
    broker = CredentialBroker()
    result = broker.verify("sec://open-case/fec/api-key")

    assert "fingerprint" in result.__dict__ or hasattr(result, "fingerprint")
    assert result.status == "valid"
    assert getattr(result, "raw_value", None) is None
    dumped = repr(result)
    assert "supersecret" not in dumped


@pytest.mark.usefixtures("fake_secret")
def test_inject_sets_env_var() -> None:
    broker = CredentialBroker()
    old = dict(os.environ)
    broker.inject("sec://open-case/fec/api-key", "FEC_API_KEY")
    assert os.environ.get("FEC_API_KEY") == "supersecret-value"
    os.environ.clear()
    os.environ.update(old)


def test_verify_present_dotenv_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "keysmith.broker.vault.keyring.get_password",
        lambda service, uri: None,
    )
    broker = CredentialBroker()
    r = broker.verify("sec://p/fec/api-key", dotenv_reports_present=True)
    assert r.status == "present_dotenv"
