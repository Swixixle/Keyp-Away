"""Tests for credential broker."""

import json
import os
from pathlib import Path

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
    ok, err = broker.inject("sec://open-case/fec/api-key", "FEC_API_KEY")
    assert ok and err is None
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


def test_slug_from_handle_uri() -> None:
    from keysmith.broker.vault import slug_from_handle_uri

    assert slug_from_handle_uri("sec://open-case/fec/api-key") == "fec"


@pytest.mark.usefixtures("fake_secret")
def test_inject_blocked_when_enforced_overdue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake_secret: None,
) -> None:
    kd = tmp_path / ".keysmith"
    kd.mkdir(parents=True)
    (kd / "rotation-policy.yaml").write_text(
        "settings:\n  enforce: true\n  grace_period_days: 7\npolicies:\n  fec: {rotation_days: 90}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "homedir"
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    smith = home / ".keysmith"
    smith.mkdir()
    handle_uri = "sec://open-case/fec/api-key"
    rot = {
        handle_uri: {
            "handle": handle_uri,
            "rotation_days": 30,
            "last_rotated": "2020-01-01T00:00:00",
            "next_rotation": "2020-01-10T00:00:00",
        }
    }
    (smith / "rotation.json").write_text(json.dumps(rot), encoding="utf-8")

    broker = CredentialBroker()
    ok, err = broker.inject(handle_uri, "FEC_API_KEY")
    assert ok is False
    assert err and "OVERDUE" in err


@pytest.mark.usefixtures("fake_secret")
def test_inject_skips_rotation_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake_secret: None,
) -> None:
    kd = tmp_path / ".keysmith"
    kd.mkdir(parents=True)
    (kd / "rotation-policy.yaml").write_text(
        "settings:\n  enforce: true\npolicies:\n  fec: {rotation_days: 90}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "homedir"
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    smith = home / ".keysmith"
    smith.mkdir()
    handle_uri = "sec://open-case/fec/api-key"
    rot = {
        handle_uri: {
            "handle": handle_uri,
            "rotation_days": 30,
            "last_rotated": "2020-01-01T00:00:00",
            "next_rotation": "2020-01-10T00:00:00",
        }
    }
    (smith / "rotation.json").write_text(json.dumps(rot), encoding="utf-8")

    broker = CredentialBroker()
    ok, err = broker.inject(handle_uri, "FEC_VAR", skip_rotation_check=True)
    assert ok is True and err is None
