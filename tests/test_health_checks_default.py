"""Health checks default behaviour (v0.6.0+) and generate-manifest."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from keysmith.cli.main import cli


def _minimal_fec_project(tmp: Path) -> None:
    (tmp / "main.py").write_text(
        'import os\n_os = os.getenv("FEC_API_KEY")\n',
        encoding="utf-8",
    )
    # Presence map for dotenv overlays (parity with scan_project reads)
    (tmp / ".env").write_text("FEC_API_KEY=placeholder-secret\n", encoding="utf-8")


def test_doctor_health_metadata_present(tmp_path: Path, monkeypatch) -> None:
    """Doctor labels HTTP probes when registry lists an endpoint."""

    monkeypatch.chdir(tmp_path)
    _minimal_fec_project(tmp_path)

    def _fake_pw(service: str, uri: str) -> str | None:
        return "test-key-ring" if "fec/api-key" in uri else None

    monkeypatch.setattr("keysmith.broker.vault.keyring.get_password", _fake_pw)

    monkeypatch.setattr(
        "keysmith.providers.loader.run_health_check",
        lambda _p, _k: True,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "health ok" in out or "credential status" in out


def test_doctor_skip_health_shows_tip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _minimal_fec_project(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--skip-health"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "skipped" in out or "tip" in out


def test_summary_skip_health_shows_tip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _minimal_fec_project(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["summary", "--skip-health"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "skipped" in out or "tip" in out


def test_summary_counts_valid_when_health_ok(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _minimal_fec_project(tmp_path)

    monkeypatch.setattr(
        "keysmith.broker.vault.keyring.get_password",
        lambda service, uri: "k" if "fec/api-key" in uri else None,
    )
    monkeypatch.setattr("keysmith.providers.loader.run_health_check", lambda _p, _k: True)

    runner = CliRunner()
    result = runner.invoke(cli, ["summary"])
    assert result.exit_code == 0
    assert "validated" in result.output.lower()


def test_generate_manifest_creates_yaml(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _minimal_fec_project(tmp_path)

    monkeypatch.setattr(
        "keysmith.broker.vault.keyring.get_password",
        lambda service, uri: None,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["generate-manifest", "--skip-health"])
    assert result.exit_code == 0

    manifest_path = tmp_path / ".keysmith" / "credentials.yaml"
    assert manifest_path.is_file()

    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert data.get("project")
    assert "credentials" in data
    assert "generated" in data
    assert "fec" in data["credentials"]
