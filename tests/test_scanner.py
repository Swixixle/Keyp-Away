"""Tests for credential scanner."""

from pathlib import Path

from keysmith.scanner.detector import (
    detect_env_vars_from_code,
    read_env_file,
    scan_project,
)


def test_read_env_file_presence_only(tmp_path) -> None:
    (tmp_path / ".env").write_text('MY_KEY="secret-value"\n# c\nBLANK=\nFOO=REPLACE_ME\n', encoding="utf-8")
    got = read_env_file(tmp_path)
    assert got.get("MY_KEY") == "present"
    assert "BLANK" not in got
    assert "FOO" not in got


def test_detect_env_vars_from_os_getenv() -> None:
    code = """
    import os
    api_key = os.getenv("FEC_API_KEY")
    """
    detected = detect_env_vars_from_code(code)
    assert "FEC_API_KEY" in detected


def test_scan_generates_manifest() -> None:
    root = Path(__file__).resolve().parents[1] / "examples" / "open-case"
    manifest = scan_project(root)
    assert manifest.project == "open-case"
    assert "fec" in manifest.credentials
    assert manifest.credentials["fec"].env == "FEC_API_KEY"
    assert "congress" in manifest.credentials
    assert manifest.credentials["congress"].env == "CONGRESS_API_KEY"
    assert manifest.env_file_vars.get("FEC_API_KEY") == "present"
