"""Tests for credential scanner."""

from pathlib import Path

from keysmith.scanner.detector import detect_env_vars_from_code, scan_project


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
