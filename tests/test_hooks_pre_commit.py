"""Tests for pre-commit secret scanner."""

from pathlib import Path

from keysmith.hooks.pre_commit import scan_file_for_secrets


def test_scan_finds_github_token(tmp_path: Path) -> None:
    p = tmp_path / "leak.py"
    p.write_text('token = "ghp_' + "a" * 36 + '"\n', encoding="utf-8")
    hits = scan_file_for_secrets(p)
    assert hits
    assert any("GitHub" in h[0] for h in hits)


def test_scan_clean_file(tmp_path: Path) -> None:
    p = tmp_path / "ok.py"
    p.write_text("print('hello world')\n", encoding="utf-8")
    assert scan_file_for_secrets(p) == []
