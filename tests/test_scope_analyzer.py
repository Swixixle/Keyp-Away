"""Tests for keysmith.ai.scope_analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from keysmith.ai.scope_analyzer import ScopeAnalyzer, analyze_all_scopes


def test_analyze_provider_read_from_get(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        'import httpx\n'
        'httpx.get("https://api.open.fec.gov/v1/candidates/?limit=1")\n',
        encoding="utf-8",
    )
    req = ScopeAnalyzer(tmp_path).analyze_provider("fec")
    assert req.required_scope == "read"
    assert req.evidence
    assert req.evidence[0].method == "GET"


def test_analyze_provider_write_from_post(tmp_path: Path) -> None:
    (tmp_path / "w.py").write_text(
        'import httpx\n'
        'httpx.post("https://api.open.fec.gov/v1/committees/", json={})\n',
        encoding="utf-8",
    )
    req = ScopeAnalyzer(tmp_path).analyze_provider("fec")
    assert req.required_scope == "write"
    assert "POST" in req.reasoning.upper() or req.evidence[0].method == "POST"


def test_regex_fallback_requests(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        'import requests\n'
        'requests.get("https://api.congress.gov/v3/bill?limit=1")\n',
        encoding="utf-8",
    )
    req = ScopeAnalyzer(tmp_path).analyze_provider("congress_gov")
    assert req.required_scope == "read"
    assert req.evidence


def test_unknown_provider_raises() -> None:
    with pytest.raises(ValueError, match="Unknown provider"):
        ScopeAnalyzer(Path(".")).analyze_provider("__not_a_real_provider__")


def test_analyze_all_scopes_filters_low_confidence(tmp_path: Path) -> None:
    """No URLs → default read at 0.5 confidence is omitted from aggregate."""
    assert analyze_all_scopes(tmp_path) == {}
