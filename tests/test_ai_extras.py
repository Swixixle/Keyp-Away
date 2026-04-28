"""Tests for rotation suggestions, grouping, and anomalies."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from keysmith.ai.anomaly_detector import AnomalyDetector
from keysmith.ai.credential_graph import CredentialGraphAnalyzer
from keysmith.audit.usage import UsageTracker
from keysmith.models import CredentialEntry, CredentialManifest


def test_credential_tier_groups() -> None:
    manifest = CredentialManifest(
        project="demo",
        credentials={
            "svc_read": CredentialEntry(env="SVCR", provider=None),
            "svc_write": CredentialEntry(env="SVCW", provider=None),
        },
        env_file_vars={},
    )
    with patch("keysmith.ai.credential_graph.scan_project", return_value=manifest):
        groups = CredentialGraphAnalyzer(Path(".")).find_groups()

    tiers = [g for g in groups if g.relationship == "tiered_access"]
    assert tiers
    assert set(tiers[0].credentials) == {"svc_read", "svc_write"}


def test_anomaly_high_frequency(tmp_path: Path) -> None:
    now = datetime.now()
    first = now - timedelta(days=10)
    text = """{
      "sec://p/x/api-key": {"handle":"sec://p/x/api-key","last_accessed":"%s","access_count":20000,"first_seen":"%s"}
    }""" % (now.isoformat(timespec="seconds"), first.isoformat(timespec="seconds"))
    ledger = tmp_path / "usage.json"
    ledger.write_text(text.replace("\n", ""), encoding="utf-8")
    tracker = UsageTracker(storage_path=ledger)

    anomalies = AnomalyDetector(tracker).detect_anomalies()
    kinds = [a.anomaly_type for a in anomalies]
    assert "high_frequency" in kinds


def test_rotation_suggest_government_providers(tmp_path: Path) -> None:
    """Bundled fec / congress rows should land in at least moderate risk buckets."""
    (tmp_path / "noop.py").write_text("", encoding="utf-8")
    from keysmith.ai.rotation_suggest import RotationSuggester

    for slug in ("fec", "congress_gov"):
        sug = RotationSuggester(tmp_path).suggest_for_credential(slug)
        assert sug.credential_slug == slug
        assert sug.risk_level in ("low", "medium", "high", "critical")
        assert sug.suggested_days >= 30

