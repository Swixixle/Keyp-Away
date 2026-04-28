"""Tests for usage tracker and rotation scheduler."""

import json
from datetime import datetime, timedelta
from pathlib import Path

from keysmith.audit.usage import UsageTracker, check_unused_credentials
from keysmith.rotation.scheduler import RotationPolicy, RotationScheduler


def test_usage_tracker_roundtrip() -> None:
    ut = UsageTracker()
    ut.record_access("sec://proj/fec/api-key")
    ut.record_access("sec://proj/fec/api-key")
    data = ut._load()
    assert data["sec://proj/fec/api-key"].access_count == 2


def test_unused_threshold() -> None:
    meta = Path.home() / ".keysmith"
    meta.mkdir(parents=True, exist_ok=True)
    store = meta / "usage_stale.json"
    old = (datetime.now() - timedelta(days=100)).isoformat(timespec="seconds")
    payload = {
        "sec://ghost/x/api-key": {
            "handle": "sec://ghost/x/api-key",
            "last_accessed": old,
            "access_count": 1,
            "first_seen": old,
        }
    }
    store.write_text(json.dumps(payload), encoding="utf-8")

    rows = check_unused_credentials(storage_path=store, days=90)
    assert any("ghost" in h for h, _ in rows)


def test_rotation_overdue() -> None:
    tmp = Path.home() / ".keysmith" / "rotation_test.json"
    sched = RotationScheduler(storage_path=tmp)
    past = (datetime.now() - timedelta(days=1)).isoformat(timespec="seconds")
    sched._save(
        {
            "sec://p/fec/api-key": RotationPolicy(
                handle="sec://p/fec/api-key",
                rotation_days=30,
                last_rotated=past,
                next_rotation=past,
                auto_rotate=False,
            )
        }
    )
    due = sched.check_due()
    assert due and due[0].handle == "sec://p/fec/api-key"
