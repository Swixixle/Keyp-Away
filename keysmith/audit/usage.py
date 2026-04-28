"""Local usage ledger for credential handles (`~/.keysmith/usage.json`)."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class CredentialUsage:
    handle: str
    last_accessed: str
    access_count: int
    first_seen: str


class UsageTracker:
    """Track when handles were verified/injected/stored."""

    def __init__(self, storage_path: Path | None = None) -> None:
        self.storage_path = storage_path or (Path.home() / ".keysmith" / "usage.json")
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, CredentialUsage]:
        if not self.storage_path.exists():
            return {}
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

        out: dict[str, CredentialUsage] = {}
        for handle, row in raw.items():
            if not isinstance(row, dict):
                continue
            try:
                out[handle] = CredentialUsage(**row)
            except TypeError:
                continue
        return out

    def _save(self, data: dict[str, CredentialUsage]) -> None:
        blob = {h: asdict(u) for h, u in data.items()}
        self.storage_path.write_text(json.dumps(blob, indent=2), encoding="utf-8")

    def record_access(self, handle: str) -> None:
        """Record interactive use of this handle (no secret bytes persisted)."""
        data = self._load()
        now = datetime.now().isoformat(timespec="seconds")

        cur = data.get(handle)
        if cur is None:
            data[handle] = CredentialUsage(handle=handle, last_accessed=now, access_count=1, first_seen=now)
        else:
            data[handle] = CredentialUsage(
                handle=handle,
                last_accessed=now,
                access_count=cur.access_count + 1,
                first_seen=cur.first_seen,
            )
        self._save(data)

    def find_unused(self, days: int = 90) -> list[tuple[str, CredentialUsage]]:
        cutoff = datetime.now() - timedelta(days=days)
        data = self._load()

        stale: list[tuple[str, CredentialUsage]] = []
        for handle, usage in sorted(data.items()):
            try:
                last = datetime.fromisoformat(usage.last_accessed)
            except ValueError:
                continue
            if last < cutoff:
                stale.append((handle, usage))
        return stale

    def get_usage(self, handle: str) -> CredentialUsage | None:
        return self._load().get(handle)

    def usage_records(self) -> dict[str, CredentialUsage]:
        """Read-only copy of the persisted usage ledger."""
        return dict(self._load())


def check_unused_credentials(
    *,
    storage_path: Path | None = None,
    days: int = 90,
) -> list[tuple[str, int]]:
    """Return `(handle, days_since_last_access)` for stale handles."""
    tracker = UsageTracker(storage_path=storage_path)
    unused = tracker.find_unused(days=days)

    now = datetime.now()
    results: list[tuple[str, int]] = []
    for handle, usage in unused:
        try:
            last_accessed = datetime.fromisoformat(usage.last_accessed)
        except ValueError:
            continue
        days_unused = max(0, (now - last_accessed).days)
        results.append((handle, days_unused))

    return sorted(results, key=lambda x: -x[1])


def main() -> None:
    ap = argparse.ArgumentParser(prog="keysmith-audit-usage")
    ap.add_argument("--days", type=int, default=90)
    ns = ap.parse_args()
    rows = check_unused_credentials(days=ns.days)
    if not rows:
        print(f"[keysmith] No handles unused for {ns.days}+ days (of those tracked).")
        raise SystemExit(0)

    print(f"[keysmith] Stale handles (not accessed in {ns.days}+ days): {len(rows)}\n")
    for handle, drift in rows:
        print(handle)
        print(f"   Last accessed (approx age): {drift} days ago")
        print("   Consider rotating or removing if orphaned.")
        print()
    raise SystemExit(0)


if __name__ == "__main__":
    sys.exit(main())
