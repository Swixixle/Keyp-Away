"""Rotation reminders stored under ``~/.keysmith/rotation.json``."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class RotationPolicy:
    handle: str
    rotation_days: int
    last_rotated: str
    next_rotation: str
    auto_rotate: bool = False


class RotationScheduler:
    def __init__(self, storage_path: Path | None = None) -> None:
        self.storage_path = storage_path or (Path.home() / ".keysmith" / "rotation.json")
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, RotationPolicy]:
        if not self.storage_path.exists():
            return {}
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

        out: dict[str, RotationPolicy] = {}
        for handle, row in raw.items():
            if not isinstance(row, dict):
                continue
            row.setdefault("auto_rotate", False)
            try:
                out[handle] = RotationPolicy(**row)
            except TypeError:
                continue
        return out

    def _save(self, data: dict[str, RotationPolicy]) -> None:
        blob = {h: asdict(p) for h, p in data.items()}
        self.storage_path.write_text(json.dumps(blob, indent=2), encoding="utf-8")

    def set_policy(
        self,
        handle: str,
        *,
        rotation_days: int,
        auto_rotate: bool = False,
    ) -> None:
        now = datetime.now()
        delta = timedelta(days=max(1, rotation_days))
        merged = RotationPolicy(
            handle=handle,
            rotation_days=max(1, rotation_days),
            last_rotated=now.isoformat(timespec="seconds"),
            next_rotation=(now + delta).isoformat(timespec="seconds"),
            auto_rotate=auto_rotate,
        )
        all_p = self._load()
        all_p[handle] = merged
        self._save(all_p)

    def mark_rotated(self, handle: str) -> None:
        all_p = self._load()
        if handle not in all_p:
            return
        prev = all_p[handle]
        now = datetime.now()
        merged = RotationPolicy(
            handle=handle,
            rotation_days=prev.rotation_days,
            last_rotated=now.isoformat(timespec="seconds"),
            next_rotation=(now + timedelta(days=prev.rotation_days)).isoformat(timespec="seconds"),
            auto_rotate=prev.auto_rotate,
        )
        all_p[handle] = merged
        self._save(all_p)

    def check_due(self) -> list[RotationPolicy]:
        all_p = self._load()
        now = datetime.now()
        overdue: list[RotationPolicy] = []
        for pol in all_p.values():
            try:
                nxt = datetime.fromisoformat(pol.next_rotation)
            except ValueError:
                continue
            if nxt <= now:
                overdue.append(pol)
        return sorted(overdue, key=lambda pl: pl.next_rotation)

    def get_policy(self, handle: str) -> RotationPolicy | None:
        """Return the saved rotation row for ``handle``, if any."""
        return self._load().get(handle)

    def check_upcoming(self, days: int = 7) -> list[RotationPolicy]:
        """Policies whose next_rotation is between now + epsilon and now + horizon (not overdue)."""
        all_p = self._load()
        now = datetime.now()
        limit = now + timedelta(days=max(1, days))
        rows: list[RotationPolicy] = []
        for pol in all_p.values():
            try:
                nxt = datetime.fromisoformat(pol.next_rotation)
            except ValueError:
                continue
            if nxt <= now:
                continue
            if now < nxt <= limit:
                rows.append(pol)
        return sorted(rows, key=lambda pl: pl.next_rotation)


def check_rotation_status() -> dict[str, list[RotationPolicy]]:
    scheduler = RotationScheduler()
    overdue = scheduler.check_due()
    upcoming = scheduler.check_upcoming(days=7)
    overdue_set = {p.handle for p in overdue}
    upcoming_filtered = [p for p in upcoming if p.handle not in overdue_set]
    return {"overdue": overdue, "upcoming": upcoming_filtered}


def rotation_cli_main() -> int:
    stat = check_rotation_status()
    overdue = stat["overdue"]
    upcoming = stat["upcoming"]
    now = datetime.now()
    ec = 0

    if overdue:
        ec = max(ec, 1)
        print(f"[keysmith] OVERDUE rotations: {len(overdue)}\n")
        for pol in overdue:
            nxt = datetime.fromisoformat(pol.next_rotation)
            drift = (now - nxt).days
            print(f"  {pol.handle}")
            print(f"    Overdue ~{drift} day(s); rotate every {pol.rotation_days} day(s).\n")

    if upcoming:
        print(f"[keysmith] Upcoming rotations (within 7 days): {len(upcoming)}\n")
        for pol in upcoming:
            nxt = datetime.fromisoformat(pol.next_rotation)
            days_until = max(0, (nxt - now).days)
            print(f"  {pol.handle}")
            print(f"    Due in about {days_until} day(s)\n")

    if not overdue and not upcoming:
        print("[keysmith] No rotation policies overdue or due in the next 7 days.")

    return ec


if __name__ == "__main__":
    sys.exit(rotation_cli_main())
