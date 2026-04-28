"""Pytest defaults: isolate KeySmith metadata under a temp home directory."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_keysmith_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid writing ``~/.keysmith`` into the developer's real home during tests."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
