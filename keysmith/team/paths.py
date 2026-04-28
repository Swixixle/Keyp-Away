"""Conventional paths under a project root."""

from __future__ import annotations

from pathlib import Path


def keysmith_dir(root: Path) -> Path:
    return root / ".keysmith"


def team_yaml(root: Path) -> Path:
    return keysmith_dir(root) / "team.yaml"


def credentials_yaml(root: Path) -> Path:
    return keysmith_dir(root) / "credentials.yaml"


def rotation_policy_yaml(root: Path) -> Path:
    return keysmith_dir(root) / "rotation-policy.yaml"


def secrets_dir(root: Path) -> Path:
    return keysmith_dir(root) / "secrets"


def team_receipts_dir(root: Path) -> Path:
    return root / ".keysmith-receipts"


def team_events_path(root: Path) -> Path:
    return team_receipts_dir(root) / "events.jsonl"
