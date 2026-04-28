"""Heuristic over-scoped API key warnings (read-only code vs broadly-scoped keys)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from keysmith.providers.loader import load_provider_registry
from keysmith.scanner.detector import scan_project

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".nox",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
    },
)

_WRITE_PATTERN = re.compile(
    r"(?:\.(?:post|put|delete|patch)\s*\()"
    r"|(?:httpx\.(?:post|put|delete|patch))"
    r"|(?:requests\.(?:post|put|delete|patch))",
    re.MULTILINE,
)

_ADMIN_PATTERN = re.compile(
    r"(?:/admin/)|(?:/sudo/)|(?:X-Admin-[A-Za-z])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScopeWarning:
    credential_name: str
    env_var: str
    assumed_key_scope: str
    required_scope: str
    severity: str
    recommendation: str


def _walk_py(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        files.append(p)
    return sorted(files)


def detect_scope_from_usage(project_root: Path) -> str:
    """Return coarse required scope: ``read`` / ``write`` / ``admin`` based on usage patterns."""
    has_write = False
    has_admin = False
    for py in _walk_py(project_root.resolve()):
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _ADMIN_PATTERN.search(text):
            has_admin = True
        if _WRITE_PATTERN.search(text):
            has_write = True
    if has_admin:
        return "admin"
    if has_write:
        return "write"
    return "read"


def _scope_rank(s: str) -> int:
    return {"read": 1, "write": 2, "admin": 3}.get(s, 1)


def check_scope_overuse(project_root: Path) -> list[ScopeWarning]:
    """Warn when provider keys are likely broader than code needs (heuristic)."""
    manifest = scan_project(project_root)
    providers = load_provider_registry().get("providers", {}) or {}
    required = detect_scope_from_usage(project_root)
    warnings: list[ScopeWarning] = []

    # Without API introspection we assume issued keys are commonly read+write.
    assumed_key_scope = "write"

    for cred_name, cred_info in manifest.credentials.items():
        if not cred_info.provider:
            continue
        pdata = providers.get(cred_info.provider)
        if not pdata:
            continue
        scopes = pdata.get("scopes")
        if not scopes:
            continue

        if _scope_rank(assumed_key_scope) > _scope_rank(required) and required == "read":
            pname = str(pdata.get("name", cred_info.provider))
            warnings.append(
                ScopeWarning(
                    credential_name=cred_name,
                    env_var=cred_info.env,
                    assumed_key_scope=assumed_key_scope,
                    required_scope=required,
                    severity="medium",
                    recommendation=(
                        f"If {pname} supports read-only credentials, create one; code looks read-only."
                    ),
                )
            )

    return warnings
