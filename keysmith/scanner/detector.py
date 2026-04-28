"""Scan Python projects for credential requirements."""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from keysmith.models import CredentialEntry, CredentialManifest
from keysmith.providers.loader import provider_for_env_name

# Pip packages → extra env hints (medium signal).
_PACKAGE_ENV_HINTS: dict[str, list[str]] = {
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "perplexity-ai": ["PERPLEXITY_API_KEY"],
}

# Regex patterns for env names (supplement AST).
_EXTRA_ENV_PATTERNS = [
    re.compile(r'os\.getenv\s*\(\s*["\']([A-Z][A-Z0-9_]*)["\']'),
    re.compile(r'os\.environ\.get\s*\(\s*["\']([A-Z][A-Z0-9_]*)["\']'),
    re.compile(r'os\.environ\s*\[\s*["\']([A-Z][A-Z0-9_]*)["\']'),
]

_SETTINGS_ATTR = re.compile(r"\bSettings\.([a-z][a-z0-9_]*)")


def settings_field_to_env_name(field: str) -> str:
    """Infer env-style name from a Pydantic Settings attribute (e.g. fec_api_key -> FEC_API_KEY)."""
    parts = field.split("_")
    if len(parts) >= 3 and parts[-2:] == ["api", "key"]:
        head = "_".join(parts[:-2]).upper()
        return f"{head}_API_KEY"
    if len(parts) >= 2 and parts[-1] == "key":
        return "_".join(parts[:-1]).upper() + "_KEY"
    return field.upper()


def detect_env_vars_from_ast(source: str) -> list[str]:
    """AST visitor for getenv / environ lookups."""
    out: list[str] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            out.extend(_extract_from_call(node))
        elif isinstance(node, ast.Subscript):
            out.extend(_extract_from_subscript(node))
    return out


def _extract_from_call(node: ast.Call) -> list[str]:
    envs: list[str] = []
    func = node.func

    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "os" and func.attr == "getenv" and node.args:
            v = _const_str(node.args[0])
            if v:
                envs.append(v)

    if isinstance(func, ast.Attribute) and func.attr == "get":
        if isinstance(func.value, ast.Attribute):
            inn = func.value
            if (
                inn.attr == "environ"
                and isinstance(inn.value, ast.Name)
                and inn.value.id == "os"
                and node.args
            ):
                v = _const_str(node.args[0])
                if v:
                    envs.append(v)
    return envs


def _extract_from_subscript(node: ast.Subscript) -> list[str]:
    envs: list[str] = []
    if isinstance(node.value, ast.Attribute):
        if (
            isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            envs.append(node.slice.value)
    return envs


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def detect_authorization_bearer_envs(source: str) -> list[str]:
    """Best-effort: Bearer {var} patterns in Authorization headers."""
    out: list[str] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, val in zip(node.keys, node.values, strict=False):
            key = _expr_str_maybe(k)
            if key and key.lower() == "authorization":
                out.extend(_env_names_in_expr(val))

    for m in re.finditer(
        r'Authorization["\']\s*:\s*["\']Bearer\s*\{([^}]+)\}',
        source,
        re.I,
    ):
        inner = m.group(1).strip()
        parts = inner.split(".")
        outer = parts[-1].strip() if parts else inner
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", outer):
            u = outer.upper()
            if "_" in outer or u.endswith(("KEY", "TOKEN")):
                out.append(u)
    return out


def _expr_str_maybe(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _env_names_in_expr(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    envs: list[str] = []
    if isinstance(node, ast.JoinedStr):
        for p in node.values:
            if isinstance(p, ast.FormattedValue):
                envs.extend(_env_names_in_expr(p.value))
    elif isinstance(node, ast.Name):
        nid = node.id.upper()
        if "_TOKEN" in nid or "_KEY" in nid or nid.endswith("TOKEN"):
            envs.append(nid)
    elif isinstance(node, ast.Attribute):
        au = node.attr.upper()
        if "KEY" in au or au.endswith("TOKEN"):
            envs.append(au)
    return envs


def detect_env_vars_from_code(source: str) -> list[str]:
    """Combined AST + regex detection for Python source."""
    seen: set[str] = set()
    out: list[str] = []

    def add_many(items: list[str]) -> None:
        for x in items:
            u = x.strip()
            if u and u not in seen and _looks_like_env_name(u):
                seen.add(u)
                out.append(u)

    add_many(detect_env_vars_from_ast(source))
    add_many(detect_authorization_bearer_envs(source))
    cleaned = source.replace("\\\n", "\n")
    for pat in _EXTRA_ENV_PATTERNS:
        add_many(pat.findall(cleaned))
    for m in _SETTINGS_ATTR.finditer(cleaned):
        add_many([settings_field_to_env_name(m.group(1))])
    # pytest.skipif referencing getenv
    for pm in re.finditer(
        r"pytest\.mark\.skipif\s*\(.*os\.(?:getenv|environ(?:\.get)?)\s*\(\s*[\"']([A-Z][A-Z0-9_]*)",
        cleaned,
        re.DOTALL,
    ):
        add_many([pm.group(1)])

    return out


def _looks_like_env_name(name: str) -> bool:
    return bool(name) and name.replace("_", "").isalnum() and name.upper() == name


def detect_env_vars(file_path: Path) -> list[str]:
    """Extract env var names from a Python file."""
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return detect_env_vars_from_code(text)


def parse_env_example(file_path: Path) -> dict[str, str]:
    """Parse .env.example for KEY=value pairs."""
    out: dict[str, str] = {}
    raw = file_path.read_text(encoding="utf-8", errors="replace")
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        key = line.split("=", 1)[0].strip()
        if key and key.isupper():
            out[key.upper()] = ""
        elif key:
            ku = key.upper()
            out[ku.replace("-", "_")] = ""
    return out


def parse_dockerfile_env(file_path: Path) -> list[str]:
    envs: list[str] = []
    for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("ENV "):
            rest = stripped[4:].strip()
            for part in rest.split():
                if "=" in part:
                    name, _, _rest = part.partition("=")
                    n = name.strip()
                    if n and (_looks_like_env_name(n.upper()) or n.upper() == n):
                        envs.append(n.upper())
    return envs


def _parse_requirements(path: Path) -> list[str]:
    pkgs: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        name = line.split("[")[0].split("=")[0].split("<")[0].split(">")[0].strip().lower()
        if name:
            pkgs.append(name)
    return pkgs


def env_name_to_cred_key(env_name: str) -> str:
    """Stable manifest key slug (FEC_API_KEY -> fec)."""
    u = env_name.upper()
    for suffix in ("_API_KEY", "_TOKEN", "_SECRET", "_KEY"):
        if u.endswith(suffix):
            base = u[: -len(suffix)]
            break
    else:
        base = u
    parts = [p.lower() for p in base.split("_") if p]
    if not parts:
        return env_name.lower()
    return "_".join(parts)


_EXCLUDE_DIRS = frozenset(
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
    }
)


_LOGGER = logging.getLogger(__name__)

# Later .env layers override earlier (.env.example → .env → .env.local).
_ENV_LAYER_FILES = [".env.example", ".env", ".env.local"]

_PLACEHOLDER_TOKENS_LOWER = frozenset(
    {
        "",
        "your-key-here",
        "replace_me",
        "changeme",
        "todo",
        "xxx",
        "placeholder",
        "sk_test_xxx",
    },
)


def _strip_env_value_quotes(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2:
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            return s[1:-1].strip()
    return s.strip()


def _is_placeholder_env_value(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    low = v.lower()
    if low in _PLACEHOLDER_TOKENS_LOWER:
        return True
    if low.startswith("<your") or low.startswith("${") or low == "...":
        return True
    return False


def _parse_env_presence_single(path: Path) -> dict[str, str]:
    """Parse one env file → upper key → literal ``present`` (never secret bytes)."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        _LOGGER.warning("could not read %s: %s", path, e)
        return out

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val_part = line.partition("=")
        k = key.strip()
        if not k:
            continue
        normalized = k.upper().replace("-", "_")
        stripped = _strip_env_value_quotes(val_part)
        if not _is_placeholder_env_value(stripped):
            out[normalized] = "present"
    return out


def read_env_file(project_root: Path) -> dict[str, str]:
    """Read existing env files for **presence** only (order: example → .env → .env.local).

    Returns ``var_name_upper -> \"present\"``. Never includes actual values.
    """
    merged: dict[str, str] = {}
    for name in _ENV_LAYER_FILES:
        env_path = project_root / name
        if not env_path.is_file():
            continue
        try:
            merged.update(_parse_env_presence_single(env_path))
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("could not read %s: %s", env_path, e)

    return merged


def _scan_dir_ok(path: Path) -> bool:
    return not any(part in _EXCLUDE_DIRS for part in path.parts)


def _line_for_needle(text: str, needle: str) -> int | None:
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return None


def scan_project(root_path: Path) -> CredentialManifest:
    """Scan project for credential requirements."""
    root = root_path.resolve()
    project_name = root.name or "detected-project"
    credential_map: dict[str, CredentialEntry] = {}

    def merge(
        env_name: str,
        detected_loc: str,
        required_file: str | None,
        provider_slug: str | None = None,
    ) -> None:
        key = env_name_to_cred_key(env_name)
        prov = provider_slug or provider_for_env_name(env_name)
        if key not in credential_map:
            credential_map[key] = CredentialEntry(env=env_name, provider=prov)
        ent = credential_map[key]
        if detected_loc and detected_loc not in ent.detected_in:
            ent.detected_in = [*ent.detected_in, detected_loc]
        if required_file and required_file not in ent.required_for:
            ent.required_for = [*ent.required_for, required_file]
        if prov and ent.provider is None:
            ent.provider = prov

    py_files = sorted(p for p in root.rglob("*.py") if _scan_dir_ok(p))

    for py in py_files:
        try:
            rel_ref = py.relative_to(root).as_posix()
        except ValueError:
            rel_ref = py.name
        content = py.read_text(encoding="utf-8", errors="replace")
        for env_name in detect_env_vars_from_code(content):
            line_no = _line_for_needle(content, env_name)
            loc = f"{rel_ref}:{line_no}" if line_no else f"{rel_ref}:1"
            merge(env_name, loc, rel_ref)

    env_example = root / ".env.example"
    if env_example.is_file():
        for k in parse_env_example(env_example):
            merge(k, ".env.example", None)

    for df in ("Dockerfile", "dockerfile"):
        dp = root / df
        if dp.is_file():
            for env_name in parse_dockerfile_env(dp):
                merge(env_name, df, None)

    for req_name in ("requirements.txt", "requirements-dev.txt"):
        rp = root / req_name
        if rp.is_file():
            for pkg in _parse_requirements(rp):
                for hint in _PACKAGE_ENV_HINTS.get(pkg, []):
                    merge(hint, req_name, None)

    for ent in credential_map.values():
        ent.detected_in = sorted(set(ent.detected_in))

    env_file_vars = read_env_file(root)

    return CredentialManifest(
        project=project_name,
        credentials=credential_map,
        env_file_vars=env_file_vars,
    )
