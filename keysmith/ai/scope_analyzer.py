"""Heuristic scope analysis from detected HTTP patterns in Python source."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from keysmith.providers.loader import load_provider_registry

_SKIP_PATH_PARTS = frozenset(
    {
        ".git",
        ".venv",
        ".tox",
        "venv",
        "node_modules",
        "__pycache__",
        ".nox",
        "dist",
        "build",
    }
)


@dataclass
class APICall:
    """Detected API call shape in Python code."""

    method: str  # GET, POST, PUT, DELETE, PATCH
    endpoint: str
    file: str
    line: int


@dataclass
class ScopeRequirement:
    """Inferred approximate scope tier for issuing or auditing keys."""

    provider: str
    required_scope: Literal["read", "write", "admin"]
    confidence: float  # 0.0 to 1.0
    evidence: list[APICall]
    reasoning: str


class ScopeAnalyzer:
    """Scan Python sources for outbound HTTP usage toward known provider hosts."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.registry = load_provider_registry()

    def analyze_provider(self, provider_slug: str) -> ScopeRequirement:
        """Infer required coarse scope tier for ``provider_slug`` based on traced calls."""

        pdata = self._provider_entry(provider_slug)
        if pdata is None:
            raise ValueError(f"Unknown provider: {provider_slug}")

        api_calls = self._find_api_calls(provider_slug)

        if not api_calls:
            return ScopeRequirement(
                provider=provider_slug,
                required_scope="read",
                confidence=0.5,
                evidence=[],
                reasoning="No API calls found in scanned Python. Defaulting to read-only for safety.",
            )

        methods = {c.method for c in api_calls}
        endpoints = {c.endpoint for c in api_calls}

        admin_patterns = [
            r"/admin/",
            r"/sudo/",
            r"/users/\w+/delete",
            r"/organizations/\w+/members",
        ]
        has_admin = any(any(re.search(p, ep) for p in admin_patterns) for ep in endpoints)

        if has_admin:
            return ScopeRequirement(
                provider=provider_slug,
                required_scope="admin",
                confidence=0.9,
                evidence=api_calls[:5],
                reasoning=(
                    "Admin-shaped paths detected "
                    + f"(e.g. {', '.join(sorted(endpoints)[:3])})."
                ),
            )

        write_methods = {"POST", "PUT", "PATCH", "DELETE"}
        has_write = bool(methods & write_methods)

        if has_write:
            return ScopeRequirement(
                provider=provider_slug,
                required_scope="write",
                confidence=0.85,
                evidence=api_calls[:5],
                reasoning=f"Write methods seen: {', '.join(sorted(methods & write_methods))}.",
            )

        return ScopeRequirement(
            provider=provider_slug,
            required_scope="read",
            confidence=0.95,
            evidence=api_calls[:5],
            reasoning="Only safe read methods observed in traced calls.",
        )

    def _provider_entry(self, provider_slug: str) -> dict[str, Any] | None:
        return self.registry.get("providers", {}).get(provider_slug)

    def _find_api_calls(self, provider_slug: str) -> list[APICall]:
        pdata = self._provider_entry(provider_slug)
        if not pdata:
            return []

        base_urls = self._get_provider_base_urls(pdata)
        seen: set[tuple[str, int, str, str]] = set()
        calls: list[APICall] = []

        for py_file in self._iter_python_files():
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for call in self._parse_file_for_calls(py_file, content, base_urls):
                key = (call.file, call.line, call.method, call.endpoint)
                if key in seen:
                    continue
                seen.add(key)
                calls.append(call)

        return calls

    def _iter_python_files(self) -> list[Path]:
        out: list[Path] = []
        root = self.project_root
        if not root.is_dir():
            return out
        for py_file in root.rglob("*.py"):
            if _SKIP_PATH_PARTS.intersection(py_file.parts):
                continue
            out.append(py_file)
        return out

    def _get_provider_base_urls(self, provider: dict[str, Any]) -> list[str]:
        """Host-level URL prefixes used to attribute calls to this provider."""
        urls: list[str] = []

        hc = provider.get("health_check")
        if isinstance(hc, dict):
            raw = hc.get("endpoint")
            if isinstance(raw, str) and "://" in raw:
                ep = raw.split("{", 1)[0].split("?", 1)[0].rstrip("/")
                parsed = urlparse(ep)
                if parsed.scheme and parsed.netloc:
                    urls.append(f"{parsed.scheme}://{parsed.netloc}")

        docs = provider.get("docs_url")
        if isinstance(docs, str) and "://" in docs:
            parsed = urlparse(docs.split("?", 1)[0])
            if parsed.netloc:
                host = parsed.netloc
                if not host.startswith("api."):
                    parts = host.split(".", 1)
                    if len(parts) == 2:
                        host = f"api.{parts[1]}"
                urls.append(f"{parsed.scheme}://{host}")

        # De-dupe while preserving order
        out: list[str] = []
        for u in urls:
            if u not in out:
                out.append(u)
        return out

    def _parse_file_for_calls(
        self,
        filepath: Path,
        content: str,
        base_urls: list[str],
    ) -> list[APICall]:
        calls: list[APICall] = []
        try:
            tree = ast.parse(content)
            calls.extend(self._extract_from_ast(tree, filepath, base_urls))
        except SyntaxError:
            pass
        calls.extend(self._extract_from_regex(content, filepath, base_urls))
        return calls

    def _extract_from_ast(
        self,
        tree: ast.AST,
        filepath: Path,
        base_urls: list[str],
    ) -> list[APICall]:
        calls: list[APICall] = []
        rel = str(filepath.relative_to(self.project_root))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            method_name = node.func.attr.upper()
            if method_name not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                continue
            if not node.args:
                continue
            url_val: str | None = None
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                url_val = first.value
            elif isinstance(first, ast.JoinedStr):  # f-strings: skip deterministic URL
                continue

            if not url_val:
                continue
            if not any(base in url_val for base in base_urls):
                continue

            calls.append(
                APICall(
                    method=method_name,
                    endpoint=self._extract_endpoint(url_val),
                    file=rel,
                    line=getattr(node, "lineno", 0) or 0,
                )
            )

        return calls

    def _extract_from_regex(
        self,
        content: str,
        filepath: Path,
        base_urls: list[str],
    ) -> list[APICall]:
        calls: list[APICall] = []
        rel = str(filepath.relative_to(self.project_root))
        pattern = r"(httpx|requests)\.(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']"

        for match in re.finditer(pattern, content, re.IGNORECASE):
            method = match.group(2).upper()
            url = match.group(3)
            if not any(base in url for base in base_urls):
                continue
            line_num = content[: match.start()].count("\n") + 1
            calls.append(
                APICall(
                    method=method,
                    endpoint=self._extract_endpoint(url),
                    file=rel,
                    line=line_num,
                )
            )

        return calls

    def _extract_endpoint(self, url: str) -> str:
        url = url.split("?", 1)[0]
        if "://" in url:
            after = url.split("://", 1)[1]
            if "/" in after:
                return "/" + after.split("/", 1)[1]
            return "/"
        return url


def analyze_all_scopes(project_root: Path) -> dict[str, ScopeRequirement]:
    """Run :class:`ScopeAnalyzer` for every provider key in the bundled registry."""
    analyzer = ScopeAnalyzer(project_root)
    registry = load_provider_registry()
    results: dict[str, ScopeRequirement] = {}

    for provider_slug in sorted(registry.get("providers", {}).keys()):
        try:
            requirement = analyzer.analyze_provider(provider_slug)
        except ValueError:
            continue
        if requirement.evidence or requirement.confidence > 0.5:
            results[provider_slug] = requirement

    return results
