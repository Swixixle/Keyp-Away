"""Pre-commit hook: scan staged text files for probable secret literals."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from re import Pattern
from typing import ClassVar


SECRET_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "Generic API Key assignment",
        re.compile(r'(?:api[_-]?key|token)\s*[=:]\s*["\']([a-zA-Z0-9_\-./+]{20,})["\']', re.I),
    ),
    ("Bearer token", re.compile(r"Bearer\s+[a-zA-Z0-9_\-.]{20,}")),
    ("GitHub token", re.compile(r"gh[ps]_[a-zA-Z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[a-zA-Z0-9-]+")),
    ("PEM block", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    ("JWT-like blob", re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]{10,}")),
]

IGNORE_PATH_RE: ClassVar[list[Pattern[str]]] = [
    re.compile(r"\.lock$"),
    re.compile(r"package-lock\.json$"),
    re.compile(r"poetry\.lock$"),
    re.compile(r"\.min\.(js|css)$"),
    re.compile(r"[/.](?:venv|\.venv)(?:/|$)"),
]


def should_ignore_file(filepath: str) -> bool:
    if any(p.search(filepath.replace("\\", "/")) for p in IGNORE_PATH_RE):
        return True
    name = filepath.rsplit("/", 1)[-1]
    # Tests often literal fake secrets; markdown often example strings
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if filepath.endswith(".md"):
        return True
    return False


TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".env",
        ".txt",
        ".sh",
        ".zsh",
        ".sql",
        ".md",
    }
)
_MAX_SCAN_BYTES = 2_000_000


def _should_scan_contents(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env") or ".env." in name or name.endswith(".example"):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def scan_file_for_secrets(filepath: Path) -> list[tuple[str, int, str]]:
    """Return [(label, line_number, excerpt), ...]."""
    path_s = filepath.as_posix()
    if should_ignore_file(path_s):
        return []
    try:
        st = filepath.stat()
    except OSError:
        return []
    if st.st_size > _MAX_SCAN_BYTES or not _should_scan_contents(filepath):
        return []

    try:
        raw = filepath.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except OSError:
        return []

    findings: list[tuple[str, int, str]] = []

    for line_num, line in enumerate(raw, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        for secret_type, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                show = stripped[:160]
                findings.append((secret_type, line_num, show))

    return findings


def check_staged_files() -> int:
    """Return 0 if clean, 1 if secrets guessed."""
    ls = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=False,
    )
    if ls.returncode != 0:
        print("[keysmith-pre-commit] could not run git diff --cached", file=sys.stderr)
        return 1

    staged = [s for s in ls.stdout.strip().split("\n") if s]
    if not staged:
        return 0

    all_bad: list[tuple[Path, list[tuple[str, int, str]]]] = []

    for rel in staged:
        path = Path(rel)
        if not path.is_file():
            continue
        findings = scan_file_for_secrets(path)
        if findings:
            all_bad.append((path, findings))

    if not all_bad:
        return 0

    lines = [
        "=" * 60,
        "🚨 COMMIT BLOCKED: Secrets detected in staged files",
        "=" * 60,
        "",
    ]
    for fp, findings in all_bad:
        lines.append(f"📄 {fp}")
        for label, lineno, excerpt in findings:
            lines.append(f"   Line {lineno}: {label}")
            masked = excerpt[:40] + "..." if len(excerpt) > 40 else excerpt
            lines.append(f"   > {masked}")
        lines.append("")

    lines.extend(
        [
            "=" * 60,
            "How to fix:",
            "=" * 60,
            "",
            "1. Remove secrets from code:",
            "   • Use environment variables instead",
            "   • Store in .env (add to .gitignore)",
            "",
            "2. Store secrets securely:",
            "   keysmith setup <provider>",
            "",
            "3. Clean shell history if you typed secrets:",
            "   keysmith scrub-history --dry-run",
            "",
            "4. Try committing again:",
            "   git commit",
            "",
            "=" * 60,
            "To bypass (NOT RECOMMENDED):",
            "   git commit --no-verify",
            "=" * 60,
            "",
        ]
    )
    sys.stderr.write("\n".join(lines) + "\n")
    return 1


def install_hook(repo_path: Path | None = None) -> None:
    """Write .git/hooks/pre-commit invoking this package."""
    repo = Path(repo_path).resolve() if repo_path else Path.cwd().resolve()
    hooks_dir = repo / ".git" / "hooks"
    hook_path = hooks_dir / "pre-commit"
    if not hooks_dir.is_dir():
        print(f"[keysmith] Not a git repository: {repo}", file=sys.stderr)
        sys.exit(1)

    root_literal = repr(str(repo.resolve()))
    hook_lines = [
        "#!/usr/bin/env python3",
        "import sys",
        "from pathlib import Path",
        f"_ROOT = Path({root_literal})",
        "sys.path.insert(0, str(_ROOT))",
        "from keysmith.hooks.pre_commit import check_staged_files",
        "raise SystemExit(check_staged_files())",
        "",
    ]
    hook_path.write_text("\n".join(hook_lines), encoding="utf-8")
    hook_path.chmod(0o755)
    print(f"[keysmith] Pre-commit hook installed: {hook_path}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="keysmith-hooks-pre-commit")
    ap.add_argument("--install", action="store_true", help="Install hook in repo at cwd")
    ap.add_argument("--repo", default=".", type=Path, help="Repo root for --install")
    ap.add_argument("--check", action="store_true", help="Scan staged files and exit non-zero")
    args = ap.parse_args()
    if args.install:
        install_hook(Path(args.repo))
        return
    if args.check:
        raise SystemExit(check_staged_files())
    ap.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
