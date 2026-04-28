"""Remove probable secret-bearing lines from shell history files."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path
from re import Pattern


SCRUB_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("Bearer token", re.compile(r"Bearer\s+[a-zA-Z0-9_\-.]{20,}")),
    (
        "API key assignment",
        re.compile(r'[A-Z][A-Z0-9_]*_API_KEY\s*=\s*["\']?[a-zA-Z0-9_\-+/=]{16,}["\']?'),
    ),
    (
        "export assignment",
        re.compile(r"export\s+[A-Z][A-Z0-9_]*=['\"]?[a-zA-Z0-9_\-+/=]{16,}['\"]?"),
    ),
    (
        "curl Authorization",
        re.compile(r'curl[^;\n]*-H\s*["\']Authorization:\s*Bearer\s+[a-zA-Z0-9_\-.]{20,}'),
    ),
    ("AWS access key prefix", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[ps]_[a-zA-Z0-9]{36,}")),
]


def find_history_files() -> list[Path]:
    home = Path.home()
    cand = [
        home / ".bash_history",
        home / ".zsh_history",
        home / ".sh_history",
        home / ".fish_history",
    ]
    return [p for p in cand if p.is_file()]


def scrub_line(line: str) -> str | None:
    for _name, pattern in SCRUB_PATTERNS:
        if pattern.search(line):
            return None
    return line


def scrub_history_file(filepath: Path, *, dry_run: bool) -> tuple[int, int]:
    backup_path = filepath.with_suffix(filepath.suffix + ".bak")
    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except OSError as e:
        print(f"[keysmith-scrub] could not read {filepath}: {e}", file=sys.stderr)
        return 0, 0

    scrubbed = [ln for ln in lines if scrub_line(ln) is not None]
    removed = len(lines) - len(scrubbed)

    if not dry_run and removed > 0:
        shutil.copy2(filepath, backup_path)
        filepath.write_text("".join(scrubbed), encoding="utf-8")

    return len(lines), removed


def scrub_all_history(*, dry_run: bool = False) -> None:
    files = find_history_files()
    if not files:
        print("[keysmith-scrub] No shell history files found.")
        return

    total_read = 0
    total_removed = 0

    if dry_run:
        print("[keysmith-scrub] DRY RUN (no writes)\n")

    for fp in files:
        lines_read, lines_removed = scrub_history_file(fp, dry_run=dry_run)
        total_read += lines_read
        total_removed += lines_removed

        tag = "(dry-run) " if dry_run else ""
        if lines_removed:
            print(f"{fp.name}: {tag}removed {lines_removed} / {lines_read} lines")
        else:
            print(f"{fp.name}: {tag}nothing removed")

    print(f"[keysmith-scrub] Total lines removed from history: {total_removed}")
    if not dry_run and total_removed > 0:
        print("[keysmith-scrub] Backups: *.bak next to originals (restore manually if needed).")


def main() -> None:
    ap = argparse.ArgumentParser(prog="keysmith-scrub-history")
    ap.add_argument("--dry-run", action="store_true")
    ns = ap.parse_args()
    scrub_all_history(dry_run=bool(ns.dry_run))


if __name__ == "__main__":
    main()
