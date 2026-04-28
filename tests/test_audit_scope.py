"""Heuristic scope audit against example tree."""

from pathlib import Path

from keysmith.audit.scope import check_scope_overuse


def test_open_case_read_only_triggers_scope_warnings() -> None:
    root = Path(__file__).resolve().parents[1] / "examples" / "open-case"
    w = check_scope_overuse(root)
    assert len(w) >= 1
    assert all(x.required_scope == "read" for x in w)
