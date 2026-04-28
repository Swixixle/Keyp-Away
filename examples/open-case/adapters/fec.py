"""Demo FEC adapter.

Pydantic-style reference for the scanner unit tests:

Settings.fec_api_key
"""

from __future__ import annotations

import os


def candidates() -> str | None:
    return os.getenv("FEC_API_KEY")
