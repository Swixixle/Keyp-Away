"""Example tests referencing FEC_API_KEY."""

import os

import pytest


@pytest.mark.skipif(not os.getenv("FEC_API_KEY"), reason="FEC API unavailable")
def test_placeholder() -> None:
    assert True
