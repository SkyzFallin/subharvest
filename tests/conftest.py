from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_loader():
    def _load(name: str):
        with open(FIXTURES / name, encoding="utf-8") as f:
            return json.load(f)

    return _load
