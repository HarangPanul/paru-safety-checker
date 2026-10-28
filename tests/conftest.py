import pytest

from paru_analyzer import crosscheck


@pytest.fixture(autouse=True)
def _no_bash_crosscheck(monkeypatch):
    """Most tests feed fragments that are not valid bash and must not depend on the machine's bash.
    tests/test_preprocess.py switches the cross-check on where it is the thing under test."""
    monkeypatch.setattr(crosscheck, "ENABLED", False)
