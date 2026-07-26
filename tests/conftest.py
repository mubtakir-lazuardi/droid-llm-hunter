import os
import sys

import pytest

# Repo root = parent of this tests/ directory.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture(autouse=True)
def _chdir_repo_root(monkeypatch):
    """The tool reads config/prompts via repo-relative paths, so run tests from the repo root."""
    monkeypatch.chdir(REPO_ROOT)
