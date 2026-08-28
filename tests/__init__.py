"""Test package marker.

Required, not cruft: `venv/bin/pytest` uses importmode `prepend`, which puts the test
module's basedir on `sys.path` - the first directory upward with no `__init__.py`. Without
this file that is `<repo>/tests`, so `from tests.fakes import FakeBackend` (Tasks 3 and 4)
fails with `ModuleNotFoundError: No module named 'tests'`. With it, the basedir walk
reaches the repo root, the repo root goes on `sys.path`, and `tests.fakes` resolves.
Do not delete this file because it looks empty.
"""
