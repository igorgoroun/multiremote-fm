# multiremote-fm Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the never-importing `core/` + `drivers/` + `remote.py` split — committed as baseline `0d8d7bc`, still unimportable — into one installable `multiremote_fm` package in which the five file operations are implemented exactly once, closing all 14 defects in the approved spec while keeping the public API frozen.

**Architecture:** Three layers. `remotes.py` holds the four thin frozen-API remotes (`Local`, `FTP`, `FTPS`, `SFTP`, ~15 lines each) which construct a backend and delegate. `driver.py` holds `RemoteDriver`, which implements `search`/`download`/`upload`/`move`/`delete` once over a `Backend`, is copy-on-write for `path`/`mask`/`files`, and shares one backend instance across all copies. `backends/` holds protocol primitives only (`connect`, `close`, `list`, `read`, `write`, `rename`, `remove`) — no backend ever sees a path mask, `unlink`, or `download_content`.

**Tech Stack:** Python 3.10.20 (venv at `./venv`), stdlib `ftplib` / `os` / `fnmatch` / `posixpath`, optional `paramiko` 5.0.0 for SFTP, pytest 9.1.1 + ruff 0.16.5 + mypy 2.3.1, setuptools build backend, GitHub Actions.

## Resolved Decisions

Both decisions from the pre-flight scan are fully closed, along with OD-1's branch sub-question. OD-1 was resolved by the repo owner committing the baseline directly; the working branch `refactor/clean-package` has since been cut from that baseline and is checked out; OD-2 was approved by the user and is implemented in **Task 1 Step 4**. There is no prerequisite task and nothing blocks execution. See "Execution progress" below for where the plan currently stands.

### OD-1 — the previously-uncommitted work: **RESOLVED — by the repo owner directly, 2026-08-28**

Commit `0d8d7bc` on `main` already captures the full baseline. It was made by the repo owner (`Ihor Horun <igor.goroun@gmail.com>`), not by any worker on this plan, and it is already pushed — `origin/main` points at it.

```
0d8d7bc (main, origin/main, refactor/clean-package)  Temporal commit before refactoring
977c6ac (tag: 0.1)                                   Fix github cicd
22 files changed, 5631 insertions(+), 762 deletions(-)
```

Verified contents: `core/` (4 files), `drivers/` (4 files), `remote.py` and the root `__init__.py` are **tracked**; `multiremote_fm.py` and `tests/test_ftp.py` are **deleted**; `README.md`, `.gitignore`, `LICENSE` and the publish workflow are modified. The commit also brought this plan and the spec under version control (22 paths in total).

**No prerequisite task is needed.** Every hazard OD-1 recorded is discharged by that commit:

| Was | Now |
|---|---|
| **D5** — Task 1's `git commit` would sweep 20 unrelated staged paths into the wrong commit | The index is empty, so every `git add <paths> && git commit` in this plan commits exactly what it names. No collateral is possible. |
| **D4a** — `git rm -r --cached core drivers remote.py __init__.py` (Task 9) would abort, because none of those paths existed at `HEAD` | All four are tracked at `HEAD` (verified with `git cat-file -e`), so **Task 9's `git rm -r --cached` and its test work as originally written, without modification**. |
| **D4b** — Task 9's `test_legacy_paths_are_gone` asserts `multiremote_fm.py` is absent, but it existed at `HEAD` and no task deleted it | `0d8d7bc` deleted it. It is absent from `HEAD` and from disk, so that assertion is now both satisfiable and meaningful. |
| **Destruction risk** — a corrected Task 1 would leave the ten legacy files never-committed, so Task 9's `rm -rf` would destroy them permanently | All ten are committed in `0d8d7bc` and recoverable from it. Task 9 is now safe. |

> **Sub-question — RESOLVED.** The controller cut branch `refactor/clean-package` from `0d8d7bc` on 2026-08-28, per the user's choice. `main` remains at `0d8d7bc`, untouched. All implementation happens on `refactor/clean-package`. Task 1 may now be dispatched.

### OD-2 — ruff configuration: **RESOLVED (user approved 2026-08-28)**

Approved resolution: move the format style into `pyproject.toml`, delete `ruff.toml`, and un-ignore it in `.gitignore`. Implemented as **Task 1 Step 4**.

- `pyproject.toml` gains `[tool.ruff.format] quote-style = "single"` — version-controlled, so it applies to every clone and to CI.
- `ruff.toml` is **deleted**. This is mandatory, not tidiness: ruff resolves `ruff.toml` **in preference to** `pyproject.toml`, so leaving it in place would silently override the new setting. Verified — with `ruff.toml` saying `double` and `pyproject.toml` saying `single`, `ruff format --check` on single-quoted source exits 1; after deleting `ruff.toml` it exits 0.
- `.gitignore:166` (the line `ruff.toml`) is **removed**, so nothing re-hides a ruff config in future.
- Nothing else is lost: the whole `[lint]` section of `ruff.toml` is commented out, so `quote-style` is the only live setting it carried.

## Execution progress — resume at Task 7

Recorded 2026-08-28. Tasks 1–6 are **complete and committed** on `refactor/clean-package`:

```
54a6345  Add FtpBackend with connection reuse, MLSD/NLST listing, honoured encoding   (Task 6)
69ba184  Add LocalBackend and Local remote; fix empty-mask search returning zero files (Task 5)
23a350d  Implement the five operations once in RemoteDriver with copy-on-write         (Task 4)
3482faf  Add Backend ABC, Stat, and in-memory FakeBackend test double                  (Task 3)
ad4c206  Add RemoteFile/RemoteFileSet with name-keyed dedup and ordered indexing       (Task 2)
ead6c6a  Add multiremote_fm package skeleton, exceptions, real PEP 440 version, ruff config in pyproject (Task 1)
0d8d7bc  Temporal commit before refactoring                                            (baseline, also on main)
```

State verified at that point: `venv/bin/pytest tests/ -q` → **81 passed, 3 failed**, and all three failures are in the *old* `tests/test_sftp.py` (`test_connect_with_password`, `test_connect_with_rsa`, `test_import_without_paramiko`) — precisely the file Task 7 rewrites. `ruff format --check` still reports 2 files to reformat, which is Task 12's job.

**Next action: Task 7.** Do **not** re-run Tasks 1–6. Per the multi-owner-files constraint below, re-running any of them would restate `multiremote_fm/__init__.py`, `remotes.py` or `backends/__init__.py` from an earlier, smaller version and silently revert committed exports. The unchecked `- [ ]` boxes in Tasks 1–6 are historical; this section is the authority on where execution stands.

---

## Global Constraints

- Source of truth is `docs/superpowers/specs/2026-08-28-multiremote-fm-refactor-design.md` (Approved 2026-08-28). Every task below traces to a spec section.
- Python floor is `>=3.10`; `requires-python = ">=3.10"` in `pyproject.toml` (spec §4.7).
- Public API is frozen per spec §3.1: no new, removed, or renamed public names, and no changed parameter defaults.
- `pyproject.toml` carries a **real PEP 440 version**: `version = "0.2.0"`. The `{{VERSION_PLACEHOLDER}}` token is gone. The release *mechanism* is preserved: the publish workflow rewrites the `version = ` line from the git tag (Task 11). Rationale: the token is not PEP 440, so with it in place `pip install -e .` and `python -m build` both fail with `configuration error: project.version must be pep440` (reproduced), which made the project uninstallable and unbuildable.
- Tests run against the editable install created in Task 1 (`venv/bin/pip install -e ".[dev]"`). There is no `conftest.py` `sys.path` manipulation.
- `paramiko>=3.2,<6` is an OPTIONAL extra named `sftp`. Never a hard runtime dependency.
- No `X | Y` annotations outside modules carrying `from __future__ import annotations`. Use `typing.Optional` / `typing.Union`.
- No `assert` used for control flow anywhere in `multiremote_fm/`. Raise `NothingToUploadException`, `TypeError`, `ValueError`, or `ConnectionError`.
- Ruff config lives in `pyproject.toml` under `[tool.ruff.format]` with `quote-style = "single"`; use single quotes in all package code. `ruff.toml` is deleted in Task 1 Step 4 because it would otherwise take precedence over `pyproject.toml`.
- The five operations `search`/`download`/`upload`/`move`/`delete` appear exactly once, in `multiremote_fm/driver.py`. `remotes.py` contains no protocol I/O and no operation bodies.
- `RemoteDriver.with_path` / `with_mask` / `with_files` return a NEW `RemoteDriver` sharing the SAME backend instance. `move(dest)` returns a copy with `path=dest`. `upload` and `delete` return `self`.
- `RemoteFile.with_driver` / `RemoteFileSet.with_driver` return `driver.with_files(...)` — a copy, never a mutation. `set_path` / `set_files` do not exist.
- Default mask is `'*'`. Default path is `''`.
- All commands use `venv/bin/pytest`, `venv/bin/ruff`, `venv/bin/mypy`, `venv/bin/python`.
- Never run `git checkout`, `git stash`, or `git reset`. Only touch the paths a task names. The working tree is **clean** as of the `0d8d7bc` baseline commit, so each task's `git add <paths> && git commit` commits exactly what it names.
- **The working branch already exists and is checked out.** `refactor/clean-package` was cut from `0d8d7bc` by the controller; assume you are already on it and verify with `git branch --show-current` if unsure. **No task creates, switches, or deletes a branch** — you do not need to create or switch to it yourself. All commits land on `refactor/clean-package`; `main` stays at `0d8d7bc`.
- **Multi-owner files.** `multiremote_fm/__init__.py`, `multiremote_fm/remotes.py` and `multiremote_fm/backends/__init__.py` are each fully restated by four to six different tasks, because every task must show its complete file. **The LAST task to touch each file is authoritative. Execute tasks in ascending order and never re-run an earlier task afterwards** — doing so silently reverts a later task's exports, and no test before Task 8 would catch it. Authoritative versions: `multiremote_fm/__init__.py` → Task 7; `multiremote_fm/remotes.py` → Task 7; `multiremote_fm/backends/__init__.py` → Task 7.

---

## File Structure

### Created

| Path | Single responsibility |
|------|----------------------|
| `multiremote_fm/__init__.py` | Public exports and `__version__`. No logic. |
| `tests/__init__.py` | Makes `tests` an importable package so `from tests.fakes import FakeBackend` resolves under `venv/bin/pytest`. Docstring only — **not cruft, do not delete** (see Task 1). |
| `multiremote_fm/py.typed` | PEP 561 marker (empty file). |
| `multiremote_fm/exceptions.py` | The five live exception types. No dead HTTP leftovers. |
| `multiremote_fm/files.py` | `RemoteFile` (name-keyed `__eq__`/`__hash__`) and `RemoteFileSet` (dict-backed, ordered, deduplicating). |
| `multiremote_fm/driver.py` | `BaseDriver` ABC with real signatures + `RemoteDriver`: the five operations, once, copy-on-write. |
| `multiremote_fm/remotes.py` | `Local`, `FTP`, `FTPS`, `SFTP` — construct a backend, delegate. No I/O. |
| `multiremote_fm/backends/__init__.py` | Backend package exports. |
| `multiremote_fm/backends/base.py` | `Stat` NamedTuple + `Backend` ABC: seven primitives. |
| `multiremote_fm/backends/local.py` | `LocalBackend`: `os`-based primitives. |
| `multiremote_fm/backends/ftp.py` | `FtpBackend`: connection reuse, MLSD with NLST+SIZE fallback, honours `encoding`, TLS switch. |
| `multiremote_fm/backends/sftp.py` | `SftpBackend`: deferred annotations, construction-time `ImportError`, honours `response_timeout`. |
| `tests/fakes.py` | `FakeBackend`: in-memory `Backend` for network-free tests. |
| `tests/test_exceptions.py` | Exception surface and messages. |
| `tests/test_driver.py` | The five operations, copy-on-write, `with_driver`, over `FakeBackend`. |
| `tests/test_backend_base.py` | `Stat` shape and `Backend` abstractness. |
| `tests/test_ftp_backend.py` | `FtpBackend` against a mocked `ftplib`. |
| `.github/workflows/test.yml` | pytest + ruff on 3.10/3.11/3.12/3.13. |

### Modified

| Path | Change |
|------|--------|
| `pyproject.toml:1-23` (whole file) | 3.10 floor, packages table, `sftp` + `dev` extras, `py.typed` package data, a **real PEP 440 `version = "0.2.0"`** (the `{{VERSION_PLACEHOLDER}}` token is removed), and — per approved OD-2 — `[tool.ruff.format] quote-style = "single"`. |
| `tests/test_remote_files.py:1-41` | Import `multiremote_fm`; add dedup and ordering assertions. |
| `tests/test_local_dir.py:1-94` | Import `multiremote_fm`; count assertion in `test_search_common`; `test_download_searched` rewritten for copy-on-write. |
| `tests/test_sftp.py:1-236` | Import `multiremote_fm`; fix the 3 failures; rewrite mutation-based assertions. |
| `tests/_test_ftp.py:1-84` | Fix the broken `from file import ...`; stay opt-in via env vars. |
| `README.md:3,15,36-42,220-222,343-348` | Drop the false "Memory Efficient" bullet, 3.9→3.10 badge, working dev-install block, SFTP extra install line, v0.2 changelog. `README.md:327-335` is left untouched. |
| `.github/workflows/publish-to-pypi.yml:13,27,30` | `actions/checkout@main` → `@v4`; `::set-output` → `$GITHUB_OUTPUT`; token substitution → `version = ` line rewrite. |
| `.gitignore:166` | Approved OD-2. Delete the single line `ruff.toml` so no ruff config can be hidden from version control again. |

### Deleted

| Path | Reason |
|------|--------|
| `__init__.py` (repo root) | Root-level package shadows the real one; `ImportError` at line 4. |
| `remote.py` | Superseded by `multiremote_fm/driver.py`. |
| `core/__init__.py`, `core/base.py`, `core/file.py`, `core/exceptions.py` | Superseded by `multiremote_fm/{files,driver,exceptions}.py`. |
| `drivers/__init__.py`, `drivers/local.py`, `drivers/ftp.py`, `drivers/sftp.py` | ~491 duplicated lines superseded by `driver.py` + `backends/`. |
| `__pycache__/`, `core/__pycache__/`, `drivers/__pycache__/` | Stale bytecode for deleted modules. |
| `ruff.toml` | Approved OD-2. Ruff resolves `ruff.toml` **in preference to** `pyproject.toml`, so leaving it would override the new `[tool.ruff.format]` block. Deleted in Task 1 Step 4. |

### Sequencing note (deviation from the suggested spine, justified)

The suggested spine put `pyproject.toml` at step 8 and legacy deletion at step 9. Two adjustments:

1. **`pyproject.toml` moves to Task 1, together with the editable install.** Nothing under `multiremote_fm/` is importable by `venv/bin/pytest` (which, unlike `python -m pytest`, does not add the CWD to `sys.path`) until the package is installed, so Task 1's own test could not otherwise run. This is only possible because the version is a real PEP 440 string — see Global Constraints. The wheel/extras content of `pyproject.toml` is finalised in Task 1 except for the `backends` subpackage line, which Task 3 adds when that directory first exists (re-run the editable install after that edit).
2. **Legacy deletion stays late (Task 9), as suggested.** The legacy tree is inert once the new package exists — nothing new imports it — so deleting it early buys nothing and would break the three existing test files before their rewrites land in Tasks 5–7.

---

### Task 1: Packaging, ruff config, editable install, and `exceptions.py`

Traces to spec §4.2 (S1 layout), §4.6 (S5 dead exceptions), §4.7 (S6 packaging), and the approved **OD-2** (ruff config move).

**Files:**
- Create: `multiremote_fm/exceptions.py`
- Create: `multiremote_fm/__init__.py`
- Create: `multiremote_fm/py.typed`
- Create: `tests/__init__.py`
- Modify: `pyproject.toml:1-23` (whole file)
- Modify: `.gitignore:166` (delete the line `ruff.toml`)
- Delete: `ruff.toml`
- Test: `tests/test_exceptions.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `multiremote_fm.exceptions.NothingToUploadException(Exception)`; `SSHPasswordRSAError(ValueError)`; `DownloadingError(Exception)` with `__init__(self, filename: str, message: str)` and attributes `.filename` / `.message`; `UploadingError(DownloadingError)`; `MovingError(DownloadingError)`. All five re-exported from `multiremote_fm`. `multiremote_fm.__version__ == '0.2.0'`. Also produces the version-controlled ruff format config in `pyproject.toml`, on which every later `ruff format` / `ruff format --check` invocation depends.

- [ ] **Step 1: Write the failing test**

Create `tests/test_exceptions.py`:

```python
import unittest

from multiremote_fm import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)


class TestExceptions(unittest.TestCase):
    def test_nothing_to_upload_message(self):
        self.assertEqual(str(NothingToUploadException()), 'Nothing to upload')

    def test_ssh_password_rsa_error_is_value_error(self):
        self.assertIsInstance(SSHPasswordRSAError(), ValueError)
        self.assertEqual(
            str(SSHPasswordRSAError()),
            'One of the attributes `password` or `rsa` should be defined',
        )

    def test_downloading_error_carries_filename_and_message(self):
        err = DownloadingError('a.txt', 'boom')
        self.assertEqual(err.filename, 'a.txt')
        self.assertEqual(err.message, 'boom')
        self.assertEqual(str(err), 'Cannot download file a.txt: boom')

    def test_uploading_and_moving_error_messages(self):
        self.assertEqual(str(UploadingError('a.txt', 'boom')), 'Cannot upload file a.txt: boom')
        self.assertEqual(str(MovingError('a.txt', 'boom')), 'Cannot move file a.txt: boom')
        self.assertIsInstance(UploadingError('a', 'b'), DownloadingError)
        self.assertIsInstance(MovingError('a', 'b'), DownloadingError)

    def test_dead_http_exceptions_are_gone(self):
        import multiremote_fm.exceptions as mod

        self.assertFalse(hasattr(mod, 'InvalidResponseCodeError'))
        self.assertFalse(hasattr(mod, 'InvalidJSONResponseError'))

    def test_version(self):
        import multiremote_fm

        self.assertEqual(multiremote_fm.__version__, '0.2.0')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_exceptions.py -v`

Expected: FAIL — collection error `ModuleNotFoundError: No module named 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Replace `pyproject.toml` entirely (note the real PEP 440 version — no magic token — and the `[tool.ruff.format]` block that replaces `ruff.toml` per approved OD-2):

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "multiremote-fm"
version = "0.2.0"
authors = [
  { name="Igor Horun", email="snake@snake.mk.ua" },
]
description = "Library to manage files on multitype remotes - ftp, sftp, ftps, local, etc.."
readme = "README.md"
requires-python = ">=3.10"
classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
]

[project.optional-dependencies]
sftp = ["paramiko>=3.2,<6"]
dev = [
    "pytest>=9.1,<10",
    "ruff>=0.16,<0.17",
    "mypy>=2.3,<3",
    "build>=1.2",
    "setuptools>=61.0",
    "paramiko>=3.2,<6",
]

[project.urls]
"Homepage" = "https://github.com/igorgoroun/multiremote-fm"
"Bug Tracker" = "https://github.com/igorgoroun/multiremote-fm/issues"

[tool.setuptools]
packages = ["multiremote_fm"]

[tool.setuptools.package-data]
multiremote_fm = ["py.typed"]

[tool.ruff.format]
# Migrated from the untracked, git-ignored ruff.toml (approved OD-2).
# Ruff prefers ruff.toml over pyproject.toml, so ruff.toml must be deleted for this
# to take effect - see Step 4.
quote-style = "single"
```

> `setuptools` is in the `dev` extra on purpose: Task 13's `test_c5_py_typed_in_built_wheel` runs `python -m build --no-isolation`, and Python 3.12+ virtualenvs no longer ship setuptools, so without this the wheel check would fail on the 3.12 and 3.13 CI legs.

Create `multiremote_fm/exceptions.py`:

```python
"""Exceptions raised by multiremote-fm."""


class NothingToUploadException(Exception):
    def __str__(self) -> str:
        return 'Nothing to upload'


class SSHPasswordRSAError(ValueError):
    def __str__(self) -> str:
        return 'One of the attributes `password` or `rsa` should be defined'


class DownloadingError(Exception):
    def __init__(self, filename: str, message: str) -> None:
        super().__init__(filename, message)
        self.filename = filename
        self.message = message

    def __str__(self) -> str:
        return 'Cannot download file {0}: {1}'.format(self.filename, self.message)


class UploadingError(DownloadingError):
    def __str__(self) -> str:
        return 'Cannot upload file {0}: {1}'.format(self.filename, self.message)


class MovingError(DownloadingError):
    def __str__(self) -> str:
        return 'Cannot move file {0}: {1}'.format(self.filename, self.message)
```

Create `multiremote_fm/__init__.py`:

```python
"""Multi-remote file manager package."""

from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)

__version__ = '0.2.0'

__all__ = [
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

Create `multiremote_fm/py.typed` as a zero-byte file:

```bash
: > multiremote_fm/py.typed
```

Create `tests/__init__.py`:

```python
"""Test package marker.

Required, not cruft: `venv/bin/pytest` uses importmode `prepend`, which puts the test
module's basedir on `sys.path` - the first directory upward with no `__init__.py`. Without
this file that is `<repo>/tests`, so `from tests.fakes import FakeBackend` (Tasks 3 and 4)
fails with `ModuleNotFoundError: No module named 'tests'`. With it, the basedir walk
reaches the repo root, the repo root goes on `sys.path`, and `tests.fakes` resolves.
Do not delete this file because it looks empty.
"""
```

- [ ] **Step 4: Retire `ruff.toml` so the `pyproject.toml` ruff config takes effect**

Resolves the approved **OD-2**. Three edits, all required together.

First delete the file — ruff prefers `ruff.toml` over `pyproject.toml`, so while it exists the `[tool.ruff.format]` block added in Step 3 is silently ignored:

```bash
rm ruff.toml
```

Then remove its ignore line from `.gitignore`. The line is exactly `ruff.toml` at `.gitignore:166`, sitting in this block:

```
.helix/
ruff.toml
.zed/
```

Delete only the middle line, leaving:

```
.helix/
.zed/
```

Verify all three parts landed — the config is now in version control, the override is gone, and single quotes still pass:

```bash
test -e ruff.toml && echo "FAIL: ruff.toml still present" || echo "ruff.toml deleted: OK"
grep -c '^ruff\.toml$' .gitignore || echo "gitignore line removed: OK"
venv/bin/python -c "import tomli; print(tomli.load(open('pyproject.toml','rb'))['tool']['ruff']['format'])"
venv/bin/ruff format --check multiremote_fm
```

Expected: `ruff.toml deleted: OK`; `gitignore line removed: OK` (grep exits 1 with a count of 0); `{'quote-style': 'single'}`; and `2 files already formatted`. On Python 3.11+ use `tomllib` instead of `tomli` in the third command.

- [ ] **Step 5: Install the package editable and verify it succeeds**

Run: `venv/bin/pip install -e ".[dev]"`

Expected: `Successfully installed multiremote-fm-0.2.0`. Then confirm the install is importable from outside the repo:

```bash
cd /tmp && /Users/snake/Projects/multiremote-fm/venv/bin/python -c "import multiremote_fm; print(multiremote_fm.__version__)"
```

Expected: `0.2.0`. If pip reports `configuration error: project.version must be pep440`, the version line still holds the old token — fix `pyproject.toml` before continuing.

- [ ] **Step 6: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_exceptions.py -v`

Expected: PASS — 6 passed.

- [ ] **Step 7: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add pyproject.toml .gitignore multiremote_fm/__init__.py multiremote_fm/exceptions.py multiremote_fm/py.typed tests/__init__.py tests/test_exceptions.py && git commit -m "Add multiremote_fm package skeleton, exceptions, real PEP 440 version, ruff config in pyproject"
```

> No `git rm` is needed for `ruff.toml`: it was never tracked (untracked and git-ignored), so deleting it from disk in Step 4 is the whole job. The `.gitignore` edit is what git records.

> Multi-owner file: this task's `multiremote_fm/__init__.py` is superseded by Tasks 2, 4, 5, 6 and finally **Task 7**, which is authoritative.

---

### Task 2: `files.py` — `RemoteFile` and `RemoteFileSet`

Traces to spec §4.5 (S4 files), defects 6 and 12.

**Files:**
- Create: `multiremote_fm/files.py`
- Modify: `multiremote_fm/__init__.py` (whole file)
- Test: `tests/test_remote_files.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `RemoteFile(name: str, content: Optional[bytes] = b'', size: Optional[int] = 0)` with attributes `.name: str`, `.content: Optional[bytes]`, `.size: Optional[int]`, property `.mimetype -> Optional[str]`, `.to_dict() -> Dict[str, Any]`, `.with_driver(driver: 'BaseDriver') -> 'BaseDriver'`, `__eq__`/`__hash__` keyed on `.name`, `__str__` returning the name, `__repr__` returning `RemoteFile(<name>)`.
  - `RemoteFileSet(*files: RemoteFile)` with `.files -> Set[RemoteFile]`, `.add(*files: RemoteFile) -> None`, `.with_driver(driver: 'BaseDriver') -> 'BaseDriver'`, `__iter__`, `__len__`, `__getitem__(item)`, `__str__`, `__repr__`. Backed by `Dict[str, RemoteFile]`: insertion-ordered, deduplicating by name.
  - Both re-exported from `multiremote_fm`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_remote_files.py` entirely:

```python
import unittest

from multiremote_fm import RemoteFile, RemoteFileSet


class TestRemoteFileObjects(unittest.TestCase):
    def test_file_single(self):
        file_s = RemoteFile('file_single.txt')
        self.assertEqual(str(file_s), 'file_single.txt')
        self.assertEqual(repr(file_s), 'RemoteFile(file_single.txt)')
        self.assertEqual(file_s.content, b'')
        self.assertEqual(file_s.size, 0)

    def test_file_multi_indexing(self):
        file_1 = RemoteFile('file_1.txt')
        file_2 = RemoteFile('file_2.txt')
        fileset = RemoteFileSet(file_1, file_2)
        self.assertIsInstance(fileset[0], RemoteFile)
        self.assertIsInstance(fileset[1], RemoteFile)

    def test_mimetype_guessed_and_fallback(self):
        self.assertEqual(RemoteFile('doc.pdf').mimetype, 'application/pdf')
        self.assertEqual(RemoteFile('blob.unknownext').mimetype, 'application/octet-stream')

    def test_to_dict(self):
        f = RemoteFile('a.txt', b'hi', 2)
        self.assertEqual(
            f.to_dict(),
            {'name': 'a.txt', 'content': b'hi', 'size': 2, 'mimetype': 'text/plain'},
        )

    def test_equality_and_hash_keyed_on_name(self):
        a = RemoteFile('same.txt', b'x', 1)
        b = RemoteFile('same.txt', b'x', 1)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, RemoteFile('other.txt', b'x', 1))
        self.assertNotEqual(a, 'same.txt')

    def test_fileset_deduplicates_by_name(self):
        a = RemoteFile('same.txt', b'x', 1)
        b = RemoteFile('same.txt', b'x', 1)
        self.assertEqual(len(RemoteFileSet(a, b)), 1)

    def test_fileset_is_insertion_ordered_and_stable(self):
        """Order follows insertion, and repeated indexing is deterministic.

        The old set-backed implementation indexed into `list(set)`, whose order was
        arbitrary; the dict-backed one is insertion-ordered, so `fileset[0]` is stable.
        """
        names = ['c.txt', 'a.txt', 'b.txt']
        fileset = RemoteFileSet(*[RemoteFile(n) for n in names])
        self.assertEqual([f.name for f in fileset], names)
        self.assertEqual(fileset[0].name, 'c.txt')
        self.assertEqual(fileset[-1].name, 'b.txt')

    def test_fileset_add_and_files_property(self):
        fileset = RemoteFileSet()
        self.assertEqual(len(fileset), 0)
        fileset.add(RemoteFile('a.txt'), RemoteFile('b.txt'))
        self.assertEqual(len(fileset), 2)
        self.assertIsInstance(fileset.files, set)
        self.assertEqual({f.name for f in fileset.files}, {'a.txt', 'b.txt'})

    def test_fileset_add_rejects_non_remote_file(self):
        with self.assertRaises(TypeError):
            RemoteFileSet().add('not-a-file')

    def test_fileset_repr(self):
        fileset = RemoteFileSet(RemoteFile('a.txt'))
        self.assertEqual(repr(fileset), 'RemoteFileSet(RemoteFile(a.txt),)')
        self.assertEqual(str(fileset), repr(fileset))


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_remote_files.py -v`

Expected: FAIL — collection error `ImportError: cannot import name 'RemoteFile' from 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/files.py`:

```python
"""File value objects returned and accepted by every driver."""

import mimetypes
from typing import TYPE_CHECKING, Any, Dict, Iterator, Optional, Set

if TYPE_CHECKING:
    from .driver import BaseDriver


class RemoteFile:
    """Represents a file from a remote source."""

    def __init__(
        self,
        name: str,
        content: Optional[bytes] = b'',
        size: Optional[int] = 0,
    ) -> None:
        self.name = name
        self.content = content
        self.size = size
        self._mimetype: Optional[str] = (
            mimetypes.guess_type(self.name)[0] or 'application/octet-stream'
        )

    @property
    def mimetype(self) -> Optional[str]:
        return self._mimetype

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return dict(
            name=self.name,
            content=self.content,
            size=self.size,
            mimetype=self.mimetype,
        )

    def with_driver(self, driver: 'BaseDriver') -> 'BaseDriver':
        """Return a copy of `driver` configured to work with this file."""
        return driver.with_files(RemoteFileSet(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RemoteFile):
            return NotImplemented
        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return '{0}({1})'.format(self.__class__.__name__, self.name)


class RemoteFileSet:
    """An insertion-ordered collection of RemoteFile objects, deduplicated by name."""

    def __init__(self, *files: RemoteFile) -> None:
        self.__files: Dict[str, RemoteFile] = {}
        self.add(*files)

    @property
    def files(self) -> Set[RemoteFile]:
        return set(self.__files.values())

    def add(self, *files: RemoteFile) -> None:
        """Add files to the set, replacing any earlier file of the same name."""
        for file in files:
            if not isinstance(file, RemoteFile):
                raise TypeError(
                    'RemoteFileSet accepts RemoteFile objects, got {0}'.format(type(file).__name__)
                )
            self.__files[file.name] = file

    def with_driver(self, driver: 'BaseDriver') -> 'BaseDriver':
        """Return a copy of `driver` configured to work with this fileset."""
        return driver.with_files(self)

    def __iter__(self) -> Iterator[RemoteFile]:
        return iter(list(self.__files.values()))

    def __len__(self) -> int:
        return len(self.__files)

    def __getitem__(self, item: Any) -> Any:
        return list(self.__files.values())[item]

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return '{0}{1}'.format(self.__class__.__name__, tuple(self.__files.values()))
```

Replace `multiremote_fm/__init__.py` entirely:

```python
"""Multi-remote file manager package."""

from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_remote_files.py tests/test_exceptions.py -v`

Expected: PASS — 16 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/files.py multiremote_fm/__init__.py tests/test_remote_files.py && git commit -m "Add RemoteFile/RemoteFileSet with name-keyed dedup and ordered indexing"
```

> Multi-owner file: this task's `multiremote_fm/__init__.py` is superseded by Tasks 4, 5, 6 and finally **Task 7**, which is authoritative.

---

### Task 3: `backends/base.py` — `Stat`, `Backend` ABC, and `FakeBackend`

Traces to spec §4.3 (S2 backend boundary), §4.8 (S7 FakeBackend).

**Files:**
- Create: `multiremote_fm/backends/__init__.py`
- Create: `multiremote_fm/backends/base.py`
- Create: `tests/fakes.py`
- Modify: `pyproject.toml` (`[tool.setuptools] packages` line)
- Test: `tests/test_backend_base.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `multiremote_fm.backends.base.Stat` — `NamedTuple` with fields `name: str`, `size: int`, `is_dir: bool`, in that order.
  - `multiremote_fm.backends.base.Backend` — ABC with abstract methods `connect(self) -> None`, `close(self) -> None`, `list(self, path: str) -> Iterable[Stat]`, `read(self, path: str) -> bytes`, `write(self, path: str, data: bytes) -> None`, `rename(self, src: str, dst: str) -> None`, `remove(self, path: str) -> None`.
  - Both re-exported from `multiremote_fm.backends`.
  - `tests.fakes.FakeBackend(tree: Optional[Dict[str, bytes]] = None)` — in-memory `Backend` with public attributes `.tree: Dict[str, bytes]` (flat path → content map), `.dirs: Set[str]`, `.connect_calls: int`, `.close_calls: int`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_backend_base.py`:

```python
import unittest

from multiremote_fm.backends import Backend, Stat

from tests.fakes import FakeBackend


class TestBackendBase(unittest.TestCase):
    def test_stat_fields_and_order(self):
        st = Stat('a.txt', 12, False)
        self.assertEqual(st.name, 'a.txt')
        self.assertEqual(st.size, 12)
        self.assertFalse(st.is_dir)
        self.assertEqual(tuple(st), ('a.txt', 12, False))
        self.assertEqual(Stat._fields, ('name', 'size', 'is_dir'))

    def test_backend_is_abstract(self):
        with self.assertRaises(TypeError):
            Backend()

    def test_backend_declares_exactly_the_seven_primitives(self):
        self.assertEqual(
            Backend.__abstractmethods__,
            frozenset({'connect', 'close', 'list', 'read', 'write', 'rename', 'remove'}),
        )

    def test_fake_backend_is_a_backend(self):
        self.assertIsInstance(FakeBackend(), Backend)

    def test_fake_backend_list_returns_only_direct_children(self):
        fake = FakeBackend({'a.txt': b'1', 'sub/b.txt': b'22'})
        fake.dirs.add('sub')
        top = sorted(fake.list('.'), key=lambda s: s.name)
        self.assertEqual([(s.name, s.size, s.is_dir) for s in top], [('a.txt', 1, False), ('sub', 0, True)])
        self.assertEqual([(s.name, s.size, s.is_dir) for s in fake.list('sub')], [('b.txt', 2, False)])

    def test_fake_backend_primitives_round_trip(self):
        fake = FakeBackend()
        fake.connect()
        fake.write('x/a.txt', b'hello')
        self.assertEqual(fake.read('x/a.txt'), b'hello')
        fake.rename('x/a.txt', 'y/a.txt')
        self.assertEqual(fake.read('y/a.txt'), b'hello')
        fake.remove('y/a.txt')
        with self.assertRaises(KeyError):
            fake.read('y/a.txt')
        fake.close()
        self.assertEqual(fake.connect_calls, 1)
        self.assertEqual(fake.close_calls, 1)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_backend_base.py -v`

Expected: FAIL — collection error `ModuleNotFoundError: No module named 'multiremote_fm.backends'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/backends/base.py`:

```python
"""The backend boundary: protocol primitives only.

A backend knows nothing about paths masks, filesets, `unlink`, or `download_content`.
Those belong to RemoteDriver, which implements the five operations once.
"""

from abc import ABC, abstractmethod
from typing import Iterable, NamedTuple


class Stat(NamedTuple):
    """One directory entry, protocol-independent."""

    name: str
    size: int
    is_dir: bool


class Backend(ABC):
    """Primitive operations every remote protocol must provide."""

    @abstractmethod
    def connect(self) -> None:
        """Open the connection if it is not already open. Idempotent."""
        raise NotImplementedError()

    @abstractmethod
    def close(self) -> None:
        """Close the connection if open. Idempotent."""
        raise NotImplementedError()

    @abstractmethod
    def list(self, path: str) -> Iterable[Stat]:
        """List the direct children of `path`."""
        raise NotImplementedError()

    @abstractmethod
    def read(self, path: str) -> bytes:
        """Return the full content of `path`."""
        raise NotImplementedError()

    @abstractmethod
    def write(self, path: str, data: bytes) -> None:
        """Write `data` to `path`, overwriting it."""
        raise NotImplementedError()

    @abstractmethod
    def rename(self, src: str, dst: str) -> None:
        """Rename `src` to `dst`."""
        raise NotImplementedError()

    @abstractmethod
    def remove(self, path: str) -> None:
        """Delete the file at `path`."""
        raise NotImplementedError()
```

Create `multiremote_fm/backends/__init__.py`:

```python
"""Protocol backends."""

from .base import Backend, Stat

__all__ = [
    'Backend',
    'Stat',
]
```

Create `tests/fakes.py`:

```python
"""In-memory Backend double, so every operation is testable without a network."""

from typing import Dict, List, Optional, Set

from multiremote_fm.backends import Backend, Stat


class FakeBackend(Backend):
    """A flat path -> content map that behaves like a directory tree."""

    def __init__(self, tree: Optional[Dict[str, bytes]] = None) -> None:
        self.tree: Dict[str, bytes] = dict(tree or {})
        self.dirs: Set[str] = set()
        self.connect_calls = 0
        self.close_calls = 0

    @staticmethod
    def _prefix(path: str) -> str:
        if path in ('', '.'):
            return ''
        return path.rstrip('/') + '/'

    def connect(self) -> None:
        self.connect_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    def list(self, path: str) -> List[Stat]:
        prefix = self._prefix(path)
        entries: List[Stat] = []
        for full, data in self.tree.items():
            if not full.startswith(prefix):
                continue
            rest = full[len(prefix):]
            if not rest or '/' in rest:
                continue
            entries.append(Stat(name=rest, size=len(data), is_dir=False))
        for directory in self.dirs:
            if not directory.startswith(prefix):
                continue
            rest = directory[len(prefix):]
            if not rest or '/' in rest:
                continue
            entries.append(Stat(name=rest, size=0, is_dir=True))
        return entries

    def read(self, path: str) -> bytes:
        return self.tree[path]

    def write(self, path: str, data: bytes) -> None:
        self.tree[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.tree[dst] = self.tree.pop(src)

    def remove(self, path: str) -> None:
        del self.tree[path]
```

In `pyproject.toml`, change the `[tool.setuptools]` packages line from:

```toml
packages = ["multiremote_fm"]
```

to:

```toml
packages = ["multiremote_fm", "multiremote_fm.backends"]
```

Then re-run the editable install so the new subpackage is registered:

```bash
venv/bin/pip install -e ".[dev]"
```

Expected: `Successfully installed multiremote-fm-0.2.0`.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_backend_base.py -v`

Expected: PASS — 6 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/backends pyproject.toml tests/fakes.py tests/test_backend_base.py && git commit -m "Add Backend ABC, Stat, and in-memory FakeBackend test double"
```

---

### Task 4: `driver.py` — the five operations, once, copy-on-write

Traces to spec §4.4 (S3), §4.3 consequences 1–2, §4.5 (`with_driver`), §4.6 (S5 errors), defects 5, 7, 8, 9.

**Files:**
- Create: `multiremote_fm/driver.py`
- Modify: `multiremote_fm/__init__.py` (whole file)
- Test: `tests/test_driver.py`

**Interfaces:**
- Consumes: `multiremote_fm.files.RemoteFile(name, content=b'', size=0)`, `multiremote_fm.files.RemoteFileSet(*files)` with `.add(*files)` / `__len__` / `__iter__`; `multiremote_fm.backends.base.Stat(name, size, is_dir)`; `multiremote_fm.backends.base.Backend` with `connect()`, `close()`, `list(path)`, `read(path)`, `write(path, data)`, `rename(src, dst)`, `remove(path)`; `multiremote_fm.exceptions.NothingToUploadException`; `tests.fakes.FakeBackend(tree)`.
- Produces:
  - `BaseDriver` ABC with exactly these eight abstract methods: `search(self, **kwargs) -> RemoteFileSet`, `download(self, unlink: bool = False, download_content: bool = True, **kwargs) -> RemoteFileSet`, `upload(self, **kwargs) -> 'BaseDriver'`, `move(self, destination: str, **kwargs) -> 'BaseDriver'`, `delete(self, **kwargs) -> 'BaseDriver'`, `with_path(self, path: str) -> 'BaseDriver'`, `with_mask(self, mask: str) -> 'BaseDriver'`, `with_files(self, files: RemoteFileSet) -> 'BaseDriver'`. No `set_files`, no `set_path`.
  - `RemoteDriver(backend: Backend, path: str = '', mask: str = '*', files: Optional[RemoteFileSet] = None)` implementing all eight, plus read-only properties `.backend -> Backend`, `.path -> str`, `.mask -> str`, `.files -> RemoteFileSet`, and `__str__` / `__repr__`.
  - `upload()` and `delete()` return `self`; `move(destination)` returns a copy with `path=destination`; `with_*` return copies sharing the same backend object.
  - Both re-exported from `multiremote_fm`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_driver.py`:

```python
import unittest

from multiremote_fm import (
    BaseDriver,
    NothingToUploadException,
    RemoteDriver,
    RemoteFile,
    RemoteFileSet,
)

from tests.fakes import FakeBackend


class TestRemoteDriverOperations(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeBackend(
            {
                'data/a.txt': b'aaa',
                'data/b.txt': b'bb',
                'data/c.log': b'c',
                'other/d.txt': b'd',
            }
        )
        self.fake.dirs.add('data/nested')
        self.driver = RemoteDriver(backend=self.fake)

    def test_is_a_base_driver(self):
        self.assertIsInstance(self.driver, BaseDriver)

    def test_default_mask_is_star_so_search_finds_everything(self):
        self.assertEqual(self.driver.mask, '*')
        self.assertEqual(self.driver.path, '')
        found = self.driver.with_path('data').search()
        self.assertEqual(len(found), 3)

    def test_search_returns_no_content_but_real_sizes(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        self.assertIsInstance(found, RemoteFileSet)
        self.assertEqual({f.name for f in found}, {'a.txt', 'b.txt'})
        for file in found:
            self.assertEqual(file.content, b'')
            self.assertGreater(file.size, 0)

    def test_download_returns_content(self):
        found = self.driver.with_path('data').with_mask('a.*').download()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'a.txt')
        self.assertEqual(found[0].content, b'aaa')
        self.assertEqual(found[0].size, 3)

    def test_download_skips_directories(self):
        names = {f.name for f in self.driver.with_path('data').search()}
        self.assertNotIn('nested', names)

    def test_download_unlink_removes_source(self):
        found = self.driver.with_path('data').with_mask('*.log').download(unlink=True)
        self.assertEqual(len(found), 1)
        self.assertNotIn('data/c.log', self.fake.tree)
        self.assertIn('data/a.txt', self.fake.tree)

    def test_upload_writes_every_file(self):
        fileset = RemoteFileSet(RemoteFile('u1.txt', b'one', 3), RemoteFile('u2.txt', b'two', 3))
        target = self.driver.with_path('out').with_files(fileset)
        self.assertIs(target.upload(), target)
        self.assertEqual(self.fake.tree['out/u1.txt'], b'one')
        self.assertEqual(self.fake.tree['out/u2.txt'], b'two')

    def test_upload_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('out').upload()

    def test_upload_rejects_non_remote_file_members(self):
        fileset = RemoteFileSet()
        fileset._RemoteFileSet__files['bogus'] = 'not-a-file'
        with self.assertRaises(TypeError):
            self.driver.with_path('out').with_files(fileset).upload()

    def test_move_renames_and_returns_copy_at_destination(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        source = self.driver.with_path('data').with_files(found)
        moved = source.move('archive')
        self.assertEqual(moved.path, 'archive')
        self.assertEqual(source.path, 'data')
        self.assertIn('archive/a.txt', self.fake.tree)
        self.assertNotIn('data/a.txt', self.fake.tree)

    def test_move_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('data').move('archive')

    def test_delete_removes_and_returns_self(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        target = self.driver.with_path('data').with_files(found)
        self.assertIs(target.delete(), target)
        self.assertNotIn('data/a.txt', self.fake.tree)
        self.assertNotIn('data/b.txt', self.fake.tree)
        self.assertIn('data/c.log', self.fake.tree)

    def test_delete_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('data').delete()

    def test_empty_path_joins_without_dot_prefix(self):
        driver = RemoteDriver(backend=FakeBackend({'top.txt': b'x'}))
        found = driver.download()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'top.txt')


class TestRemoteDriverCopyOnWrite(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeBackend({'a/one.txt': b'1', 'b/two.txt': b'22'})
        self.driver = RemoteDriver(backend=self.fake)

    def test_with_path_returns_new_object(self):
        copy = self.driver.with_path('a')
        self.assertIsNot(copy, self.driver)
        self.assertEqual(copy.path, 'a')
        self.assertEqual(self.driver.path, '')

    def test_with_mask_returns_new_object(self):
        copy = self.driver.with_mask('*.txt')
        self.assertIsNot(copy, self.driver)
        self.assertEqual(copy.mask, '*.txt')
        self.assertEqual(self.driver.mask, '*')

    def test_with_files_returns_new_object(self):
        fileset = RemoteFileSet(RemoteFile('x.txt'))
        copy = self.driver.with_files(fileset)
        self.assertIsNot(copy, self.driver)
        self.assertEqual(len(copy.files), 1)
        self.assertEqual(len(self.driver.files), 0)

    def test_copies_share_one_backend_instance(self):
        chain = self.driver.with_path('a').with_mask('*.txt').with_files(RemoteFileSet())
        self.assertIs(chain.backend, self.fake)
        self.assertIs(self.driver.backend, self.fake)

    def test_no_state_leaks_between_chains(self):
        first = self.driver.with_path('a').search()
        second = self.driver.with_path('b').search()
        self.assertEqual({f.name for f in first}, {'one.txt'})
        self.assertEqual({f.name for f in second}, {'two.txt'})
        self.assertEqual(self.driver.path, '')

    def test_file_with_driver_returns_configured_copy_without_mutating(self):
        file = RemoteFile('one.txt', b'1', 1)
        configured = file.with_driver(self.driver)
        self.assertIsNot(configured, self.driver)
        self.assertEqual(len(configured.files), 1)
        self.assertEqual(len(self.driver.files), 0)
        self.assertIs(configured.backend, self.fake)

    def test_fileset_with_driver_returns_configured_copy_without_mutating(self):
        fileset = RemoteFileSet(RemoteFile('one.txt', b'1', 1))
        configured = fileset.with_driver(self.driver)
        self.assertIsNot(configured, self.driver)
        self.assertEqual(len(configured.files), 1)
        self.assertEqual(len(self.driver.files), 0)

    def test_with_driver_preserves_path_and_mask_of_the_receiver(self):
        source = self.driver.with_path('a').with_mask('*.txt')
        found = source.search()
        configured = found.with_driver(source)
        self.assertEqual(configured.path, 'a')
        self.assertEqual(configured.mask, '*.txt')
        downloaded = configured.download()
        self.assertEqual({f.name for f in downloaded}, {'one.txt'})

    def test_no_set_path_or_set_files_mutators_exist(self):
        self.assertFalse(hasattr(self.driver, 'set_path'))
        self.assertFalse(hasattr(self.driver, 'set_files'))
        self.assertFalse(hasattr(BaseDriver, 'set_files'))

    def test_base_driver_declares_exactly_the_eight_frozen_methods(self):
        self.assertEqual(
            BaseDriver.__abstractmethods__,
            frozenset(
                {
                    'search',
                    'download',
                    'upload',
                    'move',
                    'delete',
                    'with_path',
                    'with_mask',
                    'with_files',
                }
            ),
        )

    def test_repr_and_str(self):
        driver = self.driver.with_path('a').with_mask('*.txt')
        self.assertEqual(str(driver), 'RemoteDriver(a, *.txt)')
        self.assertEqual(repr(driver), 'RemoteDriver(path=a, mask=*.txt)')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_driver.py -v`

Expected: FAIL — collection error `ImportError: cannot import name 'BaseDriver' from 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/driver.py`:

```python
"""The five file operations, implemented once over a Backend."""

import fnmatch
import logging
import posixpath
from abc import ABC, abstractmethod
from typing import Optional

from .backends.base import Backend
from .exceptions import NothingToUploadException
from .files import RemoteFile, RemoteFileSet

_logger = logging.getLogger(__name__)


def _join(base: str, name: str) -> str:
    """Join a remote directory and an entry name, treating '' and '.' as the root."""
    if base in ('', '.'):
        return name
    return posixpath.join(base, name)


class BaseDriver(ABC):
    """The frozen public surface every remote exposes."""

    @abstractmethod
    def search(self, **kwargs: object) -> RemoteFileSet:
        """Find files matching path and mask without downloading content."""
        raise NotImplementedError()

    @abstractmethod
    def download(
        self,
        unlink: bool = False,
        download_content: bool = True,
        **kwargs: object,
    ) -> RemoteFileSet:
        """Download files matching path and mask, optionally deleting the source."""
        raise NotImplementedError()

    @abstractmethod
    def upload(self, **kwargs: object) -> 'BaseDriver':
        """Upload the configured fileset into the configured path."""
        raise NotImplementedError()

    @abstractmethod
    def move(self, destination: str, **kwargs: object) -> 'BaseDriver':
        """Move the configured fileset to `destination`."""
        raise NotImplementedError()

    @abstractmethod
    def delete(self, **kwargs: object) -> 'BaseDriver':
        """Delete the configured fileset from the configured path."""
        raise NotImplementedError()

    @abstractmethod
    def with_path(self, path: str) -> 'BaseDriver':
        """Return a copy working in `path`."""
        raise NotImplementedError()

    @abstractmethod
    def with_mask(self, mask: str) -> 'BaseDriver':
        """Return a copy filtering by `mask`."""
        raise NotImplementedError()

    @abstractmethod
    def with_files(self, files: RemoteFileSet) -> 'BaseDriver':
        """Return a copy working with `files`."""
        raise NotImplementedError()


class RemoteDriver(BaseDriver):
    """Path, mask and fileset over a shared Backend. Copy-on-write."""

    def __init__(
        self,
        backend: Backend,
        path: str = '',
        mask: str = '*',
        files: Optional[RemoteFileSet] = None,
    ) -> None:
        self._backend = backend
        self._path = path
        self._mask = mask
        self._files = files if files is not None else RemoteFileSet()

    @property
    def backend(self) -> Backend:
        return self._backend

    @property
    def path(self) -> str:
        return self._path

    @property
    def mask(self) -> str:
        return self._mask

    @property
    def files(self) -> RemoteFileSet:
        return self._files

    def _copy(
        self,
        path: Optional[str] = None,
        mask: Optional[str] = None,
        files: Optional[RemoteFileSet] = None,
    ) -> 'RemoteDriver':
        """A new driver sharing this backend instance. Never clone the backend."""
        return RemoteDriver(
            backend=self._backend,
            path=self._path if path is None else path,
            mask=self._mask if mask is None else mask,
            files=self._files if files is None else files,
        )

    def with_path(self, path: str) -> 'RemoteDriver':
        return self._copy(path=path)

    def with_mask(self, mask: str) -> 'RemoteDriver':
        return self._copy(mask=mask)

    def with_files(self, files: RemoteFileSet) -> 'RemoteDriver':
        return self._copy(files=files)

    def _outgoing(self) -> RemoteFileSet:
        """The fileset for a write operation, validated."""
        if len(self._files) == 0:
            raise NothingToUploadException()
        for file in self._files:
            if not isinstance(file, RemoteFile):
                raise TypeError(
                    'Expected RemoteFile, got {0}'.format(type(file).__name__)
                )
        return self._files

    def search(self, **kwargs: object) -> RemoteFileSet:
        return self.download(unlink=False, download_content=False, **kwargs)

    def download(
        self,
        unlink: bool = False,
        download_content: bool = True,
        **kwargs: object,
    ) -> RemoteFileSet:
        self._backend.connect()
        base = self._path or '.'
        mask = self._mask or '*'
        fileset = RemoteFileSet()
        for entry in self._backend.list(base):
            if entry.is_dir:
                _logger.debug('Skipping directory %s', entry.name)
                continue
            if not fnmatch.fnmatch(entry.name, mask):
                continue
            full_path = _join(self._path, entry.name)
            content = self._backend.read(full_path) if download_content else b''
            fileset.add(RemoteFile(name=entry.name, content=content, size=entry.size))
            if unlink:
                _logger.debug('Deleting %s', full_path)
                self._backend.remove(full_path)
        return fileset

    def upload(self, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.write(_join(self._path, file.name), file.content or b'')
        return self

    def move(self, destination: str, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.rename(
                _join(self._path, file.name),
                _join(destination, file.name),
            )
        return self._copy(path=destination)

    def delete(self, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.remove(_join(self._path, file.name))
        return self

    def __str__(self) -> str:
        return 'RemoteDriver({0}, {1})'.format(self._path, self._mask)

    def __repr__(self) -> str:
        return 'RemoteDriver(path={0}, mask={1})'.format(self._path, self._mask)
```

Replace `multiremote_fm/__init__.py` entirely:

```python
"""Multi-remote file manager package."""

from .driver import BaseDriver, RemoteDriver
from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_driver.py -v`

Expected: PASS — 25 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/driver.py multiremote_fm/__init__.py tests/test_driver.py && git commit -m "Implement the five operations once in RemoteDriver with copy-on-write"
```

> Multi-owner file: this task's `multiremote_fm/__init__.py` is superseded by Tasks 5, 6 and finally **Task 7**, which is authoritative.

---

### Task 5: `LocalBackend` and the `Local` remote

Traces to spec §4.3 (S2), §4.2 (S1), defect 5, defect 7 (`local.py:25,48,50,57,59,67,69`).

**Files:**
- Create: `multiremote_fm/backends/local.py`
- Create: `multiremote_fm/remotes.py`
- Modify: `multiremote_fm/backends/__init__.py` (whole file)
- Modify: `multiremote_fm/__init__.py` (whole file)
- Test: `tests/test_local_dir.py`

**Interfaces:**
- Consumes: `multiremote_fm.backends.base.Backend` and `Stat(name, size, is_dir)`; `multiremote_fm.driver.RemoteDriver(backend, path='', mask='*', files=None)` with `with_path`, `with_mask`, `with_files`, `search`, `download(unlink, download_content)`, `upload`, `move(destination)`, `delete`, and properties `.path`, `.mask`, `.files`, `.backend`; `multiremote_fm.files.RemoteFile`, `RemoteFileSet`.
- Produces:
  - `multiremote_fm.backends.local.LocalBackend()` — `Backend` over `os`; `connect()`/`close()` are no-ops.
  - `multiremote_fm.remotes.Local()` — `RemoteDriver` subclass taking no arguments.
  - `LocalBackend` re-exported from `multiremote_fm.backends`; `Local` re-exported from `multiremote_fm`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_local_dir.py` entirely. Note `test_search_common` now asserts a count (spec §4.8) and `test_download_searched` carries the configured driver forward (spec §4.5):

```python
import glob
import os
import shutil
import tempfile
import unittest

from multiremote_fm import Local, RemoteFile, RemoteFileSet


class TestLocalDir(unittest.TestCase):
    local_dir_path: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.local_dir_path = os.environ.get('LOCAL_DIR_PATH') or tempfile.mkdtemp(
            prefix='multiremote-test-'
        )
        cls._owns_dir = 'LOCAL_DIR_PATH' not in os.environ
        os.makedirs(cls.local_dir_path, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._owns_dir:
            shutil.rmtree(cls.local_dir_path, ignore_errors=True)

    def setUp(self) -> None:
        for file_path in glob.glob(os.path.join(self.local_dir_path, '*')):
            if os.path.isfile(file_path):
                os.unlink(file_path)
        self.created = ['f1.xml', 'f2.csv', 'f3.xml', 'f4.doc', 'f5.xlsx', 'f6.doc', 'f7.jpg', 'f8.c']
        for name in self.created:
            with open(os.path.join(self.local_dir_path, name), mode='w') as handle:
                handle.write(name)
        self.driver = Local()

    def test_search_common(self):
        """Every file is found when no mask is set - the count assertion is the point.

        Named exactly `test_search_common` because spec criterion 11 names this
        identifier. Do not rename it.
        """
        files = self.driver.with_path(self.local_dir_path).search()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), len(self.created))
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)
            self.assertEqual(file.content, b'')

    def test_search_skips_subdirectories(self):
        os.makedirs(os.path.join(self.local_dir_path, 'subdir'), exist_ok=True)
        try:
            files = self.driver.with_path(self.local_dir_path).search()
            self.assertEqual(len(files), len(self.created))
            self.assertNotIn('subdir', {f.name for f in files})
        finally:
            os.rmdir(os.path.join(self.local_dir_path, 'subdir'))

    def test_search_by_mask(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.x*').search()
        self.assertEqual(len(files), 3)
        files = self.driver.with_path(self.local_dir_path).with_mask('*.c').search()
        self.assertEqual(len(files), 1)

    def test_download(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.doc').download()
        self.assertEqual(len(files), 2)
        for file in files:
            self.assertGreater(len(file.content), 0)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)

    def test_download_unlink(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.jpg').download(unlink=True)
        self.assertEqual(len(files), 1)
        deleted = self.driver.with_path(self.local_dir_path).with_mask('*.jpg').search()
        self.assertEqual(len(deleted), 0)

    def test_download_searched(self):
        source = self.driver.with_path(self.local_dir_path).with_mask('*.x*')
        found_file_list = source.search()
        self.assertEqual(len(found_file_list), 3)
        files = found_file_list.with_driver(source).download()
        self.assertEqual(len(files), 3)
        for file in files:
            self.assertGreater(len(file.content), 0)

    def test_upload_writes_files(self):
        target_dir = os.path.join(self.local_dir_path, 'out')
        os.makedirs(target_dir, exist_ok=True)
        fileset = RemoteFileSet(RemoteFile('up.txt', b'payload', 7))
        self.driver.with_path(target_dir).with_files(fileset).upload()
        with open(os.path.join(target_dir, 'up.txt'), mode='rb') as handle:
            self.assertEqual(handle.read(), b'payload')
        shutil.rmtree(target_dir)

    def test_move_files(self):
        target_dir = os.path.join(self.local_dir_path, 'archive')
        os.makedirs(target_dir, exist_ok=True)
        source = self.driver.with_path(self.local_dir_path).with_mask('*.csv')
        found = source.search()
        moved = source.with_files(found).move(target_dir)
        self.assertEqual(moved.path, target_dir)
        self.assertTrue(os.path.isfile(os.path.join(target_dir, 'f2.csv')))
        self.assertFalse(os.path.isfile(os.path.join(self.local_dir_path, 'f2.csv')))
        shutil.rmtree(target_dir)

    def test_delete_files(self):
        source = self.driver.with_path(self.local_dir_path).with_mask('*.c')
        found = source.search()
        source.with_files(found).delete()
        self.assertFalse(os.path.isfile(os.path.join(self.local_dir_path, 'f8.c')))

    def test_local_takes_no_constructor_arguments(self):
        with self.assertRaises(TypeError):
            Local(pasword='typo')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_local_dir.py -v`

Expected: FAIL — collection error `ImportError: cannot import name 'Local' from 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/backends/local.py`:

```python
"""Local filesystem backend."""

import os
from typing import List

from .base import Backend, Stat


class LocalBackend(Backend):
    """Primitives over the local filesystem."""

    def connect(self) -> None:
        """The local filesystem needs no connection."""

    def close(self) -> None:
        """The local filesystem needs no teardown."""

    def list(self, path: str) -> List[Stat]:
        entries: List[Stat] = []
        with os.scandir(path or '.') as scan:
            for entry in scan:
                if entry.is_dir():
                    entries.append(Stat(name=entry.name, size=0, is_dir=True))
                    continue
                if not entry.is_file():
                    continue
                entries.append(
                    Stat(name=entry.name, size=entry.stat().st_size, is_dir=False)
                )
        return entries

    def read(self, path: str) -> bytes:
        with open(path, mode='rb') as handle:
            return handle.read()

    def write(self, path: str, data: bytes) -> None:
        with open(path, mode='wb') as handle:
            handle.write(data)

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)

    def remove(self, path: str) -> None:
        os.unlink(path)
```

Create `multiremote_fm/remotes.py`:

```python
"""The frozen public remotes. Each one builds a backend and delegates."""

from .backends.local import LocalBackend
from .driver import RemoteDriver


class Local(RemoteDriver):
    """Local directory remote."""

    def __init__(self) -> None:
        super().__init__(backend=LocalBackend())
```

Replace `multiremote_fm/backends/__init__.py` entirely:

```python
"""Protocol backends."""

from .base import Backend, Stat
from .local import LocalBackend

__all__ = [
    'Backend',
    'Stat',
    'LocalBackend',
]
```

Replace `multiremote_fm/__init__.py` entirely:

```python
"""Multi-remote file manager package."""

from .driver import BaseDriver, RemoteDriver
from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet
from .remotes import Local

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_local_dir.py -v`

Expected: PASS — 10 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/backends/local.py multiremote_fm/backends/__init__.py multiremote_fm/remotes.py multiremote_fm/__init__.py tests/test_local_dir.py && git commit -m "Add LocalBackend and Local remote; fix empty-mask search returning zero files"
```

> Multi-owner files: this task's `multiremote_fm/remotes.py`, `multiremote_fm/backends/__init__.py` and `multiremote_fm/__init__.py` are superseded by Task 6 and finally **Task 7**, which is authoritative. Never re-run this task after Task 6 or 7.

---

### Task 6: `FtpBackend` and the `FTP` / `FTPS` remotes

Traces to spec §4.3 (S2, the FTP awkwardness), defect 10 (connection reuse, dead `_ensure_connection`, unused `encoding`, duplicated `FTPS` signature), defect 7 (`ftp.py:99,102,109,112,121,124`).

**Files:**
- Create: `multiremote_fm/backends/ftp.py`
- Modify: `multiremote_fm/remotes.py` (whole file)
- Modify: `multiremote_fm/backends/__init__.py` (whole file)
- Modify: `multiremote_fm/__init__.py` (whole file)
- Modify: `tests/_test_ftp.py:1-6`
- Test: `tests/test_ftp_backend.py`

**Interfaces:**
- Consumes: `multiremote_fm.backends.base.Backend`, `Stat(name, size, is_dir)`; `multiremote_fm.backends.local.LocalBackend()`; `multiremote_fm.driver.RemoteDriver(backend, path='', mask='*', files=None)`; `multiremote_fm.files.RemoteFile`, `RemoteFileSet`.
- Produces:
  - `multiremote_fm.backends.ftp.FtpBackend(host: str, port: int, login: str, password: str, passive_mode: bool = True, response_timeout: int = 30, encoding: str = 'utf-8', tls: bool = False)` — a `Backend` that stores one `ftplib.FTP` in `self._ftp`, reuses it, honours `encoding` through `ftplib.FTP(encoding=...)`, and lists via `MLSD` with an `NLST` + `SIZE` fallback.
  - `multiremote_fm.remotes.FTP(host: str, port: int, login: str, password: str, passive_mode: bool = True, response_timeout: int = 30, encoding: str = 'utf-8', tls: bool = False)`.
  - `multiremote_fm.remotes.FTPS(host: str, port: int, login: str, password: str, passive_mode: bool = True, response_timeout: int = 30, encoding: str = 'utf-8')` — subclass passing `tls=True`.
  - `FtpBackend` re-exported from `multiremote_fm.backends`; `FTP` and `FTPS` re-exported from `multiremote_fm`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ftp_backend.py`:

```python
import ftplib
import unittest
from unittest.mock import MagicMock, patch

from multiremote_fm import FTP, FTPS, RemoteFile, RemoteFileSet
from multiremote_fm.backends.ftp import FtpBackend


class TestFtpBackend(unittest.TestCase):
    def setUp(self) -> None:
        self.ftplib_patcher = patch('multiremote_fm.backends.ftp.ftplib')
        self.mock_ftplib = self.ftplib_patcher.start()
        self.mock_ftplib.all_errors = ftplib.all_errors
        self.mock_ftplib.error_perm = ftplib.error_perm
        self.mock_ftplib.error_proto = ftplib.error_proto
        self.mock_client = MagicMock()
        self.mock_ftplib.FTP.return_value = self.mock_client
        self.mock_ftplib.FTP_TLS.return_value = self.mock_client

    def tearDown(self) -> None:
        self.ftplib_patcher.stop()

    def _backend(self, **overrides):
        kwargs = dict(host='ftp.example.com', port=21, login='user', password='pass')
        kwargs.update(overrides)
        return FtpBackend(**kwargs)

    def test_connect_passes_encoding_and_timeout_then_logs_in(self):
        backend = self._backend(encoding='latin-1', response_timeout=17)
        backend.connect()
        self.mock_ftplib.FTP.assert_called_once_with(encoding='latin-1')
        self.mock_client.connect.assert_called_once_with(
            host='ftp.example.com', port=21, timeout=17
        )
        self.mock_client.login.assert_called_once_with(user='user', passwd='pass')
        self.mock_client.prot_p.assert_not_called()

    def test_connect_is_reused_not_reopened(self):
        backend = self._backend()
        backend.connect()
        backend.connect()
        backend.connect()
        self.assertEqual(self.mock_ftplib.FTP.call_count, 1)

    def test_close_clears_the_stored_connection(self):
        backend = self._backend()
        backend.connect()
        backend.close()
        self.mock_client.close.assert_called_once_with()
        backend.connect()
        self.assertEqual(self.mock_ftplib.FTP.call_count, 2)

    def test_passive_mode_disabled_calls_set_pasv_false(self):
        backend = self._backend(passive_mode=False)
        backend.connect()
        self.mock_client.set_pasv.assert_called_once_with(False)

    def test_tls_uses_ftp_tls_and_prot_p(self):
        backend = self._backend(tls=True)
        backend.connect()
        self.mock_ftplib.FTP_TLS.assert_called_once_with(encoding='utf-8')
        self.mock_client.prot_p.assert_called_once_with()

    def test_list_uses_mlsd_when_available(self):
        self.mock_client.mlsd.return_value = [
            ('.', {'type': 'cdir'}),
            ('..', {'type': 'pdir'}),
            ('sub', {'type': 'dir'}),
            ('a.txt', {'type': 'file', 'size': '12'}),
        ]
        backend = self._backend()
        entries = sorted(backend.list('/incoming'), key=lambda s: s.name)
        self.mock_client.mlsd.assert_called_once_with('/incoming', facts=['type', 'size'])
        self.mock_client.nlst.assert_not_called()
        self.assertEqual(
            [(e.name, e.size, e.is_dir) for e in entries],
            [('a.txt', 12, False), ('sub', 0, True)],
        )

    def test_list_falls_back_to_nlst_and_size(self):
        self.mock_client.mlsd.side_effect = ftplib.error_perm('500 unknown command')
        self.mock_client.nlst.return_value = ['a.txt', 'subdir']

        def fake_size(path):
            if path == '/incoming/a.txt':
                return 12
            raise ftplib.error_perm('550 not a regular file')

        self.mock_client.size.side_effect = fake_size
        backend = self._backend()
        entries = sorted(backend.list('/incoming'), key=lambda s: s.name)
        self.assertEqual(
            [(e.name, e.size, e.is_dir) for e in entries],
            [('a.txt', 12, False), ('subdir', 0, True)],
        )

    def test_list_fallback_handles_absolute_nlst_output(self):
        self.mock_client.mlsd.side_effect = ftplib.error_perm('500 unknown command')
        self.mock_client.nlst.return_value = ['/incoming/a.txt']
        self.mock_client.size.return_value = 3
        backend = self._backend()
        entries = list(backend.list('/incoming'))
        self.assertEqual([(e.name, e.size, e.is_dir) for e in entries], [('a.txt', 3, False)])
        self.mock_client.size.assert_called_once_with('/incoming/a.txt')

    def test_read_retrieves_binary_content(self):
        def fake_retrbinary(command, callback, blocksize=8192):
            self.assertEqual(command, 'RETR /incoming/a.txt')
            callback(b'hello ')
            callback(b'world')

        self.mock_client.retrbinary.side_effect = fake_retrbinary
        backend = self._backend()
        self.assertEqual(backend.read('/incoming/a.txt'), b'hello world')

    def test_write_stores_binary_content(self):
        backend = self._backend()
        backend.write('/out/a.txt', b'payload')
        args, _ = self.mock_client.storbinary.call_args
        self.assertEqual(args[0], 'STOR /out/a.txt')
        self.assertEqual(args[1].read(), b'payload')

    def test_rename_and_remove(self):
        backend = self._backend()
        backend.rename('/a/x.txt', '/b/x.txt')
        self.mock_client.rename.assert_called_once_with('/a/x.txt', '/b/x.txt')
        backend.remove('/a/y.txt')
        self.mock_client.delete.assert_called_once_with('/a/y.txt')


class TestFtpRemotes(unittest.TestCase):
    def setUp(self) -> None:
        self.ftplib_patcher = patch('multiremote_fm.backends.ftp.ftplib')
        self.mock_ftplib = self.ftplib_patcher.start()
        self.mock_ftplib.all_errors = ftplib.all_errors
        self.mock_ftplib.error_perm = ftplib.error_perm
        self.mock_ftplib.error_proto = ftplib.error_proto
        self.mock_client = MagicMock()
        self.mock_ftplib.FTP.return_value = self.mock_client
        self.mock_ftplib.FTP_TLS.return_value = self.mock_client

    def tearDown(self) -> None:
        self.ftplib_patcher.stop()

    def test_ftp_search_uses_one_connection_for_the_whole_chain(self):
        self.mock_client.mlsd.return_value = [('a.xml', {'type': 'file', 'size': '4'})]
        ftp = FTP(host='ftp.example.com', port=21, login='user', password='pass')
        found = ftp.with_path('/incoming').with_mask('*.xml').search()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'a.xml')
        self.assertEqual(found[0].size, 4)
        self.assertEqual(self.mock_ftplib.FTP.call_count, 1)

    def test_ftp_upload_uses_the_same_backend_instance(self):
        ftp = FTP(host='ftp.example.com', port=21, login='user', password='pass')
        target = ftp.with_path('/out').with_files(RemoteFileSet(RemoteFile('a.txt', b'x', 1)))
        self.assertIs(target.backend, ftp.backend)
        target.upload()
        self.assertEqual(self.mock_client.storbinary.call_count, 1)

    def test_ftps_sets_tls(self):
        ftps = FTPS(host='ftps.example.com', port=21, login='user', password='pass')
        ftps.backend.connect()
        self.mock_ftplib.FTP_TLS.assert_called_once_with(encoding='utf-8')
        self.mock_client.prot_p.assert_called_once_with()

    def test_ftp_rejects_unknown_kwargs(self):
        with self.assertRaises(TypeError):
            FTP(host='h', port=21, login='u', password='p', pasword='typo')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_ftp_backend.py -v`

Expected: FAIL — collection error `ImportError: cannot import name 'FTP' from 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/backends/ftp.py`:

```python
"""FTP and FTPS backend.

FTP is the awkward protocol: NLST returns names with no sizes. That complexity lives
here, in list(), instead of leaking into the five operations.
"""

import ftplib
import logging
import posixpath
from io import BytesIO
from typing import List, Optional

from .base import Backend, Stat

_logger = logging.getLogger(__name__)


class FtpBackend(Backend):
    """Primitives over a single reused ftplib connection."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
        tls: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.passive_mode = passive_mode
        self.response_timeout = response_timeout
        self.encoding = encoding
        self.tls = tls
        self._ftp: Optional[ftplib.FTP] = None

    def connect(self) -> None:
        if self._ftp is not None:
            return
        client = (
            ftplib.FTP_TLS(encoding=self.encoding)
            if self.tls
            else ftplib.FTP(encoding=self.encoding)
        )
        if not self.passive_mode:
            client.set_pasv(False)
        client.connect(host=self.host, port=self.port, timeout=self.response_timeout)
        client.login(user=self.login, passwd=self.password)
        if self.tls:
            client.prot_p()
        self._ftp = client

    def close(self) -> None:
        if self._ftp is None:
            return
        try:
            self._ftp.close()
        except ftplib.all_errors:
            _logger.warning('Error closing FTP client')
        finally:
            self._ftp = None

    def _client(self) -> ftplib.FTP:
        self.connect()
        if self._ftp is None:
            raise ConnectionError('FTP client is not connected')
        return self._ftp

    def list(self, path: str) -> List[Stat]:
        client = self._client()
        base = path or '.'
        try:
            listing = list(client.mlsd(base, facts=['type', 'size']))
        except (ftplib.error_perm, ftplib.error_proto):
            _logger.debug('MLSD unsupported on %s, falling back to NLST', self.host)
            return self._list_nlst(client, base)
        entries: List[Stat] = []
        for name, facts in listing:
            if name in ('.', '..'):
                continue
            entry_type = facts.get('type', 'file')
            if entry_type in ('dir', 'cdir', 'pdir'):
                entries.append(Stat(name=name, size=0, is_dir=True))
                continue
            entries.append(Stat(name=name, size=int(facts.get('size') or 0), is_dir=False))
        return entries

    def _list_nlst(self, client: ftplib.FTP, base: str) -> List[Stat]:
        entries: List[Stat] = []
        for raw in client.nlst(base):
            name = posixpath.basename(raw) or raw
            if name in ('.', '..'):
                continue
            full = raw if '/' in raw else posixpath.join(base, name)
            try:
                size = client.size(full)
            except ftplib.all_errors:
                size = None
            entries.append(Stat(name=name, size=size or 0, is_dir=size is None))
        return entries

    def read(self, path: str) -> bytes:
        client = self._client()
        buffer = BytesIO()
        client.retrbinary('RETR {0}'.format(path), buffer.write, blocksize=32768)
        return buffer.getvalue()

    def write(self, path: str, data: bytes) -> None:
        client = self._client()
        client.storbinary('STOR {0}'.format(path), BytesIO(data))

    def rename(self, src: str, dst: str) -> None:
        self._client().rename(src, dst)

    def remove(self, path: str) -> None:
        self._client().delete(path)
```

Replace `multiremote_fm/remotes.py` entirely:

```python
"""The frozen public remotes. Each one builds a backend and delegates."""

from .backends.ftp import FtpBackend
from .backends.local import LocalBackend
from .driver import RemoteDriver


class Local(RemoteDriver):
    """Local directory remote."""

    def __init__(self) -> None:
        super().__init__(backend=LocalBackend())


class FTP(RemoteDriver):
    """Standard FTP remote."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
        tls: bool = False,
    ) -> None:
        super().__init__(
            backend=FtpBackend(
                host=host,
                port=port,
                login=login,
                password=password,
                passive_mode=passive_mode,
                response_timeout=response_timeout,
                encoding=encoding,
                tls=tls,
            )
        )


class FTPS(FTP):
    """FTP over SSL/TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            login=login,
            password=password,
            passive_mode=passive_mode,
            response_timeout=response_timeout,
            encoding=encoding,
            tls=True,
        )
```

Replace `multiremote_fm/backends/__init__.py` entirely:

```python
"""Protocol backends."""

from .base import Backend, Stat
from .ftp import FtpBackend
from .local import LocalBackend

__all__ = [
    'Backend',
    'Stat',
    'LocalBackend',
    'FtpBackend',
]
```

Replace `multiremote_fm/__init__.py` entirely:

```python
"""Multi-remote file manager package."""

from .driver import BaseDriver, RemoteDriver
from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet
from .remotes import FTP, FTPS, Local

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'FTP',
    'FTPS',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

Fix the broken imports at `tests/_test_ftp.py:1-6`, replacing lines 1–4 with:

```python
import os
import unittest

from multiremote_fm import FTP, FTPS, RemoteFile, RemoteFileSet
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_ftp_backend.py -v`

Expected: PASS — 15 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/backends/ftp.py multiremote_fm/backends/__init__.py multiremote_fm/remotes.py multiremote_fm/__init__.py tests/test_ftp_backend.py tests/_test_ftp.py && git commit -m "Add FtpBackend with connection reuse, MLSD/NLST listing, honoured encoding"
```

> Multi-owner files: this task's `multiremote_fm/remotes.py`, `multiremote_fm/backends/__init__.py` and `multiremote_fm/__init__.py` are all superseded by **Task 7**, which is authoritative. Never re-run this task after Task 7.

---

### Task 7: `SftpBackend` and the `SFTP` remote

Traces to spec §4.3 (S2 SFTP paragraph), defect 4 (annotation evaluation), defect 13 (the 3 `test_sftp` failures), defect 3.

**Files:**
- Create: `multiremote_fm/backends/sftp.py`
- Modify: `multiremote_fm/remotes.py` (whole file)
- Modify: `multiremote_fm/backends/__init__.py` (whole file)
- Modify: `multiremote_fm/__init__.py` (whole file)
- Test: `tests/test_sftp.py`

**The SFTP timeout mechanism, with evidence.** The spec's §4.8 originally instructed that the `timeout` argument asserted at `tests/test_sftp.py:83,110` be "actually passed" to `Transport.connect`. **That is impossible**, and spec §4.8 has since been corrected to match what follows — this task and the spec now agree. Verified against the installed paramiko 5.0.0:

```
paramiko.Transport.connect signature = (self, hostkey=None, username='', password=None, pkey=None)
```

There is no `timeout` parameter (`paramiko/transport.py:1268`), which is why `drivers/sftp.py:88` had it commented out; passing it would raise `TypeError`. `response_timeout` is documented (`README.md:205,217`) as the connection timeout, so it is honoured where paramiko actually supports it: the TCP connect is made with `socket.create_connection(..., timeout=response_timeout)` and the resulting socket handed to `paramiko.Transport`, with `banner_timeout` and `auth_timeout` also set from it (all three verified present on a real `Transport` instance). The two tests therefore assert *that*, not a nonexistent kwarg. Defect 13's intent — `response_timeout` stops being silently ignored — is met.

**Interfaces:**
- Consumes: `multiremote_fm.backends.base.Backend`, `Stat(name, size, is_dir)`; `multiremote_fm.backends.local.LocalBackend()`; `multiremote_fm.backends.ftp.FtpBackend(host, port, login, password, passive_mode, response_timeout, encoding, tls)`; `multiremote_fm.driver.RemoteDriver(backend, path='', mask='*', files=None)`; `multiremote_fm.exceptions.SSHPasswordRSAError`; `multiremote_fm.files.RemoteFile`, `RemoteFileSet`.
- Produces:
  - `multiremote_fm.backends.sftp.SftpBackend(host: str, port: int = 22, login: str = '', password: Optional[str] = None, rsa: Optional[bytes] = None, response_timeout: int = 30)` — raises `ImportError('SFTP support requires paramiko: pip install multiremote-fm[sftp]')` from `__init__` when paramiko is absent. Module carries `from __future__ import annotations`.
  - `multiremote_fm.remotes.SFTP(host: str, port: int = 22, login: str = '', password: Optional[str] = None, rsa: Optional[bytes] = None, response_timeout: int = 30)` with `__enter__` returning `self` and `__exit__` closing the backend. Raises `SSHPasswordRSAError` when neither `password` nor `rsa` is given.
  - `SftpBackend` re-exported from `multiremote_fm.backends`; `SFTP` re-exported from `multiremote_fm`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_sftp.py` entirely:

```python
import socket
import unittest
from unittest.mock import MagicMock, Mock, patch

from multiremote_fm import SFTP, RemoteFile, RemoteFileSet, SSHPasswordRSAError

RSA_KEY = b'-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----'


class TestSFTP(unittest.TestCase):
    """SFTP driver and backend behaviour, with paramiko mocked."""

    def setUp(self) -> None:
        self.paramiko_patcher = patch('multiremote_fm.backends.sftp.paramiko')
        self.mock_paramiko = self.paramiko_patcher.start()
        self.socket_patcher = patch('multiremote_fm.backends.sftp.socket.create_connection')
        self.mock_create_connection = self.socket_patcher.start()
        self.mock_socket = MagicMock(spec=socket.socket)
        self.mock_create_connection.return_value = self.mock_socket

        self.mock_transport = MagicMock()
        self.mock_transport.is_active.return_value = True
        self.mock_sftp = MagicMock()
        self.mock_paramiko.Transport.return_value = self.mock_transport
        self.mock_paramiko.SFTPClient.from_transport.return_value = self.mock_sftp

    def tearDown(self) -> None:
        self.socket_patcher.stop()
        self.paramiko_patcher.stop()

    def _sftp(self, **overrides):
        kwargs = dict(host='test.com', port=22, login='testuser', password='testpass')
        kwargs.update(overrides)
        return SFTP(**kwargs)

    def test_import_without_paramiko(self):
        """Constructing SFTP without paramiko raises a clear ImportError, not AttributeError."""
        with patch('multiremote_fm.backends.sftp.paramiko', None):
            with self.assertRaises(ImportError) as cm:
                SFTP(host='test', port=22, login='user', password='pass')
            self.assertEqual(
                str(cm.exception),
                'SFTP support requires paramiko: pip install multiremote-fm[sftp]',
            )

    def test_init_without_password_or_rsa(self):
        with self.assertRaises(SSHPasswordRSAError):
            SFTP(host='test', port=22, login='user')

    def test_init_with_password(self):
        sftp = self._sftp()
        self.assertEqual(sftp.backend.host, 'test.com')
        self.assertEqual(sftp.backend.port, 22)
        self.assertEqual(sftp.backend.login, 'testuser')
        self.assertEqual(sftp.backend.password, 'testpass')
        self.assertEqual(sftp.backend.response_timeout, 30)

    def test_port_defaults_to_22(self):
        sftp = SFTP(host='test.com', login='testuser', password='testpass')
        self.assertEqual(sftp.backend.port, 22)

    def test_init_with_rsa(self):
        sftp = self._sftp(password=None, rsa=RSA_KEY)
        self.assertEqual(sftp.backend.rsa, RSA_KEY)

    def test_connect_with_password(self):
        """response_timeout is honoured at the socket and at banner/auth level.

        paramiko 5.0.0's Transport.connect signature is
        (self, hostkey=None, username='', password=None, pkey=None) - it takes no
        timeout, so the timeout is applied where paramiko supports it.
        """
        sftp = self._sftp(response_timeout=30)
        sftp.backend.connect()

        self.mock_create_connection.assert_called_once_with(('test.com', 22), timeout=30)
        self.mock_paramiko.Transport.assert_called_once_with(self.mock_socket)
        self.assertEqual(self.mock_transport.banner_timeout, 30)
        self.assertEqual(self.mock_transport.auth_timeout, 30)
        self.mock_transport.connect.assert_called_once_with(
            username='testuser',
            pkey=None,
            password='testpass',
        )
        self.mock_paramiko.SFTPClient.from_transport.assert_called_once_with(self.mock_transport)

    def test_connect_with_rsa(self):
        mock_rsa_key = Mock()
        self.mock_paramiko.RSAKey.from_private_key.return_value = mock_rsa_key
        sftp = self._sftp(password=None, rsa=RSA_KEY, response_timeout=45)

        sftp.backend.connect()

        self.mock_paramiko.RSAKey.from_private_key.assert_called_once()
        self.mock_create_connection.assert_called_once_with(('test.com', 22), timeout=45)
        self.mock_transport.connect.assert_called_once_with(
            username='testuser',
            pkey=mock_rsa_key,
            password=None,
        )

    def test_connect_is_reused_not_reopened(self):
        sftp = self._sftp()
        sftp.backend.connect()
        sftp.backend.connect()
        self.assertEqual(self.mock_paramiko.Transport.call_count, 1)

    def test_close_tears_down_client_and_transport(self):
        sftp = self._sftp()
        sftp.backend.connect()
        sftp.backend.close()
        self.mock_sftp.close.assert_called_once_with()
        self.mock_transport.close.assert_called_once_with()

    def test_context_manager_connects_and_closes(self):
        sftp = self._sftp()
        with sftp as handle:
            self.assertIs(handle, sftp)
            self.assertEqual(self.mock_paramiko.Transport.call_count, 1)
        self.mock_transport.close.assert_called_once_with()

    def _listing(self, *specs):
        entries = []
        for filename, size, mode in specs:
            entry = Mock()
            entry.filename = filename
            entry.st_size = size
            entry.st_mode = mode
            entries.append(entry)
        return entries

    def test_search_files(self):
        self.mock_sftp.listdir_attr.return_value = self._listing(
            ('test1.txt', 100, 33188),
            ('test2.txt', 200, 33188),
            ('adir', 0, 16877),
        )
        sftp = self._sftp()
        files = sftp.with_path('/remote/path').with_mask('*.txt').search()

        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 2)
        self.assertEqual({f.name for f in files}, {'test1.txt', 'test2.txt'})
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertEqual(file.content, b'')

    def test_download_files(self):
        self.mock_sftp.listdir_attr.return_value = self._listing(('test.txt', 11, 33188))

        def mock_getfo(remotepath, fl):
            self.assertEqual(remotepath, '/remote/path/test.txt')
            fl.write(b'Hello World')

        self.mock_sftp.getfo.side_effect = mock_getfo
        sftp = self._sftp()
        files = sftp.with_path('/remote/path').with_mask('*.txt').download()

        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, 'test.txt')
        self.assertEqual(files[0].content, b'Hello World')
        self.assertEqual(files[0].size, 11)

    def test_download_unlink_removes_remote_file(self):
        self.mock_sftp.listdir_attr.return_value = self._listing(('test.txt', 1, 33188))
        self.mock_sftp.getfo.side_effect = lambda remotepath, fl: fl.write(b'x')
        sftp = self._sftp()
        sftp.with_path('/remote/path').with_mask('*.txt').download(unlink=True)
        self.mock_sftp.unlink.assert_called_once_with('/remote/path/test.txt')

    def test_upload_files(self):
        fileset = RemoteFileSet(
            RemoteFile(name='upload1.txt', content=b'Content 1', size=9),
            RemoteFile(name='upload2.txt', content=b'Content 2', size=9),
        )
        sftp = self._sftp()
        target = sftp.with_path('/upload/path').with_files(fileset)
        result = target.upload()

        self.assertIs(result, target)
        self.assertEqual(self.mock_sftp.putfo.call_count, 2)
        uploaded = {call.kwargs['remotepath'] for call in self.mock_sftp.putfo.call_args_list}
        self.assertEqual(uploaded, {'/upload/path/upload1.txt', '/upload/path/upload2.txt'})

    def test_move_files(self):
        fileset = RemoteFileSet(RemoteFile(name='move1.txt', content=b'', size=0))
        sftp = self._sftp()
        source = sftp.with_path('/source').with_files(fileset)
        moved = source.move('/destination')

        self.assertEqual(moved.path, '/destination')
        self.assertEqual(source.path, '/source')
        self.mock_sftp.rename.assert_called_once_with(
            '/source/move1.txt', '/destination/move1.txt'
        )

    def test_delete_files(self):
        fileset = RemoteFileSet(RemoteFile(name='delete1.txt', content=b'', size=0))
        sftp = self._sftp()
        target = sftp.with_path('/path').with_files(fileset)
        result = target.delete()

        self.assertIs(result, target)
        self.mock_sftp.unlink.assert_called_once_with('/path/delete1.txt')

    def test_invalid_rsa_key_raises_value_error(self):
        self.mock_paramiko.RSAKey.from_private_key.side_effect = ValueError('bad key')
        sftp = self._sftp(password=None, rsa=RSA_KEY)
        with self.assertRaises(ValueError) as cm:
            sftp.backend.connect()
        self.assertIn('Invalid RSA key', str(cm.exception))

    def test_missing_sftp_channel_raises_connection_error(self):
        self.mock_paramiko.SFTPClient.from_transport.return_value = None
        sftp = self._sftp()
        with self.assertRaises(ConnectionError):
            sftp.backend.connect()


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_sftp.py -v`

Expected: FAIL — collection error `ImportError: cannot import name 'SFTP' from 'multiremote_fm'`.

- [ ] **Step 3: Write minimal implementation**

Create `multiremote_fm/backends/sftp.py`:

```python
"""SFTP backend.

`from __future__ import annotations` is load-bearing: it stops every paramiko
annotation below from being evaluated at import time, so this module is importable
without paramiko installed and the failure happens at construction, with a message
that says what to do.
"""

from __future__ import annotations

import logging
import socket
from io import BytesIO, StringIO
from stat import S_ISDIR
from typing import List, Optional

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised with paramiko patched to None
    paramiko = None  # type: ignore[assignment]

from .base import Backend, Stat

_logger = logging.getLogger(__name__)

_MISSING_PARAMIKO = 'SFTP support requires paramiko: pip install multiremote-fm[sftp]'


class SftpBackend(Backend):
    """Primitives over a single reused paramiko SFTP channel."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        login: str = '',
        password: Optional[str] = None,
        rsa: Optional[bytes] = None,
        response_timeout: int = 30,
    ) -> None:
        if paramiko is None:
            raise ImportError(_MISSING_PARAMIKO)
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.rsa = rsa
        self.response_timeout = response_timeout
        self._transport: Optional[paramiko.Transport] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def _load_key(self) -> Optional[paramiko.RSAKey]:
        if not self.rsa:
            return None
        try:
            return paramiko.RSAKey.from_private_key(StringIO(self.rsa.decode('utf-8')))
        except ValueError as exc:
            raise ValueError('Invalid RSA key: {0}'.format(exc)) from exc

    def connect(self) -> None:
        if self._sftp is not None and self._transport is not None and self._transport.is_active():
            return
        self.close()
        rsa_key = self._load_key()
        # paramiko 5.0.0's Transport.connect takes no timeout, so response_timeout is
        # applied to the TCP connect and to the banner/auth phases instead.
        sock = socket.create_connection((self.host, self.port), timeout=self.response_timeout)
        sock.settimeout(None)
        transport = paramiko.Transport(sock)
        transport.set_log_channel(__name__)
        transport.banner_timeout = self.response_timeout
        transport.auth_timeout = self.response_timeout
        self._transport = transport
        try:
            transport.connect(username=self.login, pkey=rsa_key, password=self.password)
            client = paramiko.SFTPClient.from_transport(transport)
            if client is None:
                raise ConnectionError('Failed to open an SFTP channel')
            self._sftp = client
        except Exception as exc:
            _logger.error('SFTP connection failed: %s', exc)
            self.close()
            raise

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception as exc:
                _logger.warning('Error closing SFTP client: %s', exc)
            finally:
                self._sftp = None
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception as exc:
                _logger.warning('Error closing transport: %s', exc)
            finally:
                self._transport = None

    def _client(self) -> paramiko.SFTPClient:
        self.connect()
        if self._sftp is None:
            raise ConnectionError('SFTP client is not connected')
        return self._sftp

    def list(self, path: str) -> List[Stat]:
        client = self._client()
        entries: List[Stat] = []
        for entry in client.listdir_attr(path or '.'):
            entries.append(
                Stat(
                    name=entry.filename,
                    size=entry.st_size or 0,
                    is_dir=S_ISDIR(entry.st_mode or 0),
                )
            )
        return entries

    def read(self, path: str) -> bytes:
        client = self._client()
        buffer = BytesIO()
        client.getfo(remotepath=path, fl=buffer)
        return buffer.getvalue()

    def write(self, path: str, data: bytes) -> None:
        client = self._client()
        client.putfo(fl=BytesIO(data), remotepath=path, confirm=True)

    def rename(self, src: str, dst: str) -> None:
        self._client().rename(src, dst)

    def remove(self, path: str) -> None:
        self._client().unlink(path)
```

Replace `multiremote_fm/remotes.py` entirely:

```python
"""The frozen public remotes. Each one builds a backend and delegates."""

from types import TracebackType
from typing import Optional, Type

from .backends.ftp import FtpBackend
from .backends.local import LocalBackend
from .backends.sftp import SftpBackend
from .driver import RemoteDriver
from .exceptions import SSHPasswordRSAError


class Local(RemoteDriver):
    """Local directory remote."""

    def __init__(self) -> None:
        super().__init__(backend=LocalBackend())


class FTP(RemoteDriver):
    """Standard FTP remote."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
        tls: bool = False,
    ) -> None:
        super().__init__(
            backend=FtpBackend(
                host=host,
                port=port,
                login=login,
                password=password,
                passive_mode=passive_mode,
                response_timeout=response_timeout,
                encoding=encoding,
                tls=tls,
            )
        )


class FTPS(FTP):
    """FTP over SSL/TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            login=login,
            password=password,
            passive_mode=passive_mode,
            response_timeout=response_timeout,
            encoding=encoding,
            tls=True,
        )


class SFTP(RemoteDriver):
    """SSH File Transfer Protocol remote."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        login: str = '',
        password: Optional[str] = None,
        rsa: Optional[bytes] = None,
        response_timeout: int = 30,
    ) -> None:
        if not (password or rsa):
            raise SSHPasswordRSAError()
        super().__init__(
            backend=SftpBackend(
                host=host,
                port=port,
                login=login,
                password=password,
                rsa=rsa,
                response_timeout=response_timeout,
            )
        )

    def __enter__(self) -> 'SFTP':
        self.backend.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.backend.close()
```

> Implementation note: `SFTP.__exit__` swallows nothing — it closes the backend and lets any exception propagate, matching `drivers/sftp.py:284-286`.

Replace `multiremote_fm/backends/__init__.py` entirely:

```python
"""Protocol backends."""

from .base import Backend, Stat
from .ftp import FtpBackend
from .local import LocalBackend
from .sftp import SftpBackend

__all__ = [
    'Backend',
    'Stat',
    'LocalBackend',
    'FtpBackend',
    'SftpBackend',
]
```

Replace `multiremote_fm/__init__.py` entirely:

```python
"""Multi-remote file manager package."""

from .driver import BaseDriver, RemoteDriver
from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet
from .remotes import FTP, FTPS, SFTP, Local

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'FTP',
    'FTPS',
    'SFTP',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_sftp.py -v`

Expected: PASS — 18 passed, including `test_import_without_paramiko`, `test_connect_with_password`, `test_connect_with_rsa`.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add multiremote_fm/backends/sftp.py multiremote_fm/backends/__init__.py multiremote_fm/remotes.py multiremote_fm/__init__.py tests/test_sftp.py && git commit -m "Add SftpBackend with deferred annotations, actionable ImportError, honoured timeout"
```

> Multi-owner files: this task is the **authoritative, final** version of `multiremote_fm/remotes.py`, `multiremote_fm/backends/__init__.py` and `multiremote_fm/__init__.py`. No later task restates them.

---

### Task 8: Public export surface and `py.typed` verification

Traces to spec §4.2 (S1 `__init__.py` is public exports only), §3.1 (frozen import form), §4.7 (`py.typed`).

**Files:**
- Test: `tests/test_public_api.py` (create)

**Interfaces:**
- Consumes: `multiremote_fm` exporting `RemoteFile`, `RemoteFileSet`, `BaseDriver`, `RemoteDriver`, `Local`, `FTP`, `FTPS`, `SFTP`, `NothingToUploadException`, `SSHPasswordRSAError`, `DownloadingError`, `UploadingError`, `MovingError`, `__version__`.
- Produces: no new package names. A regression test locking the export surface and the README-documented signatures.

- [ ] **Step 1: Write the failing test**

Create `tests/test_public_api.py`:

```python
import inspect
import os
import unittest


class TestPublicApi(unittest.TestCase):
    def test_readme_import_form_works(self):
        from multiremote_fm import FTP, Local, RemoteFile  # noqa: F401

    def test_every_frozen_name_is_exported(self):
        import multiremote_fm

        expected = {
            'RemoteFile',
            'RemoteFileSet',
            'BaseDriver',
            'RemoteDriver',
            'Local',
            'FTP',
            'FTPS',
            'SFTP',
            'NothingToUploadException',
            'SSHPasswordRSAError',
            'DownloadingError',
            'UploadingError',
            'MovingError',
        }
        self.assertEqual(set(multiremote_fm.__all__), expected)
        for name in expected:
            self.assertTrue(hasattr(multiremote_fm, name), name)

    def test_py_typed_present_in_the_source_tree(self):
        """Source-tree check only.

        Under the editable install this resolves into `<repo>/multiremote_fm`, so it
        cannot detect a missing `[tool.setuptools.package-data]` entry. The wheel-member
        check that CAN detect that is Task 13's `test_c5_py_typed_in_built_wheel`.
        """
        import multiremote_fm

        package_dir = os.path.dirname(inspect.getfile(multiremote_fm))
        self.assertTrue(os.path.isfile(os.path.join(package_dir, 'py.typed')))

    def test_documented_signatures_and_defaults(self):
        from multiremote_fm import FTP, FTPS, SFTP, Local, RemoteDriver

        self.assertEqual(list(inspect.signature(Local).parameters), [])

        ftp_params = inspect.signature(FTP).parameters
        self.assertEqual(ftp_params['passive_mode'].default, True)
        self.assertEqual(ftp_params['response_timeout'].default, 30)
        self.assertEqual(ftp_params['encoding'].default, 'utf-8')
        self.assertEqual(ftp_params['tls'].default, False)

        ftps_params = inspect.signature(FTPS).parameters
        self.assertNotIn('tls', ftps_params)
        self.assertEqual(ftps_params['passive_mode'].default, True)

        sftp_params = inspect.signature(SFTP).parameters
        self.assertEqual(sftp_params['port'].default, 22)
        self.assertIsNone(sftp_params['password'].default)
        self.assertIsNone(sftp_params['rsa'].default)
        self.assertEqual(sftp_params['response_timeout'].default, 30)

        download_params = inspect.signature(RemoteDriver.download).parameters
        self.assertEqual(download_params['unlink'].default, False)
        self.assertEqual(download_params['download_content'].default, True)

    def test_five_operations_defined_exactly_once_package_wide(self):
        """Each of the five operations is declared exactly twice in driver.py only.

        Twice because `driver.py` declares each one abstract on `BaseDriver` and concrete
        on `RemoteDriver`. Any occurrence in any other module means an operation body was
        duplicated back out into a remote or a backend, which is the exact regression this
        refactor exists to prevent. Walks the whole package, not just `remotes`.
        """
        import multiremote_fm

        package_dir = os.path.dirname(inspect.getfile(multiremote_fm))
        ops = ('def search', 'def download', 'def upload', 'def move', 'def delete')
        counts = dict.fromkeys(ops, 0)
        for dirpath, _dirnames, filenames in os.walk(package_dir):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                full = os.path.join(dirpath, filename)
                with open(full, encoding='utf-8') as handle:
                    source = handle.read()
                for op in ops:
                    found = source.count(op + '(')
                    if found and filename != 'driver.py':
                        self.fail('{0} declares {1}'.format(full, op))
                    counts[op] += found
        for op, count in counts.items():
            self.assertEqual(count, 2, '{0} declared {1} times'.format(op, count))


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run the test**

Run: `venv/bin/pytest tests/test_public_api.py -v`

Expected: PASS. **Task 8 is a verification task, not a TDD task** — its tests lock a surface that Tasks 1–7 already built, so on correct predecessors they pass on the first run and that IS the pass condition. Any FAIL names a real drift in the predecessor task that produced the offending name, default, or module; fix that task's output, never this test. Do not hand-edit a shipped source file to manufacture a red run.

- [ ] **Step 3: Write minimal implementation**

No package change is expected — Task 7 already produced the authoritative `multiremote_fm/__init__.py`. If Step 2 reported a genuine failure, fix it **in Task 7's output** (the authoritative owner of this file, per Global Constraints), so that its `__all__` is exactly:

```python
__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'FTP',
    'FTPS',
    'SFTP',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_public_api.py -v`

Expected: PASS — 5 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add tests/test_public_api.py multiremote_fm/__init__.py && git commit -m "Lock the frozen public export surface with a regression test"
```

---

### Task 9: Delete the legacy tree

Traces to spec §4.2 (S1: delete root-level `core/`, `drivers/`, `remote.py`, root `__init__.py`), defects 1, 2, 11.

**Files:**
- Delete: `__init__.py`
- Delete: `remote.py`
- Delete: `core/__init__.py`, `core/base.py`, `core/file.py`, `core/exceptions.py`
- Delete: `drivers/__init__.py`, `drivers/local.py`, `drivers/ftp.py`, `drivers/sftp.py`
- Delete: `__pycache__/`, `core/__pycache__/`, `drivers/__pycache__/`
- Test: `tests/test_legacy_removed.py` (create)

**Interfaces:**
- Consumes: `multiremote_fm` with the full export surface from Task 8.
- Produces: no importable `core`, `drivers`, or `remote` module. No new names.

- [ ] **Step 1: Write the failing test**

Create `tests/test_legacy_removed.py`:

```python
import os
import unittest


class TestLegacyTreeRemoved(unittest.TestCase):
    @property
    def repo_root(self) -> str:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_legacy_paths_are_gone(self):
        for relative in (
            '__init__.py',
            'remote.py',
            'core',
            'drivers',
            'multiremote_fm.py',
        ):
            self.assertFalse(
                os.path.exists(os.path.join(self.repo_root, relative)),
                '{0} still exists'.format(relative),
            )

    # A `test_legacy_modules_are_not_importable` check was deliberately NOT written here:
    # `import core` already raises ModuleNotFoundError under `venv/bin/pytest` even with
    # `core/` fully present on disk, because pytest's prepend importmode never puts the
    # repo root on sys.path. Such a test is green before AND after the deletion, so it
    # verifies nothing. The filesystem check above is the real one.

    def test_package_still_imports(self):
        from multiremote_fm import FTP, FTPS, SFTP, Local, RemoteFile, RemoteFileSet  # noqa: F401


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_legacy_removed.py -v`

Expected: FAIL — `test_legacy_paths_are_gone` reports `__init__.py still exists`. (`test_package_still_imports` passes already; it is a guard against collateral damage from Step 3, not a red-first test.)

- [ ] **Step 3: Write minimal implementation**

Safe as written, unchanged from the original plan. All four paths are tracked at `HEAD` since baseline `0d8d7bc`, so `git rm --cached` matches them, and every deleted file stays recoverable from that commit. `multiremote_fm.py` was deleted by the same baseline commit and is absent from both `HEAD` and disk, which is what makes the `test_legacy_paths_are_gone` assertion on it meaningful rather than vacuous.

```bash
git rm -r --cached core drivers remote.py __init__.py
rm -rf core drivers remote.py __init__.py __pycache__
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_legacy_removed.py -v && venv/bin/pytest tests/ -v`

Expected: PASS — 2 passed for the new file; the full run passes with `tests/_test_ftp.py` uncollected (leading underscore) and every other test green.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add -A core drivers remote.py __init__.py tests/test_legacy_removed.py && git commit -m "Delete the legacy core/, drivers/, remote.py and root __init__.py"
```

---

### Task 10: README corrections

Traces to spec §4.5 (delete the false "Memory Efficient" bullet), §4.7 (3.10 floor, `sftp` extra), §5 item 4.

**Files:**
- Modify: `README.md:3` (badge), `README.md:15` (bullet), `README.md:36-42` (dev install block), `README.md:220-221` (SFTP install note — **not** 222, the closing fence), `README.md:341-348` (changelog, including the `## Changelog` heading at 341). `README.md:327-335` is intentionally unchanged.
- Test: `tests/test_readme_claims.py` (create)

**Interfaces:**
- Consumes: `multiremote_fm.__version__ == '0.2.0'`.
- Produces: no code names. A test asserting the README no longer carries the three retired claims.

- [ ] **Step 1: Write the failing test**

Create `tests/test_readme_claims.py`:

```python
import os
import unittest


class TestReadmeClaims(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'README.md'), encoding='utf-8') as handle:
            cls.readme = handle.read()

    def test_memory_efficient_claim_is_gone(self):
        self.assertNotIn('Memory Efficient', self.readme)

    def test_download_content_remains_the_memory_story(self):
        self.assertIn('download_content=False', self.readme)

    def test_python_floor_is_310(self):
        self.assertNotIn('python-3.9+', self.readme)
        self.assertIn('python-3.10+', self.readme)

    def test_sftp_extra_is_documented(self):
        self.assertIn('pip install multiremote-fm[sftp]', self.readme)

    def test_dev_install_documents_the_editable_install(self):
        self.assertIn('pip install -e ".[dev]"', self.readme)

    def test_changelog_mentions_v02(self):
        self.assertIn('v0.2.0', self.readme)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_readme_claims.py -v`

Expected: FAIL — 4 of 6 fail; `Memory Efficient` is present at `README.md:15`, the badge at `README.md:3` says `python-3.9+`, there is no `pip install multiremote-fm[sftp]` line, and there is no `v0.2.0` entry.

- [ ] **Step 3: Write minimal implementation**

Apply exactly these five edits to `README.md`.

Line 3 — replace:

```markdown
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
```

with:

```markdown
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
```

Line 15 — delete this line entirely (content is eager `bytes`; the claim is false):

```markdown
- **Memory Efficient** - Optional content loading
```

Lines 36–42 — replace the Development Installation block:

```markdown
### Development Installation

```bash
git clone https://github.com/igorgoroun/multiremote-fm
cd multiremote-fm
pip install -e .
```
```

with (the editable install now works, because `pyproject.toml` carries a real PEP 440 version):

```markdown
### Development Installation

```bash
git clone https://github.com/igorgoroun/multiremote-fm
cd multiremote-fm
python -m venv venv
venv/bin/pip install -e ".[dev]"
venv/bin/pytest tests/ -v
```

The published version is stamped by CI, which rewrites the `version = ` line in
`pyproject.toml` from the release tag before building.
```

Lines 220–**221** — replace. **Do not touch line 222: it is the closing ``` fence of the SFTP example block.** Replacing 220–222 would delete that fence and render every following section of the README inside an unterminated code block. The two quoted lines below are exactly 220 and 221.

```markdown
# Note: Requires 'paramiko' package
# Install with: pip install paramiko
```

with:

```markdown
# Note: Requires the optional 'sftp' extra
# Install with: pip install multiremote-fm[sftp]
```

`README.md:327-335` (Development Setup) needs **no change**: it already documents `pip install -e ".[dev]"`, which now genuinely works because the version is real PEP 440 and the `dev` extra exists. Leave it untouched.

Lines 341–348 — replace the changelog head (line 341 is the `## Changelog` heading itself):

```markdown
## Changelog

### v0.1.0 (Current)
- ✅ Initial release
- ✅ Local, FTP, FTPS, SFTP drivers
- ✅ Core file operations
- ✅ Fluent API design
- ✅ Type hints support
```

with:

```markdown
## Changelog

### v0.2.0 (Current)
- ✅ Real installable `multiremote_fm` package
- ✅ The five operations implemented once over a backend protocol
- ✅ Fluent methods are copy-on-write; no state leaks between chains
- ✅ `RemoteFileSet` deduplicates by file name
- ✅ SFTP moved to the optional `sftp` extra with an actionable ImportError
- ✅ Ships `py.typed`

### v0.1.0
- ✅ Initial release
- ✅ Local, FTP, FTPS, SFTP drivers
- ✅ Core file operations
- ✅ Fluent API design
- ✅ Type hints support
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_readme_claims.py -v`

Expected: PASS — 6 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add README.md tests/test_readme_claims.py && git commit -m "Correct README: drop false memory claim, 3.10 floor, sftp extra, v0.2 changelog"
```

---

### Task 11: CI workflows

Traces to spec §4.8 (S7 CI), defect 14.

**Files:**
- Create: `.github/workflows/test.yml`
- Modify: `.github/workflows/publish-to-pypi.yml:13,27`
- Test: `tests/test_workflows.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no code names. A test asserting both workflows are correct.

- [ ] **Step 1: Write the failing test**

Create `tests/test_workflows.py`:

```python
import os
import unittest


class TestWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.workflows = os.path.join(cls.root, '.github', 'workflows')

    def _read(self, name: str) -> str:
        with open(os.path.join(self.workflows, name), encoding='utf-8') as handle:
            return handle.read()

    def test_publish_workflow_has_no_deprecated_directives(self):
        content = self._read('publish-to-pypi.yml')
        self.assertNotIn('::set-output', content)
        self.assertNotIn('actions/checkout@main', content)
        self.assertIn('actions/checkout@v4', content)
        self.assertIn('$GITHUB_OUTPUT', content)

    def test_publish_workflow_rewrites_the_real_version_line(self):
        content = self._read('publish-to-pypi.yml')
        self.assertIn('s/^version = .*/version = ', content)
        self.assertNotIn('{{VERSION_PLACEHOLDER}}', content)

    def test_test_workflow_exists_and_covers_four_pythons(self):
        content = self._read('test.yml')
        for version in ('3.10', '3.11', '3.12', '3.13'):
            self.assertIn('"{0}"'.format(version), content)
        self.assertIn('pytest', content)
        self.assertIn('ruff', content)
        self.assertIn('actions/checkout@v4', content)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_workflows.py -v`

Expected: FAIL — `test_publish_workflow_has_no_deprecated_directives` finds `::set-output` and `actions/checkout@main`; `test_test_workflow_exists_and_covers_four_pythons` raises `FileNotFoundError` for `test.yml`.

- [ ] **Step 3: Write minimal implementation**

Create `.github/workflows/test.yml`:

```yaml
name: Test MultiremoteFM

on:
  push:
    branches:
      - '**'
  pull_request:

jobs:
  test:
    name: pytest and ruff on Python ${{ matrix.python-version }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install the package under test with dev and sftp extras
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e ".[dev,sftp]"
      - name: Ruff check
        run: ruff check multiremote_fm tests
      - name: Ruff format check
        run: ruff format --check multiremote_fm tests
      - name: Pytest
        run: pytest tests/ -v
      - name: Mypy
        run: mypy multiremote_fm
```

In `.github/workflows/publish-to-pypi.yml`, replace line 13:

```yaml
    - uses: actions/checkout@main
```

with:

```yaml
    - uses: actions/checkout@v4
```

and replace lines 24–27:

```yaml
    - name: Extract tag name
      id: tag
      run: >-
        echo ::set-output name=TAG_NAME::$(echo $GITHUB_REF | cut -d / -f 3)
```

with:

```yaml
    - name: Extract tag name
      id: tag
      run: >-
        echo "TAG_NAME=$(echo $GITHUB_REF | cut -d / -f 3)" >> $GITHUB_OUTPUT
```

and replace line 30, which substituted the magic token:

```yaml
        sed -i "s/{{VERSION_PLACEHOLDER}}/${{ steps.tag.outputs.TAG_NAME }}/g" pyproject.toml
```

with a rewrite of the real version line (runner is `ubuntu-latest`, so this is GNU `sed`; the `^version = ` anchor matches exactly one line in `pyproject.toml`, verified):

```yaml
        sed -i "s/^version = .*/version = \"${{ steps.tag.outputs.TAG_NAME }}\"/" pyproject.toml
```

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/test_workflows.py -v`

Expected: PASS — 3 passed.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add .github/workflows/test.yml .github/workflows/publish-to-pypi.yml tests/test_workflows.py && git commit -m "Add test/lint CI workflow and fix deprecated publish workflow directives"
```

---

### Task 12: Ruff and mypy clean

Traces to spec §8 criterion 12, Global Constraints (single-quote style, no `X | Y`).

**Files:**
- Modify: any file under `multiremote_fm/` or `tests/` that ruff or mypy reports
- Test: the tool runs themselves are the test

**Interfaces:**
- Consumes: the complete package from Tasks 1–11.
- Produces: no new names. No behaviour change — if a fix would change behaviour, stop and fix the underlying code instead of silencing the tool.

- [ ] **Step 1: Write the failing test**

The check is the tool run. Record the baseline:

```bash
venv/bin/ruff check multiremote_fm tests ; venv/bin/ruff format --check multiremote_fm tests ; venv/bin/mypy multiremote_fm
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/ruff check multiremote_fm tests && venv/bin/ruff format --check multiremote_fm tests && venv/bin/mypy multiremote_fm`

Expected: this is a pass/fail gate, not a red-first step. **Pass condition: all three commands exit 0.** Record the actual findings; do not go looking for predicted ones. If ruff reports import-sort order in the rewritten `__init__.py` files or double quotes left in a copied block, fix them in Step 3. The single-quote style comes from `[tool.ruff.format]` in `pyproject.toml` (Task 1 Step 4); if `ruff format --check` unexpectedly wants double quotes, check that `ruff.toml` was actually deleted — it takes precedence over `pyproject.toml`.

- [ ] **Step 3: Write minimal implementation**

Apply the fixes:

```bash
venv/bin/ruff check --fix multiremote_fm tests
venv/bin/ruff format multiremote_fm tests
```

Then read every remaining mypy error and fix the source. Do not add `# type: ignore` except the one already specified in `multiremote_fm/backends/sftp.py` for the `paramiko = None` fallback assignment.

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/ruff check multiremote_fm tests && venv/bin/ruff format --check multiremote_fm tests && venv/bin/mypy multiremote_fm && venv/bin/pytest tests/ -v`

Expected: PASS — `All checks passed!`, `N files already formatted`, `Success: no issues found`, and every test green.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add -A multiremote_fm tests && git commit -m "Make ruff and mypy clean across the package and tests"
```

---

### Task 13: Walk all 20 acceptance criteria from spec §8

Traces to spec §8 (all criteria).

**Files:**
- Test: `tests/test_acceptance.py` (create) plus the manual commands below

**Interfaces:**
- Consumes: the complete package from Tasks 1–12.
- Produces: no new names. An executable record that all 20 criteria hold.

- [ ] **Step 1: Write the failing test**

Create `tests/test_acceptance.py`, covering the criteria that are expressible in-process:

```python
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestAcceptanceCriteria(unittest.TestCase):
    def test_c1_frozen_import_form(self):
        from multiremote_fm import (  # noqa: F401
            FTP,
            FTPS,
            SFTP,
            Local,
            RemoteFile,
            RemoteFileSet,
        )

    def test_c2_search_on_three_files_returns_three(self):
        from multiremote_fm import Local

        temp_dir = tempfile.mkdtemp(prefix='acceptance-')
        try:
            for name in ('a.txt', 'b.txt', 'c.txt'):
                with open(os.path.join(temp_dir, name), mode='w') as handle:
                    handle.write(name)
            self.assertEqual(len(Local().with_path(temp_dir).search()), 3)
        finally:
            shutil.rmtree(temp_dir)

    def test_c3_fileset_deduplicates(self):
        from multiremote_fm import RemoteFile, RemoteFileSet

        a = RemoteFile('same.txt', b'x', 1)
        b = RemoteFile('same.txt', b'x', 1)
        self.assertEqual(len(RemoteFileSet(a, b)), 1)

    def test_c5_py_typed_in_built_wheel(self):
        """Criterion 5 verifies the WHEEL, not the source tree.

        Under an editable install a source-tree check passes even when
        `[tool.setuptools.package-data]` is missing, which is the exact failure this
        criterion exists to catch. So build a real wheel and inspect its members.
        `--no-isolation` keeps it offline and deterministic; setuptools is already
        present in the venv.
        """
        with tempfile.TemporaryDirectory() as outdir:
            result = subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'build',
                    '--wheel',
                    '--no-isolation',
                    '--outdir',
                    outdir,
                    REPO_ROOT,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            wheels = glob.glob(os.path.join(outdir, '*.whl'))
            self.assertEqual(len(wheels), 1, wheels)
            with zipfile.ZipFile(wheels[0]) as archive:
                members = archive.namelist()
        self.assertIn('multiremote_fm/py.typed', members)
        self.assertIn('multiremote_fm/__init__.py', members)
        self.assertIn('multiremote_fm/backends/__init__.py', members)

    def test_c6_sftp_backend_without_paramiko_raises_clear_import_error(self):
        script = textwrap.dedent(
            """
            import sys
            sys.path.insert(0, {root!r})
            sys.modules['paramiko'] = None
            from multiremote_fm.backends.sftp import SftpBackend
            try:
                SftpBackend(host='h', login='u', password='p')
            except ImportError as exc:
                print(type(exc).__name__, exc)
            """
        ).format(root=REPO_ROOT)
        result = subprocess.run(
            [sys.executable, '-c', script], capture_output=True, text=True, cwd=REPO_ROOT
        )
        self.assertIn(
            'ImportError SFTP support requires paramiko: pip install multiremote-fm[sftp]',
            result.stdout,
        )
        self.assertNotIn('AttributeError', result.stdout + result.stderr)

    def test_c7_no_asserts_in_package(self):
        offenders = []
        package = os.path.join(REPO_ROOT, 'multiremote_fm')
        for dirpath, _dirnames, filenames in os.walk(package):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                full = os.path.join(dirpath, filename)
                with open(full, encoding='utf-8') as handle:
                    for lineno, line in enumerate(handle, start=1):
                        if line.lstrip().startswith('assert '):
                            offenders.append('{0}:{1}'.format(full, lineno))
        self.assertEqual(offenders, [])

    def test_c8_upload_empty_raises_even_under_optimisation(self):
        script = textwrap.dedent(
            """
            import sys, tempfile
            sys.path.insert(0, {root!r})
            from multiremote_fm import Local, NothingToUploadException
            try:
                Local().with_path(tempfile.mkdtemp()).upload()
                print('SILENT')
            except NothingToUploadException:
                print('RAISED')
            """
        ).format(root=REPO_ROOT)
        result = subprocess.run(
            [sys.executable, '-O', '-c', script], capture_output=True, text=True, cwd=REPO_ROOT
        )
        self.assertIn('RAISED', result.stdout)

    def test_c9_typo_kwarg_raises_type_error(self):
        from multiremote_fm import FTP

        with self.assertRaises(TypeError):
            FTP(host='h', port=21, login='u', password='p', pasword='typo')

    def test_c13_no_pep604_annotations_outside_future_modules(self):
        offenders = []
        package = os.path.join(REPO_ROOT, 'multiremote_fm')
        for dirpath, _dirnames, filenames in os.walk(package):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                full = os.path.join(dirpath, filename)
                with open(full, encoding='utf-8') as handle:
                    source = handle.read()
                if 'from __future__ import annotations' in source:
                    continue
                for lineno, line in enumerate(source.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped.startswith('#'):
                        continue
                    if ('->' in stripped or ': ' in stripped) and ' | ' in stripped:
                        offenders.append('{0}:{1}'.format(full, lineno))
        self.assertEqual(offenders, [])

    def test_c14_pyproject_declarations(self):
        with open(os.path.join(REPO_ROOT, 'pyproject.toml'), encoding='utf-8') as handle:
            content = handle.read()
        self.assertIn('requires-python = ">=3.10"', content)
        self.assertIn('packages = ["multiremote_fm", "multiremote_fm.backends"]', content)
        self.assertIn('sftp = ["paramiko>=3.2,<6"]', content)
        self.assertIn('version = "0.2.0"', content)
        self.assertNotIn('{{VERSION_PLACEHOLDER}}', content)
        self.assertIn('[project.optional-dependencies]', content)
        self.assertIn('dev = [', content)

    def test_c16_dead_http_exceptions_absent_from_package(self):
        package = os.path.join(REPO_ROOT, 'multiremote_fm')
        for dirpath, _dirnames, filenames in os.walk(package):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                with open(os.path.join(dirpath, filename), encoding='utf-8') as handle:
                    source = handle.read()
                self.assertNotIn('InvalidResponseCodeError', source)
                self.assertNotIn('InvalidJSONResponseError', source)

    def test_c18_five_operations_defined_once_in_driver_only(self):
        package = os.path.join(REPO_ROOT, 'multiremote_fm')
        counts = {'def search': 0, 'def download': 0, 'def upload': 0, 'def move': 0, 'def delete': 0}
        for dirpath, _dirnames, filenames in os.walk(package):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                full = os.path.join(dirpath, filename)
                with open(full, encoding='utf-8') as handle:
                    source = handle.read()
                for op in counts:
                    found = source.count(op + '(')
                    if found and os.path.basename(full) != 'driver.py':
                        self.fail('{0} defines {1}'.format(full, op))
                    counts[op] += found
        # driver.py declares each operation twice: once abstract on BaseDriver, once concrete.
        for op, count in counts.items():
            self.assertEqual(count, 2, '{0} declared {1} times'.format(op, count))

    def test_c19_with_driver_download_uses_configured_path(self):
        from multiremote_fm import Local

        temp_dir = tempfile.mkdtemp(prefix='acceptance-')
        try:
            for name in ('a.xml', 'b.xml'):
                with open(os.path.join(temp_dir, name), mode='w') as handle:
                    handle.write(name)
            source = Local().with_path(temp_dir).with_mask('*.xml')
            found = source.search()
            downloaded = found.with_driver(source).download()
            self.assertEqual(len(downloaded), 2)
            for file in downloaded:
                self.assertGreater(len(file.content), 0)
        finally:
            shutil.rmtree(temp_dir)

    def test_c20_no_set_files_or_set_path_in_package(self):
        package = os.path.join(REPO_ROOT, 'multiremote_fm')
        for dirpath, _dirnames, filenames in os.walk(package):
            for filename in filenames:
                if not filename.endswith('.py'):
                    continue
                with open(os.path.join(dirpath, filename), encoding='utf-8') as handle:
                    source = handle.read()
                self.assertNotIn('set_files', source)
                self.assertNotIn('set_path', source)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `venv/bin/pytest tests/test_acceptance.py -v`

Expected: PASS for every criterion if Tasks 1–12 are complete. Any FAIL names the criterion and the task to revisit — fix that task's code, not this test.

- [ ] **Step 3: Write minimal implementation**

Run the six criteria that need a shell, and confirm each expected output.

Criterion 4 — a valid wheel containing `multiremote_fm/`, built plainly with no version rewriting and no throwaway copy:

```bash
rm -rf dist && venv/bin/python -m build --sdist --wheel --outdir dist . \
  && venv/bin/python -m zipfile -l dist/multiremote_fm-0.2.0-py3-none-any.whl
```

Expected: build succeeds; the listing shows `multiremote_fm/__init__.py`, `multiremote_fm/driver.py`, `multiremote_fm/files.py`, `multiremote_fm/remotes.py`, `multiremote_fm/exceptions.py`, `multiremote_fm/py.typed`, `multiremote_fm/backends/base.py`, `multiremote_fm/backends/local.py`, `multiremote_fm/backends/ftp.py`, `multiremote_fm/backends/sftp.py`. Criterion 5 (`py.typed` inside the wheel) is additionally asserted in-process by `test_c5_py_typed_in_built_wheel`, which builds its own wheel into a temp dir — the two are independent checks of the same packaging fact.

Criterion 7 — no asserts:

```bash
grep -rn "assert " multiremote_fm/ ; echo "exit=$?"
```

Expected: no output, `exit=1` (grep found nothing).

Criterion 10 — every README example still runs. Run the three fluent chains against a temp tree:

```bash
venv/bin/python - <<'PY'
import os, shutil, tempfile
from multiremote_fm import FTP, Local, RemoteFile, RemoteFileSet

src = tempfile.mkdtemp(); dst = tempfile.mkdtemp()
for name in ('r1.pdf', 'r2.txt', 'r3.log'):
    open(os.path.join(src, name), 'w').write(name)

local = Local()
print('pdf:', len(local.with_path(src).with_mask('*.pdf').search()))
files = local.with_path(src).with_mask('*.txt').download()
for f in files:
    print('File:', f.name, f.size, f.mimetype)
local.with_path(dst).with_files(files).upload()
print('uploaded:', sorted(os.listdir(dst)))

f1 = RemoteFile(name='data.txt', content=b'Hello World', size=11)
f2 = RemoteFile(name='config.json', content=b'{"key": "value"}', size=16)
fileset = RemoteFileSet(f1, f2)
local.with_path(dst).with_files(fileset).upload()
print('fileset uploaded:', sorted(os.listdir(dst)))

logs = local.with_path(src).with_mask('*.log').download(unlink=True)
print('logs:', len(logs), 'remaining:', sorted(os.listdir(src)))
local.with_path(dst).with_files(logs).upload()

ftp = FTP(host='ftp.example.com', port=21, login='user', password='pass')
print('ftp chain builds:', type(ftp.with_path('/incoming').with_mask('*.xml')).__name__)
shutil.rmtree(src); shutil.rmtree(dst)
PY
```

Expected: `pdf: 1`; one `File: r2.txt 6 text/plain` line; `uploaded: ['r2.txt']`; `fileset uploaded: ['config.json', 'data.txt', 'r2.txt']`; `logs: 1 remaining: ['r1.pdf', 'r2.txt']`; `ftp chain builds: RemoteDriver`.

Criterion 11 — pytest clean:

```bash
venv/bin/pytest tests/ -v
```

Expected: all tests pass, zero failures, zero errors; `tests/_test_ftp.py` is not collected.

Criterion 12 — ruff and mypy clean:

```bash
venv/bin/ruff check multiremote_fm tests && venv/bin/ruff format --check multiremote_fm tests && venv/bin/mypy multiremote_fm
```

Expected: `All checks passed!`, `N files already formatted`, `Success: no issues found`.

Criterion 15 — workflows:

```bash
venv/bin/pytest tests/test_workflows.py -v
```

Expected: 3 passed.

Criterion 17 — FTP connection reuse:

```bash
venv/bin/pytest tests/test_ftp_backend.py -k "reused or close_clears" -v
```

Expected: 2 passed (`test_connect_is_reused_not_reopened`, `test_close_clears_the_stored_connection`).

- [ ] **Step 4: Run test to verify it passes**

Run: `venv/bin/pytest tests/ -v && venv/bin/ruff check multiremote_fm tests && venv/bin/ruff format --check multiremote_fm tests && venv/bin/mypy multiremote_fm`

Expected: PASS — every test green, ruff clean, mypy clean.

- [ ] **Step 5: Commit** — the index is clean as of baseline `0d8d7bc`, so this commits exactly the paths named.

```bash
git add tests/test_acceptance.py && git commit -m "Add executable acceptance checks for all 20 spec criteria"
```

---

## Self-review

### 1. Spec coverage

| Spec section | Implementing task |
|---|---|
| §4.2 S1 layout (new package) | 1, 2, 3, 4, 5, 6, 7 |
| §4.2 S1 layout (delete legacy) | 9 |
| §4.3 S2 `Stat` + `Backend` | 3 |
| §4.3 S2 identical mask semantics, one filter site | 4 |
| §4.3 S2 FakeBackend testability | 3 (double), 4 (used) |
| §4.3 S2 FTP MLSD/NLST, connection reuse, `encoding` | 6 |
| §4.3 S2 SFTP deferred annotations + ImportError | 7 |
| §4.4 S3 copy-on-write, shared backend, `move` copy, mask `'*'` | 4 |
| §4.5 S4 `__eq__`/`__hash__`, dict-backed set, `Optional[str]` | 2 |
| §4.5 S4 `with_driver` returns a copy; no `set_*` | 2 (files), 4 (driver) |
| §4.5 S4 `test_download_searched` rewrite | 5 |
| §4.5 S4 eager bytes → README bullet deleted | 10 |
| §4.6 S5 real raises, dead exceptions, explicit ctor params, real ABC | 1 (exceptions), 4 (raises + ABC), 5/6/7 (ctors) |
| §4.7 S6 packaging | 1 (base), 3 (backends package line) |
| §4.8 S7 FakeBackend, count assertion, 3 sftp fixes, opt-in ftp | 3, 5, 7, 6 |
| §4.8 S7 CI | 11 |
| §5 behavioural changes 1–2 | 4, 5 |
| §5 behavioural change 3 | 2 |
| §5 behavioural change 4 | 10 |
| §7 risks | mitigations executed in 2, 4, 5, 6, 7 |

**Gap found, fixed inline, then fixed in the spec:** §4.8 originally instructed that `timeout` be passed to `Transport.connect`, which is impossible in paramiko 5.0.0 (`paramiko/transport.py:1268` — the parameter does not exist, and passing it raises `TypeError`). Task 7 honours `response_timeout` at the socket and banner/auth level instead. Spec §4.8 and the spec's defect-13 row have since been corrected, and spec §7 records the mis-specification, so plan and spec now agree. No other gap.

**Second gap found and fixed inline, then fixed at the root:** the spec originally froze `{{VERSION_PLACEHOLDER}}` verbatim. It is not PEP 440, so `pip install -e .` and bare `python -m build` both fail (`configuration error: project.version must be pep440`, reproduced) — the project was uninstallable and unbuildable, and `README.md:41,334` documented commands that could never work. The first draft of this plan worked around it with a `conftest.py` `sys.path` injection and a sed'd throwaway copy for the wheel check. That treated the symptom. The token is now replaced by a real `version = "0.2.0"` (Task 1); the release mechanism is preserved by having the publish workflow rewrite the `version = ` line (Task 11); the `conftest.py` workaround is deleted; tests run against a genuine editable install; and criteria 1 and 4 are now literally achievable. Spec §3.2, §4.7, §4.8 and §8 were updated to match.

### 2. Placeholder scan

Searched this plan for `TBD`, `TODO`, `implement later`, `add appropriate error handling`, `add validation`, `handle edge cases`, `write tests for the above`, `similar to Task`. Zero occurrences. Every code step contains complete runnable code; the FTP and SFTP tasks repeat the whole of `remotes.py` and `__init__.py` rather than referring back.

### 3. Type consistency

- `Stat(name, size, is_dir)` — identical in Tasks 3, 4, 5, 6, 7.
- `Backend` primitives `connect/close/list/read/write/rename/remove` — identical in Tasks 3, 5, 6, 7; asserted by name in Task 3's `test_backend_declares_exactly_the_seven_primitives`.
- `RemoteDriver(backend, path='', mask='*', files=None)` — identical in Tasks 4, 5, 6, 7.
- `BaseDriver` eight abstract methods — declared in Task 4, asserted in Task 4's `test_base_driver_declares_exactly_the_eight_frozen_methods`, re-asserted structurally in Task 8.
- `with_driver` returns `driver.with_files(...)` — Task 2 defines it; Task 4 tests it; Task 5 and Task 13 depend on it.
- `FtpBackend(host, port, login, password, passive_mode, response_timeout, encoding, tls)` — identical in Task 6's backend, remote, and tests.
- `SftpBackend(host, port=22, login='', password=None, rsa=None, response_timeout=30)` — identical in Task 7's backend, remote, and tests.
- `_join(base, name)` — defined once in Task 4's `driver.py`, used only there; no other task references it.
- `FakeBackend(tree)` with `.tree/.dirs/.connect_calls/.close_calls` — defined in Task 3, consumed in Tasks 3 and 4 only.
- `__version__ == '0.2.0'` — asserted in Tasks 1 and 8, referenced by Task 10's changelog.
- Test names renamed during review — `test_dev_install_documents_the_editable_install` (Task 10, was `test_dev_install_does_not_use_broken_editable_install`) and `test_publish_workflow_rewrites_the_real_version_line` (Task 11, was `test_publish_workflow_still_seds_the_placeholder`) — are each referenced only inside their own task; a repo-wide search for the old names returns zero hits.
- Duplicate test-method names are intentional and live in different files: `test_move_files` and `test_delete_files` in Task 5 (`tests/test_local_dir.py`) and Task 7 (`tests/test_sftp.py`); `test_connect_is_reused_not_reopened` in Task 6 (`tests/test_ftp_backend.py`) and Task 7 (`tests/test_sftp.py`).
- Every plan→spec citation is by **section** (`§4.7`), never by spec line number, so the two rounds of spec edits could not make them stale. Verified: zero spec-line citations in the plan.
- `tests/__init__.py` — created by Task 1; it is what makes `from tests.fakes import FakeBackend` (Tasks 3 and 4) resolve under `venv/bin/pytest`. Proven both ways in a scaffold: without it the probe run is a collection ERROR, with it the probe passes.
- Test names changed by the pre-flight repair pass, each referenced only inside its own task: `test_search_common` (Task 5 — restored to the identifier spec criterion 11 names), `test_py_typed_present_in_the_source_tree` and `test_five_operations_defined_exactly_once_package_wide` (Task 8), `test_c5_py_typed_in_built_wheel` (Task 13). `test_legacy_modules_are_not_importable` (Task 9) was deleted as unfalsifiable, and Task 9's expected count dropped from 3 to 2.

### 4. Pre-flight repair pass

An independent pre-flight scan raised 23 findings. Repaired in this document: A1, B1, B3, B4, B5 (in the spec), C1–C11. The two findings that needed a human decision were both resolved on 2026-08-28 and are recorded under **Resolved Decisions**: OD-1 (D4 + D5) was resolved by the repo owner committing the baseline directly as `0d8d7bc`, which discharged every hazard without any prerequisite task, and its branch sub-question was then closed by cutting `refactor/clean-package` from that baseline; OD-2 (A2 + B2) was approved and is implemented as Task 1 Step 4, moving the ruff format style into `pyproject.toml` and deleting `ruff.toml`. D0–D3 are facts, not defects, and needed no change.
