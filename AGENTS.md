# Repository Guidelines

## Project Overview

`multiremote_fm` (PyPI: `multiremote-fm`, v0.2.0) is a Python 3.10+ library providing a unified, fluent API for file operations (search/download/upload/move/delete) across heterogeneous remote locations: local filesystem, FTP, FTPS, and SFTP. Goal: implement each operation exactly once and drive every protocol through a thin backend abstraction, rather than duplicating logic per protocol.

## Architecture & Data Flow

Three-layer strategy pattern; each layer has one job:

1. **`multiremote_fm/remotes.py`** — thin, protocol-specific wrappers (`Local`, `FTP`, `FTPS`, `SFTP`), ~15 lines each. Construct the right `Backend` and delegate everything else to `RemoteDriver`. `FTPS` = `FTP` with `tls=True`. `SFTP` validates `password` XOR `rsa` (raises `SSHPasswordRSAError`) and implements `__enter__`/`__exit__` delegating to `backend.connect()`/`close()`.
2. **`multiremote_fm/driver.py`** — `BaseDriver` (ABC) declares `search/download/upload/move/delete/with_path/with_mask/with_files`. `RemoteDriver` implements all five operations **once**, on top of `Backend` primitives only. State (`path`, `mask`, `files`) is copy-on-write: `with_path()`/`with_mask()`/`with_files()` return a *new* `RemoteDriver` sharing the same backend instance — never mutate in place. `search()` is literally `download(unlink=False, download_content=False)`. Write ops (`upload`/`move`/`delete`) validate the fileset first and raise `NothingToUploadException` if empty.
3. **`multiremote_fm/backends/`** — protocol-specific `Backend` implementations exposing exactly seven primitives declared in `base.py`: `connect`, `close` (both idempotent), `list(path) -> Iterable[Stat]`, `read`, `write`, `rename`, `remove`. Backends know nothing about masks, filesets, or `unlink`/`download_content` flags — that complexity belongs to `RemoteDriver` only. Implementations: `local.py` (`os.scandir`/`os.open`/`os.rename`/`os.unlink`), `ftp.py` (`ftplib`, MLSD with NLST+size fallback for older servers), `sftp.py` (`paramiko`, lazy-imported — raises `ImportError` with an actionable message if `paramiko` isn't installed; install via extra).

Data flow: `Remote.<op>()` → `RemoteDriver.<op>()` → `Backend.<primitive>()` → `RemoteFile`/`RemoteFileSet` value objects returned to caller.

Supporting modules:
- **`multiremote_fm/files.py`** — `RemoteFile` (name/content/size/mimetype via `mimetypes.guess_type`; equality/hash keyed on `name`) and `RemoteFileSet` (dict-backed, insertion-ordered, deduplicated by `name`). Both expose `to_dict()` and `with_driver(driver)` for fluent chaining into a new driver.
- **`multiremote_fm/exceptions.py`** — domain exception hierarchy: `NothingToUploadException`, `SSHPasswordRSAError(ValueError)`, `DownloadingError` (carries `filename` + `message`), `UploadingError`/`MovingError` (subclass `DownloadingError`). No dead/legacy HTTP exceptions.

Design spec/plan (historical context for the current architecture) live under `docs/superpowers/specs/2026-08-28-multiremote-fm-refactor-design.md` and `docs/superpowers/plans/2026-08-28-multiremote-fm-refactor.md`.

## Key Directories

- `multiremote_fm/` — library source. `driver.py` (core logic), `remotes.py` (public entry classes), `files.py` (value objects), `exceptions.py`, `backends/` (per-protocol I/O).
- `tests/` — unittest-based test suite (see below).
- `docs/superpowers/` — design spec and implementation plan from the last refactor; useful for rationale on API/behavior decisions.
- `.github/workflows/` — CI (`test.yml`) and release automation (`publish-to-pypi.yml`).

## Development Commands

```bash
# editable install with dev + sftp extras
pip install -e ".[dev,sftp]"

# lint (must pass, no autofix in CI)
ruff check multiremote_fm tests
ruff format --check multiremote_fm tests

# type-check
mypy multiremote_fm

# tests
pytest tests/ -v
```

CI (`test.yml`) runs this exact sequence across Python 3.10, 3.11, 3.12, 3.13 on ubuntu-latest. Release (`publish-to-pypi.yml`) triggers on tag push, rewrites the version line in `pyproject.toml`, builds sdist+wheel, publishes to PyPI.

Local filesystem tests can target a custom directory: `LOCAL_DIR_PATH=/tmp/multiremote-test pytest tests/test_local_dir.py -v` (defaults to a temp dir if unset).

## Code Conventions & Common Patterns

- **Strategy pattern, not inheritance-per-protocol**: never add protocol-specific logic to `RemoteDriver`; new protocols get a new `Backend` in `backends/` and a thin wrapper in `remotes.py`.
- **Copy-on-write, not mutation**: `with_path`/`with_mask`/`with_files` return new `RemoteDriver` instances. Do not add `set_path`/`set_mask`/mutator methods — the test suite explicitly asserts these don't exist (`tests/test_driver.py`, `tests/test_acceptance.py::test_c20`).
- **Backend boundary is sacred**: `Backend` primitives (`connect/close/list/read/write/rename/remove`) must stay protocol-agnostic; no masking, filtering, or fileset logic inside a backend (`tests/test_backend_base.py` asserts exactly seven primitives).
- **Value objects dedupe by name**: `RemoteFile.__eq__`/`__hash__` and `RemoteFileSet` are keyed on `name` only — adding a file with a duplicate name replaces, not appends.
- **Exceptions carry context**: raise the specific subclass (`DownloadingError`/`UploadingError`/`MovingError`) with `filename` + `message`, not bare `Exception`/`ValueError`, except `SSHPasswordRSAError` (intentionally `ValueError`) and `NothingToUploadException` (intentionally bare `Exception`).
- **No asserts for control flow** — production code must raise real exceptions, not `assert` (enforced by `tests/test_acceptance.py::test_c7`, verified to still fail correctly under `python -O`).
- **Sync-only, no async** — do not introduce `async`/`await`; async support is a documented "planned" item, not current scope.
- **Typing**: fully type-hinted, `py.typed` marker present (PEP 561). Avoid PEP 604 `X | Y` union syntax outside `backends/sftp.py`, which uses `from __future__ import annotations` — match existing per-file style rather than introducing new union syntax elsewhere (enforced by `tests/test_acceptance.py::test_c13`).
- **Formatting**: single-quote strings (`[tool.ruff.format] quote-style = "single"` in `pyproject.toml`). Run `ruff format` rather than hand-formatting.
- **Optional dependency isolation**: `paramiko` is imported lazily inside `backends/sftp.py`, with an `ImportError` pointing to `pip install multiremote-fm[sftp]` if missing. Follow this pattern for any new optional-dependency backend.
- **Frozen public API**: `multiremote_fm/__init__.py` exports exactly `Local, FTP, FTPS, SFTP, BaseDriver, RemoteDriver, RemoteFile, RemoteFileSet` plus the five exceptions. Changing these names/signatures is a breaking change guarded by `tests/test_public_api.py` and `tests/test_acceptance.py` — don't rename or remove without updating README and tests together.

## Important Files

- `multiremote_fm/driver.py` — core five-operations implementation; start here to understand behavior.
- `multiremote_fm/remotes.py` — public-facing classes users instantiate (`Local`, `FTP`, `FTPS`, `SFTP`).
- `multiremote_fm/backends/base.py` — the `Backend` ABC / `Stat` namedtuple contract every backend must satisfy.
- `multiremote_fm/__init__.py` — frozen public API surface + `__version__`.
- `pyproject.toml` — package metadata, extras (`sftp`, `dev`), ruff/mypy config; single source of truth for version (rewritten by CI on tag push).
- `README.md` — user-facing quick start, API reference, and changelog; several tests (`tests/test_readme_claims.py`) assert its content stays in sync with code.
- `tests/fakes.py` — `FakeBackend`, the in-memory `Backend` double used across driver/backend unit tests.

## Runtime/Tooling Preferences

- Python **3.10+** (CI matrix: 3.10–3.13). No Node/Bun/other runtime involved.
- Package manager: **pip** with `pyproject.toml` (setuptools backend) — no Poetry/uv/PDM in use.
- Install dev environment: `pip install -e ".[dev,sftp]"` (or `.[dev]` if not touching SFTP).
- Lint/format: **ruff** (`ruff check`, `ruff format --check`). Type-check: **mypy**. Both are CI gates — run before considering work done.
- `paramiko` is optional; only required for SFTP backend/tests.

## Testing & QA

- Framework: **`unittest`** (via `unittest.TestCase`), run through **pytest** as the discovery/execution frontend. No pytest-specific features in use (no `@pytest.mark.parametrize`, no custom markers, no `pytest.ini`/`[tool.pytest]` config) — match this style; don't introduce pytest-only idioms without discussion.
- Run full suite: `pytest tests/ -v`. Run a single module: `pytest tests/test_driver.py -v`.
- Mocking: `unittest.mock.patch`/`Mock`/`MagicMock` in `setUp`/`tearDown`, e.g. `tests/test_ftp_backend.py` patches `multiremote_fm.backends.ftp.ftplib`; `tests/test_sftp.py` patches `paramiko` and `socket.create_connection`.
- Fakes: `tests/fakes.py::FakeBackend` — an in-memory `Backend` implementation for isolated `RemoteDriver`/`Backend` contract tests (`tests/test_driver.py`, `tests/test_backend_base.py`).
- Real I/O: `tests/test_local_dir.py` exercises the actual filesystem (temp dir by default, override with `LOCAL_DIR_PATH`).
- Integration-only, not auto-run: `tests/_test_ftp.py` is prefixed with `_` (excluded from default discovery) and requires real FTP server env vars (`FTP_HOST`, `FTP_PORT`, `FTP_LOGIN`, `FTP_PASSWORD`, `FTP_DIR`, `FTP_PASSIVE_MODE`, `FTP_ENCODING`).
- Contract/acceptance tests double as living documentation of invariants: `tests/test_acceptance.py`, `tests/test_public_api.py`, `tests/test_readme_claims.py`, `tests/test_legacy_removed.py`, `tests/test_workflows.py` assert things like "five operations defined exactly once package-wide," "no legacy modules reappear," "README claims match code," and "CI workflow still covers all four Python versions." When changing public behavior, check these first — they often encode a decision from the refactor spec.
- No coverage tooling configured; no explicit coverage threshold to satisfy.
