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
                check=False,
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
            [sys.executable, '-c', script],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
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
                            offenders.append('{0}:{1}'.format(full, lineno))  # noqa: UP030, UP032
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
        result = subprocess.run(  # noqa: PLW1510
            [sys.executable, '-O', '-c', script],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
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
                        offenders.append('{0}:{1}'.format(full, lineno))  # noqa: UP030, UP032
        self.assertEqual(offenders, [])

    def test_c14_pyproject_declarations(self):
        with open(
            os.path.join(REPO_ROOT, 'pyproject.toml'), encoding='utf-8'
        ) as handle:
            content = handle.read()
        self.assertIn('requires-python = ">=3.10"', content)
        self.assertIn(
            'packages = ["multiremote_fm", "multiremote_fm.backends"]', content
        )
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
        counts = {
            'def search': 0,
            'def download': 0,
            'def upload': 0,
            'def move': 0,
            'def delete': 0,
        }
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
                        self.fail('{0} defines {1}'.format(full, op))  # noqa: UP030, UP032
                    counts[op] += found
        # driver.py declares each operation twice: once abstract on BaseDriver, once concrete.
        for op, count in counts.items():
            self.assertEqual(count, 2, '{0} declared {1} times'.format(op, count))  # noqa: UP030, UP032

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
