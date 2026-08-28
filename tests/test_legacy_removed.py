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
