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
