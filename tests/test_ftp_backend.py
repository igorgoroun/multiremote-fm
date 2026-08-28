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
        kwargs = {
            'host': 'ftp.example.com',
            'port': 21,
            'login': 'user',
            'password': 'pass',
        }
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
        self.mock_client.mlsd.assert_called_once_with(
            '/incoming', facts=['type', 'size']
        )
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
        self.assertEqual(
            [(e.name, e.size, e.is_dir) for e in entries], [('a.txt', 3, False)]
        )
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
        target = ftp.with_path('/out').with_files(
            RemoteFileSet(RemoteFile('a.txt', b'x', 1))
        )
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
