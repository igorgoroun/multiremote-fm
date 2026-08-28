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
        self.socket_patcher = patch(
            'multiremote_fm.backends.sftp.socket.create_connection'
        )
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
        kwargs = {
            'host': 'test.com',
            'port': 22,
            'login': 'testuser',
            'password': 'testpass',
        }
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

        self.mock_create_connection.assert_called_once_with(
            ('test.com', 22), timeout=30
        )
        self.mock_paramiko.Transport.assert_called_once_with(self.mock_socket)
        self.assertEqual(self.mock_transport.banner_timeout, 30)
        self.assertEqual(self.mock_transport.auth_timeout, 30)
        self.mock_transport.connect.assert_called_once_with(
            username='testuser',
            pkey=None,
            password='testpass',
        )
        self.mock_paramiko.SFTPClient.from_transport.assert_called_once_with(
            self.mock_transport
        )

    def test_connect_with_rsa(self):
        mock_rsa_key = Mock()
        self.mock_paramiko.RSAKey.from_private_key.return_value = mock_rsa_key
        sftp = self._sftp(password=None, rsa=RSA_KEY, response_timeout=45)

        sftp.backend.connect()

        self.mock_paramiko.RSAKey.from_private_key.assert_called_once()
        self.mock_create_connection.assert_called_once_with(
            ('test.com', 22), timeout=45
        )
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
        self.mock_sftp.listdir_attr.return_value = self._listing(
            ('test.txt', 11, 33188)
        )

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
        uploaded = {
            call.kwargs['remotepath'] for call in self.mock_sftp.putfo.call_args_list
        }
        self.assertEqual(
            uploaded, {'/upload/path/upload1.txt', '/upload/path/upload2.txt'}
        )

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
