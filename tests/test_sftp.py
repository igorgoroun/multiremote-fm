import unittest
import os
import logging
from unittest.mock import Mock, patch, MagicMock

from core.file import RemoteFile, RemoteFileSet
from core.exceptions import SSHPasswordRSAError

_logger = logging.getLogger('test_sftp')
_logger.setLevel(logging.DEBUG)


class TestSFTP(unittest.TestCase):
    """Test SFTP driver functionality."""

    def setUp(self) -> None:
        # Mock paramiko to avoid requiring it for tests
        self.paramiko_patcher = patch('drivers.sftp.paramiko')
        self.mock_paramiko = self.paramiko_patcher.start()
        
        # Setup mock objects
        self.mock_transport = Mock()
        self.mock_sftp = Mock()
        self.mock_paramiko.Transport.return_value = self.mock_transport
        self.mock_paramiko.SFTPClient.from_transport.return_value = self.mock_sftp

    def tearDown(self) -> None:
        self.paramiko_patcher.stop()

    def test_import_without_paramiko(self):
        """Test that SFTP raises ImportError when paramiko is not available."""
        with patch('drivers.sftp.paramiko', None):
            from drivers.sftp import SFTP
            
            with self.assertRaises(ImportError) as cm:
                SFTP(host='test', port=22, login='user', password='pass')
            
            self.assertIn("paramiko is required", str(cm.exception))

    def test_init_without_password_or_rsa(self):
        """Test that SFTP raises SSHPasswordRSAError without credentials."""
        from drivers.sftp import SFTP
        
        with self.assertRaises(SSHPasswordRSAError):
            SFTP(host='test', port=22, login='user')

    def test_init_with_password(self):
        """Test SFTP initialization with password."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        self.assertEqual(sftp.host, 'test.com')
        self.assertEqual(sftp.port, 22)
        self.assertEqual(sftp.login, 'testuser')
        self.assertEqual(sftp.password, 'testpass')
        self.assertEqual(sftp.response_timeout, 30)  # default

    def test_init_with_rsa(self):
        """Test SFTP initialization with RSA key."""
        from drivers.sftp import SFTP
        
        rsa_key = b'-----BEGIN RSA PRIVATE KEY-----\\ntest\\n-----END RSA PRIVATE KEY-----'
        sftp = SFTP(host='test.com', port=22, login='testuser', rsa=rsa_key)
        
        self.assertEqual(sftp.rsa, rsa_key)

    def test_connect_with_password(self):
        """Test SFTP connection with password."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Mock the connection process
        result = sftp.connect()
        
        # Verify connection was attempted
        self.mock_paramiko.Transport.assert_called_with(('test.com', 22))
        self.mock_transport.connect.assert_called_with(
            username='testuser',
            pkey=None,  # No RSA key
            password='testpass',
            timeout=30
        )
        
        self.assertEqual(result, self.mock_sftp)

    @patch('drivers.sftp.StringIO')
    def test_connect_with_rsa(self, mock_stringio):
        """Test SFTP connection with RSA key."""
        from drivers.sftp import SFTP
        
        rsa_key = b'-----BEGIN RSA PRIVATE KEY-----\\ntest\\n-----END RSA PRIVATE KEY-----'
        mock_rsa_key = Mock()
        self.mock_paramiko.RSAKey.from_private_key.return_value = mock_rsa_key
        
        sftp = SFTP(host='test.com', port=22, login='testuser', rsa=rsa_key)
        
        result = sftp.connect()
        
        # Verify RSA key processing
        mock_stringio.assert_called()
        self.mock_paramiko.RSAKey.from_private_key.assert_called()
        
        # Verify connection with RSA key
        self.mock_transport.connect.assert_called_with(
            username='testuser',
            pkey=mock_rsa_key,
            password=None,
            timeout=30
        )

    def test_search_files(self):
        """Test searching for files."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Mock file listing
        mock_file1 = Mock()
        mock_file1.filename = 'test1.txt'
        mock_file1.st_mode = 33188  # Regular file mode
        mock_file1.st_size = 100
        
        mock_file2 = Mock()
        mock_file2.filename = 'test2.txt'  
        mock_file2.st_mode = 33188
        mock_file2.st_size = 200
        
        self.mock_sftp.listdir_attr.return_value = [mock_file1, mock_file2]
        
        # Test search
        files = sftp.with_path('/remote/path').with_mask('*.txt').search()
        
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 2)
        
        # Verify files were found but content wasn't downloaded
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertEqual(file.content, b'')  # No content in search

    def test_download_files(self):
        """Test downloading files with content."""
        from drivers.sftp import SFTP
        from io import BytesIO
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Mock file listing
        mock_file = Mock()
        mock_file.filename = 'test.txt'
        mock_file.st_mode = 33188  # Regular file mode
        mock_file.st_size = 11
        
        self.mock_sftp.listdir_attr.return_value = [mock_file]
        
        # Mock file content download
        def mock_getfo(remotepath, fl):
            fl.write(b'Hello World')
        
        self.mock_sftp.getfo.side_effect = mock_getfo
        
        # Test download
        files = sftp.with_path('/remote/path').with_mask('*.txt').download()
        
        self.assertEqual(len(files), 1)
        file = files[0]
        self.assertEqual(file.name, 'test.txt')
        self.assertEqual(file.content, b'Hello World')
        self.assertEqual(file.size, 11)

    def test_upload_files(self):
        """Test uploading files."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Create test files
        file1 = RemoteFile(name='upload1.txt', content=b'Content 1', size=9)
        file2 = RemoteFile(name='upload2.txt', content=b'Content 2', size=9)
        fileset = RemoteFileSet(file1, file2)
        
        # Mock upload result
        mock_result = Mock()
        mock_result.st_size = 9
        self.mock_sftp.putfo.return_value = mock_result
        
        # Test upload
        result = sftp.with_path('/upload/path').with_files(fileset).upload()
        
        self.assertEqual(result, sftp)  # Should return self
        
        # Verify upload was called for each file
        self.assertEqual(self.mock_sftp.putfo.call_count, 2)

    def test_move_files(self):
        """Test moving files."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Create test files
        file1 = RemoteFile(name='move1.txt', content=b'', size=0)
        fileset = RemoteFileSet(file1)
        
        # Test move
        result = sftp.with_path('/source').with_files(fileset).move('/destination')
        
        self.assertEqual(result, sftp)
        self.assertEqual(sftp.path, '/destination')  # Path should be updated
        
        # Verify rename was called
        self.mock_sftp.rename.assert_called_with('/source/move1.txt', '/destination/move1.txt')

    def test_delete_files(self):
        """Test deleting files."""
        from drivers.sftp import SFTP
        
        sftp = SFTP(host='test.com', port=22, login='testuser', password='testpass')
        
        # Create test files
        file1 = RemoteFile(name='delete1.txt', content=b'', size=0)
        fileset = RemoteFileSet(file1)
        
        # Test delete
        result = sftp.with_path('/path').with_files(fileset).delete()
        
        self.assertEqual(result, sftp)
        
        # Verify unlink was called
        self.mock_sftp.unlink.assert_called_with('/path/delete1.txt')


if __name__ == '__main__':
    unittest.main()
