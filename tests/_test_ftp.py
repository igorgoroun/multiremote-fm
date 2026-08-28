import os
import unittest

from multiremote_fm import FTP, FTPS, RemoteFile, RemoteFileSet


class TestRemoteFTP(unittest.TestCase):
    driver_ftp: FTP
    driver_ftps: FTPS
    credentials: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.credentials = {
            'host': os.environ.get('FTP_HOST', None),
            'port': int(os.environ.get('FTP_PORT', None)),
            'response_timeout': 10,
            'login': os.environ.get('FTP_LOGIN', None),
            'password': os.environ.get('FTP_PASSWORD', None),
            'passive_mode': os.environ.get('FTP_PASSIVE_MODE', 'true').lower()
            not in ('false', '0', ''),
            'encoding': os.environ.get('FTP_ENCODING', 'utf-8'),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def setUp(self) -> None:
        self.driver_ftp = FTP(**self.credentials)
        self.driver_ftps = FTPS(**self.credentials)

    def tearDown(self) -> None:
        pass

    def test_ftp_search_path(self):
        files = self.driver_ftp.with_path(os.environ.get('FTP_DIR')).search()
        print(files)
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertEqual(len(file.content), 0)
            self.assertIsNotNone(file.mimetype)
            print(file.mimetype)

    def test_ftp_search_path_ext(self):
        files = (
            self.driver_ftp.with_path(os.environ.get('FTP_DIR'))
            .with_mask('*.xml')
            .search()
        )
        print(files)
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertEqual(len(file.content), 0)
            self.assertIsNotNone(file.mimetype)
            self.assertEqual(file.mimetype, 'application/xml')
            print(file.mimetype)

    def test_ftp_search_path_mask(self):
        files = (
            self.driver_ftp.with_path(os.environ.get('FTP_DIR'))
            .with_mask('*OFF*')
            .search()
        )
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertEqual(len(file.content), 0)
            self.assertTrue('OFF' in file.name)
            print(file.name)

    def test_ftp_download_path(self):
        files = (
            self.driver_ftp.with_path(os.environ.get('FTP_DIR'))
            .with_mask('*TAKEOFF*')
            .download()
        )
        self.assertTrue(len(files) == 1)
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertGreater(len(file.content), 0)
            print(file.size)

    def test_ftp_upload_file(self):
        files = RemoteFileSet(
            RemoteFile('first_file.xml', b'Some content of first file.'),
            RemoteFile('second_file.txt', b'Some content of the second file.'),
            RemoteFile('third_file.html', b'<p>Some content of the third file.</p>'),
        )
        files.with_driver(self.driver_ftp).with_path(os.environ.get('FTP_DIR')).upload()


if __name__ == '__main__':
    unittest.main()
