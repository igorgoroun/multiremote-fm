import glob
import logging
import os
import unittest
import uuid

from core.file import RemoteFile, RemoteFileSet
from drivers.local import Local

_logger = logging.getLogger('test_local_dir')
_logger.setLevel(logging.DEBUG)


class TestLocalDir(unittest.TestCase):
    local_dir_path: str
    driver: Local

    @classmethod
    def setUpClass(cls) -> None:
        cls.local_dir_path = os.environ.get('LOCAL_DIR_PATH', './tmp/')
        ext_to_create = ['xml', 'csv', 'xml', 'doc', 'xlsx', 'doc', 'jpg', 'c']
        for ex in ext_to_create:
            fnm = uuid.uuid4().hex
            with open(os.path.join(cls.local_dir_path, f'{fnm}.{ex}'), mode='w') as f:
                f.write(fnm)

    @classmethod
    def tearDownClass(cls) -> None:
        path_pattern = os.path.join(cls.local_dir_path or '', '*')
        for file_path in glob.glob(pathname=path_pattern):
            if os.path.isfile(file_path):
                os.unlink(file_path)

    def setUp(self) -> None:
        self.driver = Local()

    def tearDown(self) -> None:
        pass

    def test_search_common(self):
        files = self.driver.with_path(self.local_dir_path).search()
        self.assertIsInstance(files, RemoteFileSet)
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)

    def test_search_by_mask(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.x*').search()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 3)
        files = self.driver.with_path(self.local_dir_path).with_mask('*.c').search()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 1)

    def test_download(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.doc').download()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 2)
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertIsNotNone(file.content)
            self.assertGreater(len(file.content), 0)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)

    def test_download_unlink(self):
        files = (
            self.driver.with_path(self.local_dir_path)
            .with_mask('*.jpg')
            .download(unlink=True)
        )
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 1)
        deleted_files = (
            self.driver.with_path(self.local_dir_path).with_mask('*.jpg').search()
        )
        self.assertEqual(len(deleted_files), 0)

    def test_download_searched(self):
        found_file_list = (
            self.driver.with_path(self.local_dir_path).with_mask('*.x*').search()
        )
        self.assertIsInstance(found_file_list, RemoteFileSet)
        self.assertEqual(len(found_file_list), 3)
        files = found_file_list.with_driver(self.driver).download()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), 3)


if __name__ == '__main__':
    unittest.main()
