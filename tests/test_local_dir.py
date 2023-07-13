import unittest
import os
import uuid
import glob
import logging
from multiremote_fm import FileObj, LocalDir

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger(__name__)


class TestLocalDir(unittest.TestCase):
    local_dir_path: str
    driver: LocalDir

    @classmethod
    def setUpClass(cls) -> None:
        cls.local_dir_path = os.environ.get('LOCAL_DIR_PATH', None)
        ext_to_create = ['xml', 'csv', 'xml', 'doc', 'xlsx', 'doc', 'jpg', 'c']
        for ex in ext_to_create:
            fnm = uuid.uuid4().hex
            # _logger.debug(f"Creating tmp file {fnm}.{ex}")
            with open(os.path.join(cls.local_dir_path, f"{fnm}.{ex}"), mode='w') as f:
                f.write(fnm)

    @classmethod
    def tearDownClass(cls) -> None:
        path_pattern = os.path.join(cls.local_dir_path or '', '*')
        for file_path in glob.glob(pathname=path_pattern):
            if os.path.isfile(file_path):
                # _logger.debug(f"Deleting file {file_path}")
                os.unlink(file_path)

    def setUp(self) -> None:
        self.driver = LocalDir()
        self.driver.path = self.local_dir_path

    def tearDown(self) -> None:
        pass

    def test_list(self):
        self.driver.list()
        self.assertIsInstance(self.driver.response, list)
        self.assertTrue(self.driver.response)
        for i in self.driver.response:
            self.assertIsInstance(i, FileObj)
            self.assertIsNotNone(i.file_name)
            self.assertEqual(len(i.file_content), 0)
            self.assertGreater(i.file_size, 0)
            self.assertIsNotNone(i.file_mimetype)

    def test_download(self):
        self.driver.download(unlink=False)
        self.assertIsInstance(self.driver.response, list)
        self.assertTrue(self.driver.response)
        for i in self.driver.response:
            self.assertIsInstance(i, FileObj)
            self.assertIsNotNone(i.file_name)
            self.assertGreater(len(i.file_content), 0)
            self.assertGreater(i.file_size, 0)
            self.assertIsNotNone(i.file_mimetype)

    def test_download_unlink(self):
        self.driver.mask = "*.xml"
        self.driver.download(unlink=True)
        self.assertIsInstance(self.driver.response, list)
        self.assertTrue(self.driver.response)
        # check were deleted
        self.driver.list()
        self.assertIsInstance(self.driver.response, list)
        self.assertFalse(self.driver.response)

    def test_download_single(self):
        self.driver.mask = '*.c'
        self.driver.list()
        self.assertIsInstance(self.driver.response, list)
        self.assertTrue(self.driver.response)
        file = self.driver.response[0]
        filepath = os.path.join(self.driver.path, file.file_name)
        self.driver.path = filepath
        self.driver.download_single()
        self.assertIsInstance(self.driver.response, list)
        self.assertTrue(self.driver.response)
        for i in self.driver.response:
            print(i.file_name)
            self.assertIsInstance(i, FileObj)
            self.assertIsNotNone(i.file_name)
            self.assertGreater(len(i.file_content), 0)
            self.assertGreater(i.file_size, 0)
            self.assertIsNotNone(i.file_mimetype)



if __name__ == '__main__':
    unittest.main()
