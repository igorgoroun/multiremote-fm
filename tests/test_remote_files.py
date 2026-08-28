import unittest
import logging
from core.file import RemoteFileSet, RemoteFile

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


class TestRemoteFileObjects(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        pass

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_file_single(self):
        file_s = RemoteFile("file_single.txt")
        self.assertEqual(str(file_s), "file_single.txt")
        self.assertEqual(repr(file_s), "RemoteFile(file_single.txt)")
        # print(repr(file_1))
        # print(str(file_1))

    def test_file_multi(self):
        file_1 = RemoteFile("file_1.txt")
        file_2 = RemoteFile("file_2.txt")
        fileset = RemoteFileSet(file_1, file_2)
        self.assertIsInstance(fileset[0], RemoteFile)
        self.assertIsInstance(fileset[1], RemoteFile)


if __name__ == '__main__':
    unittest.main()
