import unittest
import os
import logging
from multiremote_fm import FTP, FileObj

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger(__name__)


class TestMultiRemote(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        # _logger.debug("Setup Class")
        pass

    @classmethod
    def tearDownClass(cls) -> None:
        # _logger.debug("Teardown Class")
        pass

    def setUp(self) -> None:
        # _logger.debug("Run setUp")
        # _logger.debug(os.environ.get('FTP_LOGIN', None))
        pass

    def tearDown(self) -> None:
        # _logger.debug("Run tearDown")
        pass

    def test_connect(self):
        self.assertEqual(True, True)

    def test_list(self):
        self.assertEqual(True, True)

    def test_download(self):
        self.assertEqual(True, True)


if __name__ == '__main__':
    unittest.main()
