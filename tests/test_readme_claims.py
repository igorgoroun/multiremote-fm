import os
import unittest


class TestReadmeClaims(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'README.md'), encoding='utf-8') as handle:
            cls.readme = handle.read()

    def test_memory_efficient_claim_is_gone(self):
        self.assertNotIn('Memory Efficient', self.readme)

    def test_download_content_remains_the_memory_story(self):
        self.assertIn('download_content=False', self.readme)

    def test_python_floor_is_310(self):
        self.assertNotIn('python-3.9+', self.readme)
        self.assertIn('python-3.10+', self.readme)

    def test_sftp_extra_is_documented(self):
        self.assertIn('pip install multiremote-fm[sftp]', self.readme)

    def test_dev_install_documents_the_editable_install(self):
        self.assertIn('pip install -e ".[dev]"', self.readme)

    def test_changelog_mentions_v02(self):
        self.assertIn('v0.2.0', self.readme)


if __name__ == '__main__':
    unittest.main()
