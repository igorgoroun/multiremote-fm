import os
import unittest


class TestWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.workflows = os.path.join(cls.root, '.github', 'workflows')

    def _read(self, name: str) -> str:
        with open(os.path.join(self.workflows, name), encoding='utf-8') as handle:
            return handle.read()

    def test_publish_workflow_has_no_deprecated_directives(self):
        content = self._read('publish-to-pypi.yml')
        self.assertNotIn('::set-output', content)
        self.assertNotIn('actions/checkout@main', content)
        self.assertIn('actions/checkout@v4', content)
        self.assertIn('$GITHUB_OUTPUT', content)

    def test_publish_workflow_rewrites_the_real_version_line(self):
        content = self._read('publish-to-pypi.yml')
        self.assertIn('s/^version = .*/version = ', content)
        self.assertNotIn('{{VERSION_PLACEHOLDER}}', content)

    def test_test_workflow_exists_and_covers_four_pythons(self):
        content = self._read('test.yml')
        for version in ('3.10', '3.11', '3.12', '3.13'):
            self.assertIn('"{0}"'.format(version), content)
        self.assertIn('pytest', content)
        self.assertIn('ruff', content)
        self.assertIn('actions/checkout@v4', content)


if __name__ == '__main__':
    unittest.main()
