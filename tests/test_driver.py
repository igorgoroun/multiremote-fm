import unittest

from multiremote_fm import (
    BaseDriver,
    NothingToUploadException,
    RemoteDriver,
    RemoteFile,
    RemoteFileSet,
)
from tests.fakes import FakeBackend


class TestRemoteDriverOperations(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeBackend(
            {
                'data/a.txt': b'aaa',
                'data/b.txt': b'bb',
                'data/c.log': b'c',
                'other/d.txt': b'd',
            }
        )
        self.fake.dirs.add('data/nested')
        self.driver = RemoteDriver(backend=self.fake)

    def test_is_a_base_driver(self):
        self.assertIsInstance(self.driver, BaseDriver)

    def test_default_mask_is_star_so_search_finds_everything(self):
        self.assertEqual(self.driver.mask, '*')
        self.assertEqual(self.driver.path, '')
        found = self.driver.with_path('data').search()
        self.assertEqual(len(found), 3)

    def test_search_returns_no_content_but_real_sizes(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        self.assertIsInstance(found, RemoteFileSet)
        self.assertEqual({f.name for f in found}, {'a.txt', 'b.txt'})
        for file in found:
            self.assertEqual(file.content, b'')
            self.assertGreater(file.size, 0)

    def test_download_returns_content(self):
        found = self.driver.with_path('data').with_mask('a.*').download()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'a.txt')
        self.assertEqual(found[0].content, b'aaa')
        self.assertEqual(found[0].size, 3)

    def test_download_skips_directories(self):
        names = {f.name for f in self.driver.with_path('data').search()}
        self.assertNotIn('nested', names)

    def test_download_unlink_removes_source(self):
        found = self.driver.with_path('data').with_mask('*.log').download(unlink=True)
        self.assertEqual(len(found), 1)
        self.assertNotIn('data/c.log', self.fake.tree)
        self.assertIn('data/a.txt', self.fake.tree)

    def test_upload_writes_every_file(self):
        fileset = RemoteFileSet(
            RemoteFile('u1.txt', b'one', 3), RemoteFile('u2.txt', b'two', 3)
        )
        target = self.driver.with_path('out').with_files(fileset)
        self.assertIs(target.upload(), target)
        self.assertEqual(self.fake.tree['out/u1.txt'], b'one')
        self.assertEqual(self.fake.tree['out/u2.txt'], b'two')

    def test_upload_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('out').upload()

    def test_upload_rejects_non_remote_file_members(self):
        fileset = RemoteFileSet()
        fileset._RemoteFileSet__files['bogus'] = 'not-a-file'
        with self.assertRaises(TypeError):
            self.driver.with_path('out').with_files(fileset).upload()

    def test_move_renames_and_returns_copy_at_destination(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        source = self.driver.with_path('data').with_files(found)
        moved = source.move('archive')
        self.assertEqual(moved.path, 'archive')
        self.assertEqual(source.path, 'data')
        self.assertIn('archive/a.txt', self.fake.tree)
        self.assertNotIn('data/a.txt', self.fake.tree)

    def test_move_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('data').move('archive')

    def test_delete_removes_and_returns_self(self):
        found = self.driver.with_path('data').with_mask('*.txt').search()
        target = self.driver.with_path('data').with_files(found)
        self.assertIs(target.delete(), target)
        self.assertNotIn('data/a.txt', self.fake.tree)
        self.assertNotIn('data/b.txt', self.fake.tree)
        self.assertIn('data/c.log', self.fake.tree)

    def test_delete_with_empty_fileset_raises(self):
        with self.assertRaises(NothingToUploadException):
            self.driver.with_path('data').delete()

    def test_empty_path_joins_without_dot_prefix(self):
        driver = RemoteDriver(backend=FakeBackend({'top.txt': b'x'}))
        found = driver.download()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'top.txt')


class TestRemoteDriverCopyOnWrite(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeBackend({'a/one.txt': b'1', 'b/two.txt': b'22'})
        self.driver = RemoteDriver(backend=self.fake)

    def test_with_path_returns_new_object(self):
        copy = self.driver.with_path('a')
        self.assertIsNot(copy, self.driver)
        self.assertEqual(copy.path, 'a')
        self.assertEqual(self.driver.path, '')

    def test_with_mask_returns_new_object(self):
        copy = self.driver.with_mask('*.txt')
        self.assertIsNot(copy, self.driver)
        self.assertEqual(copy.mask, '*.txt')
        self.assertEqual(self.driver.mask, '*')

    def test_with_files_returns_new_object(self):
        fileset = RemoteFileSet(RemoteFile('x.txt'))
        copy = self.driver.with_files(fileset)
        self.assertIsNot(copy, self.driver)
        self.assertEqual(len(copy.files), 1)
        self.assertEqual(len(self.driver.files), 0)

    def test_copies_share_one_backend_instance(self):
        chain = (
            self.driver.with_path('a').with_mask('*.txt').with_files(RemoteFileSet())
        )
        self.assertIs(chain.backend, self.fake)
        self.assertIs(self.driver.backend, self.fake)

    def test_no_state_leaks_between_chains(self):
        first = self.driver.with_path('a').search()
        second = self.driver.with_path('b').search()
        self.assertEqual({f.name for f in first}, {'one.txt'})
        self.assertEqual({f.name for f in second}, {'two.txt'})
        self.assertEqual(self.driver.path, '')

    def test_file_with_driver_returns_configured_copy_without_mutating(self):
        file = RemoteFile('one.txt', b'1', 1)
        configured = file.with_driver(self.driver)
        self.assertIsNot(configured, self.driver)
        self.assertEqual(len(configured.files), 1)
        self.assertEqual(len(self.driver.files), 0)
        self.assertIs(configured.backend, self.fake)

    def test_fileset_with_driver_returns_configured_copy_without_mutating(self):
        fileset = RemoteFileSet(RemoteFile('one.txt', b'1', 1))
        configured = fileset.with_driver(self.driver)
        self.assertIsNot(configured, self.driver)
        self.assertEqual(len(configured.files), 1)
        self.assertEqual(len(self.driver.files), 0)

    def test_with_driver_preserves_path_and_mask_of_the_receiver(self):
        source = self.driver.with_path('a').with_mask('*.txt')
        found = source.search()
        configured = found.with_driver(source)
        self.assertEqual(configured.path, 'a')
        self.assertEqual(configured.mask, '*.txt')
        downloaded = configured.download()
        self.assertEqual({f.name for f in downloaded}, {'one.txt'})

    def test_no_set_path_or_set_files_mutators_exist(self):
        self.assertFalse(hasattr(self.driver, 'set_path'))
        self.assertFalse(hasattr(self.driver, 'set_files'))
        self.assertFalse(hasattr(BaseDriver, 'set_files'))

    def test_base_driver_declares_exactly_the_eight_frozen_methods(self):
        self.assertEqual(
            BaseDriver.__abstractmethods__,
            frozenset(
                {
                    'search',
                    'download',
                    'upload',
                    'move',
                    'delete',
                    'with_path',
                    'with_mask',
                    'with_files',
                }
            ),
        )

    def test_repr_and_str(self):
        driver = self.driver.with_path('a').with_mask('*.txt')
        self.assertEqual(str(driver), 'RemoteDriver(a, *.txt)')
        self.assertEqual(repr(driver), 'RemoteDriver(path=a, mask=*.txt)')


if __name__ == '__main__':
    unittest.main()
