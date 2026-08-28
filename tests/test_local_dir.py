import glob
import os
import shutil
import tempfile
import unittest

from multiremote_fm import Local, RemoteFile, RemoteFileSet


class TestLocalDir(unittest.TestCase):
    local_dir_path: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.local_dir_path = os.environ.get('LOCAL_DIR_PATH') or tempfile.mkdtemp(
            prefix='multiremote-test-'
        )
        cls._owns_dir = 'LOCAL_DIR_PATH' not in os.environ
        os.makedirs(cls.local_dir_path, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._owns_dir:
            shutil.rmtree(cls.local_dir_path, ignore_errors=True)

    def setUp(self) -> None:
        for file_path in glob.glob(os.path.join(self.local_dir_path, '*')):
            if os.path.isfile(file_path):
                os.unlink(file_path)
        self.created = ['f1.xml', 'f2.csv', 'f3.xml', 'f4.doc', 'f5.xlsx', 'f6.doc', 'f7.jpg', 'f8.c']
        for name in self.created:
            with open(os.path.join(self.local_dir_path, name), mode='w') as handle:
                handle.write(name)
        self.driver = Local()

    def test_search_common(self):
        """Every file is found when no mask is set - the count assertion is the point.

        Named exactly `test_search_common` because spec criterion 11 names this
        identifier. Do not rename it.
        """
        files = self.driver.with_path(self.local_dir_path).search()
        self.assertIsInstance(files, RemoteFileSet)
        self.assertEqual(len(files), len(self.created))
        for file in files:
            self.assertIsInstance(file, RemoteFile)
            self.assertIsNotNone(file.name)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)
            self.assertEqual(file.content, b'')

    def test_search_skips_subdirectories(self):
        os.makedirs(os.path.join(self.local_dir_path, 'subdir'), exist_ok=True)
        try:
            files = self.driver.with_path(self.local_dir_path).search()
            self.assertEqual(len(files), len(self.created))
            self.assertNotIn('subdir', {f.name for f in files})
        finally:
            os.rmdir(os.path.join(self.local_dir_path, 'subdir'))

    def test_search_by_mask(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.x*').search()
        self.assertEqual(len(files), 3)
        files = self.driver.with_path(self.local_dir_path).with_mask('*.c').search()
        self.assertEqual(len(files), 1)

    def test_download(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.doc').download()
        self.assertEqual(len(files), 2)
        for file in files:
            self.assertGreater(len(file.content), 0)
            self.assertGreater(file.size, 0)
            self.assertIsNotNone(file.mimetype)

    def test_download_unlink(self):
        files = self.driver.with_path(self.local_dir_path).with_mask('*.jpg').download(unlink=True)
        self.assertEqual(len(files), 1)
        deleted = self.driver.with_path(self.local_dir_path).with_mask('*.jpg').search()
        self.assertEqual(len(deleted), 0)

    def test_download_searched(self):
        source = self.driver.with_path(self.local_dir_path).with_mask('*.x*')
        found_file_list = source.search()
        self.assertEqual(len(found_file_list), 3)
        files = found_file_list.with_driver(source).download()
        self.assertEqual(len(files), 3)
        for file in files:
            self.assertGreater(len(file.content), 0)

    def test_upload_writes_files(self):
        target_dir = os.path.join(self.local_dir_path, 'out')
        os.makedirs(target_dir, exist_ok=True)
        fileset = RemoteFileSet(RemoteFile('up.txt', b'payload', 7))
        self.driver.with_path(target_dir).with_files(fileset).upload()
        with open(os.path.join(target_dir, 'up.txt'), mode='rb') as handle:
            self.assertEqual(handle.read(), b'payload')
        shutil.rmtree(target_dir)

    def test_move_files(self):
        target_dir = os.path.join(self.local_dir_path, 'archive')
        os.makedirs(target_dir, exist_ok=True)
        source = self.driver.with_path(self.local_dir_path).with_mask('*.csv')
        found = source.search()
        moved = source.with_files(found).move(target_dir)
        self.assertEqual(moved.path, target_dir)
        self.assertTrue(os.path.isfile(os.path.join(target_dir, 'f2.csv')))
        self.assertFalse(os.path.isfile(os.path.join(self.local_dir_path, 'f2.csv')))
        shutil.rmtree(target_dir)

    def test_delete_files(self):
        source = self.driver.with_path(self.local_dir_path).with_mask('*.c')
        found = source.search()
        source.with_files(found).delete()
        self.assertFalse(os.path.isfile(os.path.join(self.local_dir_path, 'f8.c')))

    def test_local_takes_no_constructor_arguments(self):
        with self.assertRaises(TypeError):
            Local(pasword='typo')


if __name__ == '__main__':
    unittest.main()
