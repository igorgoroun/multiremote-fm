import unittest

from multiremote_fm import RemoteFile, RemoteFileSet


class TestRemoteFileObjects(unittest.TestCase):
    def test_file_single(self):
        file_s = RemoteFile('file_single.txt')
        self.assertEqual(str(file_s), 'file_single.txt')
        self.assertEqual(repr(file_s), 'RemoteFile(file_single.txt)')
        self.assertEqual(file_s.content, b'')
        self.assertEqual(file_s.size, 0)

    def test_file_multi_indexing(self):
        file_1 = RemoteFile('file_1.txt')
        file_2 = RemoteFile('file_2.txt')
        fileset = RemoteFileSet(file_1, file_2)
        self.assertIsInstance(fileset[0], RemoteFile)
        self.assertIsInstance(fileset[1], RemoteFile)

    def test_mimetype_guessed_and_fallback(self):
        self.assertEqual(RemoteFile('doc.pdf').mimetype, 'application/pdf')
        self.assertEqual(RemoteFile('blob.unknownext').mimetype, 'application/octet-stream')

    def test_to_dict(self):
        f = RemoteFile('a.txt', b'hi', 2)
        self.assertEqual(
            f.to_dict(),
            {'name': 'a.txt', 'content': b'hi', 'size': 2, 'mimetype': 'text/plain'},
        )

    def test_equality_and_hash_keyed_on_name(self):
        a = RemoteFile('same.txt', b'x', 1)
        b = RemoteFile('same.txt', b'x', 1)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, RemoteFile('other.txt', b'x', 1))
        self.assertNotEqual(a, 'same.txt')

    def test_fileset_deduplicates_by_name(self):
        a = RemoteFile('same.txt', b'x', 1)
        b = RemoteFile('same.txt', b'x', 1)
        self.assertEqual(len(RemoteFileSet(a, b)), 1)

    def test_fileset_is_insertion_ordered_and_stable(self):
        """Order follows insertion, and repeated indexing is deterministic.

        The old set-backed implementation indexed into `list(set)`, whose order was
        arbitrary; the dict-backed one is insertion-ordered, so `fileset[0]` is stable.
        """
        names = ['c.txt', 'a.txt', 'b.txt']
        fileset = RemoteFileSet(*[RemoteFile(n) for n in names])
        self.assertEqual([f.name for f in fileset], names)
        self.assertEqual(fileset[0].name, 'c.txt')
        self.assertEqual(fileset[-1].name, 'b.txt')

    def test_fileset_add_and_files_property(self):
        fileset = RemoteFileSet()
        self.assertEqual(len(fileset), 0)
        fileset.add(RemoteFile('a.txt'), RemoteFile('b.txt'))
        self.assertEqual(len(fileset), 2)
        self.assertIsInstance(fileset.files, set)
        self.assertEqual({f.name for f in fileset.files}, {'a.txt', 'b.txt'})

    def test_fileset_add_rejects_non_remote_file(self):
        with self.assertRaises(TypeError):
            RemoteFileSet().add('not-a-file')

    def test_fileset_repr(self):
        fileset = RemoteFileSet(RemoteFile('a.txt'))
        self.assertEqual(repr(fileset), 'RemoteFileSet(RemoteFile(a.txt),)')
        self.assertEqual(str(fileset), repr(fileset))
    def test_fileset_add_is_atomic_on_type_error(self):
        fileset = RemoteFileSet(RemoteFile('existing.txt'))
        with self.assertRaises(TypeError):
            fileset.add(RemoteFile('new.txt'), 'not-a-file')
        self.assertEqual(len(fileset), 1)
        self.assertEqual([f.name for f in fileset], ['existing.txt'])



if __name__ == '__main__':
    unittest.main()
