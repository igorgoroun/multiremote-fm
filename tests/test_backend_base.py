import unittest

from multiremote_fm.backends import Backend, Stat

from tests.fakes import FakeBackend


class TestBackendBase(unittest.TestCase):
    def test_stat_fields_and_order(self):
        st = Stat('a.txt', 12, False)
        self.assertEqual(st.name, 'a.txt')
        self.assertEqual(st.size, 12)
        self.assertFalse(st.is_dir)
        self.assertEqual(tuple(st), ('a.txt', 12, False))
        self.assertEqual(Stat._fields, ('name', 'size', 'is_dir'))

    def test_backend_is_abstract(self):
        with self.assertRaises(TypeError):
            Backend()

    def test_backend_declares_exactly_the_seven_primitives(self):
        self.assertEqual(
            Backend.__abstractmethods__,
            frozenset({'connect', 'close', 'list', 'read', 'write', 'rename', 'remove'}),
        )

    def test_fake_backend_is_a_backend(self):
        self.assertIsInstance(FakeBackend(), Backend)

    def test_fake_backend_list_returns_only_direct_children(self):
        fake = FakeBackend({'a.txt': b'1', 'sub/b.txt': b'22'})
        fake.dirs.add('sub')
        top = sorted(fake.list('.'), key=lambda s: s.name)
        self.assertEqual([(s.name, s.size, s.is_dir) for s in top], [('a.txt', 1, False), ('sub', 0, True)])
        self.assertEqual([(s.name, s.size, s.is_dir) for s in fake.list('sub')], [('b.txt', 2, False)])

    def test_fake_backend_primitives_round_trip(self):
        fake = FakeBackend()
        fake.connect()
        fake.write('x/a.txt', b'hello')
        self.assertEqual(fake.read('x/a.txt'), b'hello')
        fake.rename('x/a.txt', 'y/a.txt')
        self.assertEqual(fake.read('y/a.txt'), b'hello')
        fake.remove('y/a.txt')
        with self.assertRaises(KeyError):
            fake.read('y/a.txt')
        fake.close()
        self.assertEqual(fake.connect_calls, 1)
        self.assertEqual(fake.close_calls, 1)


if __name__ == '__main__':
    unittest.main()
