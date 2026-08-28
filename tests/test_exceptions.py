import unittest

from multiremote_fm import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)


class TestExceptions(unittest.TestCase):
    def test_nothing_to_upload_message(self):
        self.assertEqual(str(NothingToUploadException()), 'Nothing to upload')

    def test_ssh_password_rsa_error_is_value_error(self):
        self.assertIsInstance(SSHPasswordRSAError(), ValueError)
        self.assertEqual(
            str(SSHPasswordRSAError()),
            'One of the attributes `password` or `rsa` should be defined',
        )

    def test_downloading_error_carries_filename_and_message(self):
        err = DownloadingError('a.txt', 'boom')
        self.assertEqual(err.filename, 'a.txt')
        self.assertEqual(err.message, 'boom')
        self.assertEqual(str(err), 'Cannot download file a.txt: boom')

    def test_uploading_and_moving_error_messages(self):
        self.assertEqual(str(UploadingError('a.txt', 'boom')), 'Cannot upload file a.txt: boom')
        self.assertEqual(str(MovingError('a.txt', 'boom')), 'Cannot move file a.txt: boom')
        self.assertIsInstance(UploadingError('a', 'b'), DownloadingError)
        self.assertIsInstance(MovingError('a', 'b'), DownloadingError)

    def test_dead_http_exceptions_are_gone(self):
        import multiremote_fm.exceptions as mod

        self.assertFalse(hasattr(mod, 'InvalidResponseCodeError'))
        self.assertFalse(hasattr(mod, 'InvalidJSONResponseError'))

    def test_version(self):
        import multiremote_fm

        self.assertEqual(multiremote_fm.__version__, '0.2.0')


if __name__ == '__main__':
    unittest.main()
