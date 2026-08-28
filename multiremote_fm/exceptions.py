"""Exceptions raised by multiremote-fm."""


class NothingToUploadException(Exception):
    def __str__(self) -> str:
        return 'Nothing to upload'


class SSHPasswordRSAError(ValueError):
    def __str__(self) -> str:
        return 'One of the attributes `password` or `rsa` should be defined'


class DownloadingError(Exception):
    def __init__(self, filename: str, message: str) -> None:
        super().__init__(filename, message)
        self.filename = filename
        self.message = message

    def __str__(self) -> str:
        return 'Cannot download file {0}: {1}'.format(self.filename, self.message)


class UploadingError(DownloadingError):
    def __str__(self) -> str:
        return 'Cannot upload file {0}: {1}'.format(self.filename, self.message)


class MovingError(DownloadingError):
    def __str__(self) -> str:
        return 'Cannot move file {0}: {1}'.format(self.filename, self.message)
