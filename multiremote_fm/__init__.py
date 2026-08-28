"""Multi-remote file manager package."""

from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)

__version__ = '0.2.0'

__all__ = [
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
