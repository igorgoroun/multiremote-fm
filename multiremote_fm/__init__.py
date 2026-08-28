"""Multi-remote file manager package."""

from .driver import BaseDriver, RemoteDriver
from .exceptions import (
    DownloadingError,
    MovingError,
    NothingToUploadException,
    SSHPasswordRSAError,
    UploadingError,
)
from .files import RemoteFile, RemoteFileSet
from .remotes import Local

__version__ = '0.2.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'NothingToUploadException',
    'SSHPasswordRSAError',
    'DownloadingError',
    'UploadingError',
    'MovingError',
]
