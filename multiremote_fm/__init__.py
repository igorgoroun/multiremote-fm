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
from .remotes import FTP, FTPS, SFTP, Local

__version__ = '0.2.0'

__all__ = [
    'FTP',
    'FTPS',
    'SFTP',
    'BaseDriver',
    'DownloadingError',
    'Local',
    'MovingError',
    'NothingToUploadException',
    'RemoteDriver',
    'RemoteFile',
    'RemoteFileSet',
    'SSHPasswordRSAError',
    'UploadingError',
]
