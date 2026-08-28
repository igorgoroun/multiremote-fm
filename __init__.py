"""Multi-remote file manager package."""

from core import BaseDriver, RemoteFile, RemoteFileSet
from drivers import FTP, FTPS, SFTP, Local
from remote import RemoteDriver

__version__ = '0.1.0'

__all__ = [
    'RemoteFile',
    'RemoteFileSet',
    'BaseDriver',
    'RemoteDriver',
    'Local',
    'FTP',
    'FTPS',
    'SFTP',
]


# class Client(object):
#     def __init__(self, driver, **kwargs):
#         pass
