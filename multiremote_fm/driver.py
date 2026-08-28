"""The five file operations, implemented once over a Backend."""

import fnmatch
import logging
import posixpath
from abc import ABC, abstractmethod
from typing import Optional

from .backends.base import Backend
from .exceptions import NothingToUploadException
from .files import RemoteFile, RemoteFileSet

_logger = logging.getLogger(__name__)


def _join(base: str, name: str) -> str:
    """Join a remote directory and an entry name, treating '' and '.' as the root."""
    if base in ('', '.'):
        return name
    return posixpath.join(base, name)


class BaseDriver(ABC):
    """The frozen public surface every remote exposes."""

    @abstractmethod
    def search(self, **kwargs: object) -> RemoteFileSet:
        """Find files matching path and mask without downloading content."""
        raise NotImplementedError()

    @abstractmethod
    def download(
        self,
        unlink: bool = False,
        download_content: bool = True,
        **kwargs: object,
    ) -> RemoteFileSet:
        """Download files matching path and mask, optionally deleting the source."""
        raise NotImplementedError()

    @abstractmethod
    def upload(self, **kwargs: object) -> 'BaseDriver':
        """Upload the configured fileset into the configured path."""
        raise NotImplementedError()

    @abstractmethod
    def move(self, destination: str, **kwargs: object) -> 'BaseDriver':
        """Move the configured fileset to `destination`."""
        raise NotImplementedError()

    @abstractmethod
    def delete(self, **kwargs: object) -> 'BaseDriver':
        """Delete the configured fileset from the configured path."""
        raise NotImplementedError()

    @abstractmethod
    def with_path(self, path: str) -> 'BaseDriver':
        """Return a copy working in `path`."""
        raise NotImplementedError()

    @abstractmethod
    def with_mask(self, mask: str) -> 'BaseDriver':
        """Return a copy filtering by `mask`."""
        raise NotImplementedError()

    @abstractmethod
    def with_files(self, files: RemoteFileSet) -> 'BaseDriver':
        """Return a copy working with `files`."""
        raise NotImplementedError()


class RemoteDriver(BaseDriver):
    """Path, mask and fileset over a shared Backend. Copy-on-write."""

    def __init__(
        self,
        backend: Backend,
        path: str = '',
        mask: str = '*',
        files: Optional[RemoteFileSet] = None,
    ) -> None:
        self._backend = backend
        self._path = path
        self._mask = mask
        self._files = files if files is not None else RemoteFileSet()

    @property
    def backend(self) -> Backend:
        return self._backend

    @property
    def path(self) -> str:
        return self._path

    @property
    def mask(self) -> str:
        return self._mask

    @property
    def files(self) -> RemoteFileSet:
        return self._files

    def _copy(
        self,
        path: Optional[str] = None,
        mask: Optional[str] = None,
        files: Optional[RemoteFileSet] = None,
    ) -> 'RemoteDriver':
        """A new driver sharing this backend instance. Never clone the backend."""
        return RemoteDriver(
            backend=self._backend,
            path=self._path if path is None else path,
            mask=self._mask if mask is None else mask,
            files=self._files if files is None else files,
        )

    def with_path(self, path: str) -> 'RemoteDriver':
        return self._copy(path=path)

    def with_mask(self, mask: str) -> 'RemoteDriver':
        return self._copy(mask=mask)

    def with_files(self, files: RemoteFileSet) -> 'RemoteDriver':
        return self._copy(files=files)

    def _outgoing(self) -> RemoteFileSet:
        """The fileset for a write operation, validated."""
        if len(self._files) == 0:
            raise NothingToUploadException()
        for file in self._files:
            if not isinstance(file, RemoteFile):
                raise TypeError(
                    'Expected RemoteFile, got {0}'.format(type(file).__name__)
                )
        return self._files

    def search(self, **kwargs: object) -> RemoteFileSet:
        return self.download(unlink=False, download_content=False, **kwargs)

    def download(
        self,
        unlink: bool = False,
        download_content: bool = True,
        **kwargs: object,
    ) -> RemoteFileSet:
        self._backend.connect()
        base = self._path or '.'
        mask = self._mask or '*'
        fileset = RemoteFileSet()
        for entry in self._backend.list(base):
            if entry.is_dir:
                _logger.debug('Skipping directory %s', entry.name)
                continue
            if not fnmatch.fnmatch(entry.name, mask):
                continue
            full_path = _join(self._path, entry.name)
            content = self._backend.read(full_path) if download_content else b''
            fileset.add(RemoteFile(name=entry.name, content=content, size=entry.size))
            if unlink:
                _logger.debug('Deleting %s', full_path)
                self._backend.remove(full_path)
        return fileset

    def upload(self, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.write(_join(self._path, file.name), file.content or b'')
        return self

    def move(self, destination: str, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.rename(
                _join(self._path, file.name),
                _join(destination, file.name),
            )
        return self._copy(path=destination)

    def delete(self, **kwargs: object) -> 'RemoteDriver':
        files = self._outgoing()
        self._backend.connect()
        for file in files:
            self._backend.remove(_join(self._path, file.name))
        return self

    def __str__(self) -> str:
        return 'RemoteDriver({0}, {1})'.format(self._path, self._mask)

    def __repr__(self) -> str:
        return 'RemoteDriver(path={0}, mask={1})'.format(self._path, self._mask)
