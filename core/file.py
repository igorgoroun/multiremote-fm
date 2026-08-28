import mimetypes
from typing import Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .base import BaseDriver


class RemoteFile:
    """Represents a file from a remote source."""
    
    name: str
    path: Optional[str] = None
    content: Optional[bytes] = b''
    size: Optional[int] = 0

    _mimetype: Optional[str] = None

    def __init__(self, name: str, content: Optional[bytes] = b'', size: Optional[int] = 0):
        self.name = name
        self.content = content
        self.size = size
        self._mimetype = mimetypes.guess_type(self.name)[0] or 'application/octet-stream'
    
    @property
    def mimetype(self) -> str | None:
        return self._mimetype

    def __str__(self):
        return self.name

    def to_dict(self):
        """Convert to dictionary representation."""
        return dict(name=self.name, content=self.content, size=self.size, mimetype=self.mimetype)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.name})"

    def with_driver(self, driver: 'BaseDriver'):
        """Attach this file to a driver."""
        driver.set_files(RemoteFileSet(self))
        return driver


class RemoteFileSet:
    """A collection of RemoteFile objects."""

    __files: Set[RemoteFile]

    def __init__(self, *files: RemoteFile):
        self.__files = set()
        self.add(*files)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"{self.__class__.__name__}{tuple(self.files)}"

    def __iter__(self):
        return iter(self.files)

    def __len__(self):
        return len(self.__files)

    def __getitem__(self, item):
        return list(self.__files)[item]

    @property
    def files(self):
        return self.__files

    def add(self, *files: RemoteFile):
        """Add files to the set."""
        self.__files |= set(files)

    def with_driver(self, driver: 'BaseDriver'):
        """Attach this fileset to a driver."""
        driver.set_files(self)
        return driver
