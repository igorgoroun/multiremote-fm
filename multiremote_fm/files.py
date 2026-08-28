"""File value objects returned and accepted by every driver."""

import mimetypes
from typing import TYPE_CHECKING, Any, Dict, Iterator, Optional, Set

if TYPE_CHECKING:
    from .driver import BaseDriver


class RemoteFile:
    """Represents a file from a remote source."""

    def __init__(
        self,
        name: str,
        content: Optional[bytes] = b'',
        size: Optional[int] = 0,
    ) -> None:
        self.name = name
        self.content = content
        self.size = size
        self._mimetype: Optional[str] = (
            mimetypes.guess_type(self.name)[0] or 'application/octet-stream'
        )

    @property
    def mimetype(self) -> Optional[str]:
        return self._mimetype

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return dict(
            name=self.name,
            content=self.content,
            size=self.size,
            mimetype=self.mimetype,
        )

    def with_driver(self, driver: 'BaseDriver') -> 'BaseDriver':
        """Return a copy of `driver` configured to work with this file."""
        return driver.with_files(RemoteFileSet(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RemoteFile):
            return NotImplemented
        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return '{0}({1})'.format(self.__class__.__name__, self.name)


class RemoteFileSet:
    """An insertion-ordered collection of RemoteFile objects, deduplicated by name."""

    def __init__(self, *files: RemoteFile) -> None:
        self.__files: Dict[str, RemoteFile] = {}
        self.add(*files)

    @property
    def files(self) -> Set[RemoteFile]:
        return set(self.__files.values())

    def add(self, *files: RemoteFile) -> None:
        """Add files to the set, replacing any earlier file of the same name.

        Validates every argument before mutating anything, so a failed call
        leaves the set unchanged.
        """
        for file in files:
            if not isinstance(file, RemoteFile):
                raise TypeError(
                    'RemoteFileSet accepts RemoteFile objects, got {0}'.format(type(file).__name__)
                )
        for file in files:
            self.__files[file.name] = file

    def with_driver(self, driver: 'BaseDriver') -> 'BaseDriver':
        """Return a copy of `driver` configured to work with this fileset."""
        return driver.with_files(self)

    def __iter__(self) -> Iterator[RemoteFile]:
        return iter(list(self.__files.values()))

    def __len__(self) -> int:
        return len(self.__files)

    def __getitem__(self, item: Any) -> Any:
        return list(self.__files.values())[item]

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return '{0}{1}'.format(self.__class__.__name__, tuple(self.__files.values()))
