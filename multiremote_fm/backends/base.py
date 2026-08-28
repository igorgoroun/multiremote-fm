"""The backend boundary: protocol primitives only.

A backend knows nothing about paths masks, filesets, `unlink`, or `download_content`.
Those belong to RemoteDriver, which implements the five operations once.
"""

from abc import ABC, abstractmethod
from typing import Iterable, NamedTuple


class Stat(NamedTuple):
    """One directory entry, protocol-independent."""

    name: str
    size: int
    is_dir: bool


class Backend(ABC):
    """Primitive operations every remote protocol must provide."""

    @abstractmethod
    def connect(self) -> None:
        """Open the connection if it is not already open. Idempotent."""
        raise NotImplementedError()

    @abstractmethod
    def close(self) -> None:
        """Close the connection if open. Idempotent."""
        raise NotImplementedError()

    @abstractmethod
    def list(self, path: str) -> Iterable[Stat]:
        """List the direct children of `path`."""
        raise NotImplementedError()

    @abstractmethod
    def read(self, path: str) -> bytes:
        """Return the full content of `path`."""
        raise NotImplementedError()

    @abstractmethod
    def write(self, path: str, data: bytes) -> None:
        """Write `data` to `path`, overwriting it."""
        raise NotImplementedError()

    @abstractmethod
    def rename(self, src: str, dst: str) -> None:
        """Rename `src` to `dst`."""
        raise NotImplementedError()

    @abstractmethod
    def remove(self, path: str) -> None:
        """Delete the file at `path`."""
        raise NotImplementedError()
