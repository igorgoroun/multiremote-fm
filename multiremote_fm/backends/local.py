"""Local filesystem backend."""

import os
from typing import List

from .base import Backend, Stat


class LocalBackend(Backend):
    """Primitives over the local filesystem."""

    def connect(self) -> None:
        """The local filesystem needs no connection."""

    def close(self) -> None:
        """The local filesystem needs no teardown."""

    def list(self, path: str) -> List[Stat]:
        entries: List[Stat] = []
        with os.scandir(path or '.') as scan:
            for entry in scan:
                if entry.is_dir():
                    entries.append(Stat(name=entry.name, size=0, is_dir=True))
                    continue
                if not entry.is_file():
                    continue
                entries.append(
                    Stat(name=entry.name, size=entry.stat().st_size, is_dir=False)
                )
        return entries

    def read(self, path: str) -> bytes:
        with open(path, mode='rb') as handle:
            return handle.read()

    def write(self, path: str, data: bytes) -> None:
        with open(path, mode='wb') as handle:
            handle.write(data)

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)

    def remove(self, path: str) -> None:
        os.unlink(path)
