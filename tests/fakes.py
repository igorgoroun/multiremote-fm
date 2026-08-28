"""In-memory Backend double, so every operation is testable without a network."""

from typing import Dict, List, Optional, Set

from multiremote_fm.backends import Backend, Stat


class FakeBackend(Backend):
    """A flat path -> content map that behaves like a directory tree."""

    def __init__(self, tree: Optional[Dict[str, bytes]] = None) -> None:
        self.tree: Dict[str, bytes] = dict(tree or {})
        self.dirs: Set[str] = set()
        self.connect_calls = 0
        self.close_calls = 0

    @staticmethod
    def _prefix(path: str) -> str:
        if path in ('', '.'):
            return ''
        return path.rstrip('/') + '/'

    def connect(self) -> None:
        self.connect_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    def list(self, path: str) -> List[Stat]:
        prefix = self._prefix(path)
        entries: List[Stat] = []
        for full, data in self.tree.items():
            if not full.startswith(prefix):
                continue
            rest = full[len(prefix):]
            if not rest or '/' in rest:
                continue
            entries.append(Stat(name=rest, size=len(data), is_dir=False))
        for directory in self.dirs:
            if not directory.startswith(prefix):
                continue
            rest = directory[len(prefix):]
            if not rest or '/' in rest:
                continue
            entries.append(Stat(name=rest, size=0, is_dir=True))
        return entries

    def read(self, path: str) -> bytes:
        return self.tree[path]

    def write(self, path: str, data: bytes) -> None:
        self.tree[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.tree[dst] = self.tree.pop(src)

    def remove(self, path: str) -> None:
        del self.tree[path]
