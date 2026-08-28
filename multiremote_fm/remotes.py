"""The frozen public remotes. Each one builds a backend and delegates."""

from .backends.local import LocalBackend
from .driver import RemoteDriver


class Local(RemoteDriver):
    """Local directory remote."""

    def __init__(self) -> None:
        super().__init__(backend=LocalBackend())
