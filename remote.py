from abc import ABC
from typing import Optional

from core.base import BaseDriver
from core.file import RemoteFileSet


class RemoteDriver(BaseDriver):
    __files: RemoteFileSet
    __path: Optional[str]
    __mask: Optional[str]

    def __init__(self, *args, **kwargs):
        self.__files = RemoteFileSet()
        self.__mask = ''
        self.__path = ''
        for k, v in kwargs.items():
            # if hasattr(self, k):
            #     print(f"{k}={v}")
            setattr(self, k, v)

    @property
    def files(self):
        return self.__files

    def set_files(self, files: RemoteFileSet):
        self.__files = files

    @property
    def path(self):
        return self.__path

    def set_path(self, path: str):
        self.__path = path

    @property
    def mask(self):
        return self.__mask

    def with_files(self, files: RemoteFileSet) -> 'RemoteDriver':
        self.set_files(files)
        return self

    def with_path(self, path: str) -> 'RemoteDriver':
        self.set_path(path)
        return self

    def with_mask(self, mask: str) -> 'RemoteDriver':
        self.__mask = mask
        return self

    def __str__(self):
        return f"RemoteDriver({self.path}, {self.mask})"

    def __repr__(self):
        return f"RemoteDriver(path={self.path}, mask={self.mask})"
