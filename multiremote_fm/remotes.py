"""The frozen public remotes. Each one builds a backend and delegates."""

from types import TracebackType
from typing import Optional, Type

from .backends.ftp import FtpBackend
from .backends.local import LocalBackend
from .backends.sftp import SftpBackend
from .driver import RemoteDriver
from .exceptions import SSHPasswordRSAError


class Local(RemoteDriver):
    """Local directory remote."""

    def __init__(self) -> None:
        super().__init__(backend=LocalBackend())


class FTP(RemoteDriver):
    """Standard FTP remote."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
        tls: bool = False,
    ) -> None:
        super().__init__(
            backend=FtpBackend(
                host=host,
                port=port,
                login=login,
                password=password,
                passive_mode=passive_mode,
                response_timeout=response_timeout,
                encoding=encoding,
                tls=tls,
            )
        )


class FTPS(FTP):
    """FTP over SSL/TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: str,
        passive_mode: bool = True,
        response_timeout: int = 30,
        encoding: str = 'utf-8',
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            login=login,
            password=password,
            passive_mode=passive_mode,
            response_timeout=response_timeout,
            encoding=encoding,
            tls=True,
        )


class SFTP(RemoteDriver):
    """SSH File Transfer Protocol remote."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        login: str = '',
        password: Optional[str] = None,
        rsa: Optional[bytes] = None,
        response_timeout: int = 30,
    ) -> None:
        if not (password or rsa):
            raise SSHPasswordRSAError()
        super().__init__(
            backend=SftpBackend(
                host=host,
                port=port,
                login=login,
                password=password,
                rsa=rsa,
                response_timeout=response_timeout,
            )
        )

    def __enter__(self) -> 'SFTP':
        self.backend.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.backend.close()
