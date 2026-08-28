"""The frozen public remotes. Each one builds a backend and delegates."""

from .backends.ftp import FtpBackend
from .backends.local import LocalBackend
from .driver import RemoteDriver


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
