"""FTP and FTPS backend.

FTP is the awkward protocol: NLST returns names with no sizes. That complexity lives
here, in list(), instead of leaking into the five operations.
"""

import ftplib
import logging
import posixpath
from io import BytesIO
from typing import List, Optional, cast

from .base import Backend, Stat

_logger = logging.getLogger(__name__)


class FtpBackend(Backend):
    """Primitives over a single reused ftplib connection."""

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
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.passive_mode = passive_mode
        self.response_timeout = response_timeout
        self.encoding = encoding
        self.tls = tls
        self._ftp: Optional[ftplib.FTP] = None

    def connect(self) -> None:
        if self._ftp is not None:
            return
        client = (
            ftplib.FTP_TLS(encoding=self.encoding)
            if self.tls
            else ftplib.FTP(encoding=self.encoding)
        )
        if not self.passive_mode:
            client.set_pasv(False)
        client.connect(host=self.host, port=self.port, timeout=self.response_timeout)
        client.login(user=self.login, passwd=self.password)
        if self.tls:
            cast(ftplib.FTP_TLS, client).prot_p()
        self._ftp = client

    def close(self) -> None:
        if self._ftp is None:
            return
        try:
            self._ftp.close()
        except ftplib.all_errors:
            _logger.warning('Error closing FTP client')
        finally:
            self._ftp = None

    def _client(self) -> ftplib.FTP:
        self.connect()
        if self._ftp is None:
            raise ConnectionError('FTP client is not connected')
        return self._ftp

    def list(self, path: str) -> List[Stat]:
        client = self._client()
        base = path or '.'
        try:
            listing = list(client.mlsd(base, facts=['type', 'size']))
        except (ftplib.error_perm, ftplib.error_proto):
            _logger.debug('MLSD unsupported on %s, falling back to NLST', self.host)
            return self._list_nlst(client, base)
        entries: List[Stat] = []
        for name, facts in listing:
            if name in ('.', '..'):
                continue
            entry_type = facts.get('type', 'file')
            if entry_type in ('dir', 'cdir', 'pdir'):
                entries.append(Stat(name=name, size=0, is_dir=True))
                continue
            entries.append(
                Stat(name=name, size=int(facts.get('size') or 0), is_dir=False)
            )
        return entries

    def _list_nlst(self, client: ftplib.FTP, base: str) -> List[Stat]:
        entries: List[Stat] = []
        for raw in client.nlst(base):
            name = posixpath.basename(raw) or raw
            if name in ('.', '..'):
                continue
            full = raw if '/' in raw else posixpath.join(base, name)
            try:
                size = client.size(full)
            except ftplib.all_errors:
                size = None
            entries.append(Stat(name=name, size=size or 0, is_dir=size is None))
        return entries

    def read(self, path: str) -> bytes:
        client = self._client()
        buffer = BytesIO()
        client.retrbinary(f'RETR {path}', buffer.write, blocksize=32768)
        return buffer.getvalue()

    def write(self, path: str, data: bytes) -> None:
        client = self._client()
        client.storbinary(f'STOR {path}', BytesIO(data))

    def rename(self, src: str, dst: str) -> None:
        self._client().rename(src, dst)

    def remove(self, path: str) -> None:
        self._client().delete(path)
