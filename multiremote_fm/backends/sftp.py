"""SFTP backend.

`from __future__ import annotations` is load-bearing: it stops every paramiko
annotation below from being evaluated at import time, so this module is importable
without paramiko installed and the failure happens at construction, with a message
that says what to do.
"""

from __future__ import annotations

import logging
import socket
from io import BytesIO, StringIO
from stat import S_ISDIR
from typing import List, Optional

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised with paramiko patched to None
    paramiko = None  # type: ignore[assignment]

from .base import Backend, Stat

_logger = logging.getLogger(__name__)

_MISSING_PARAMIKO = 'SFTP support requires paramiko: pip install multiremote-fm[sftp]'


class SftpBackend(Backend):
    """Primitives over a single reused paramiko SFTP channel."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        login: str = '',
        password: Optional[str] = None,
        rsa: Optional[bytes] = None,
        response_timeout: int = 30,
    ) -> None:
        if paramiko is None:
            raise ImportError(_MISSING_PARAMIKO)
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.rsa = rsa
        self.response_timeout = response_timeout
        self._transport: Optional[paramiko.Transport] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def _load_key(self) -> Optional[paramiko.RSAKey]:
        if not self.rsa:
            return None
        try:
            return paramiko.RSAKey.from_private_key(StringIO(self.rsa.decode('utf-8')))
        except ValueError as exc:
            raise ValueError('Invalid RSA key: {0}'.format(exc)) from exc

    def connect(self) -> None:
        if self._sftp is not None and self._transport is not None and self._transport.is_active():
            return
        self.close()
        rsa_key = self._load_key()
        # paramiko 5.0.0's Transport.connect takes no timeout, so response_timeout is
        # applied to the TCP connect and to the banner/auth phases instead.
        sock = socket.create_connection((self.host, self.port), timeout=self.response_timeout)
        sock.settimeout(None)
        transport = paramiko.Transport(sock)
        transport.set_log_channel(__name__)
        transport.banner_timeout = self.response_timeout
        transport.auth_timeout = self.response_timeout
        self._transport = transport
        try:
            transport.connect(username=self.login, pkey=rsa_key, password=self.password)
            client = paramiko.SFTPClient.from_transport(transport)
            if client is None:
                raise ConnectionError('Failed to open an SFTP channel')
            self._sftp = client
        except Exception as exc:
            _logger.error('SFTP connection failed: %s', exc)
            self.close()
            raise

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception as exc:
                _logger.warning('Error closing SFTP client: %s', exc)
            finally:
                self._sftp = None
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception as exc:
                _logger.warning('Error closing transport: %s', exc)
            finally:
                self._transport = None

    def _client(self) -> paramiko.SFTPClient:
        self.connect()
        if self._sftp is None:
            raise ConnectionError('SFTP client is not connected')
        return self._sftp

    def list(self, path: str) -> List[Stat]:
        client = self._client()
        entries: List[Stat] = []
        for entry in client.listdir_attr(path or '.'):
            entries.append(
                Stat(
                    name=entry.filename,
                    size=entry.st_size or 0,
                    is_dir=S_ISDIR(entry.st_mode or 0),
                )
            )
        return entries

    def read(self, path: str) -> bytes:
        client = self._client()
        buffer = BytesIO()
        client.getfo(remotepath=path, fl=buffer)
        return buffer.getvalue()

    def write(self, path: str, data: bytes) -> None:
        client = self._client()
        client.putfo(fl=BytesIO(data), remotepath=path, confirm=True)

    def rename(self, src: str, dst: str) -> None:
        self._client().rename(src, dst)

    def remove(self, path: str) -> None:
        self._client().unlink(path)
