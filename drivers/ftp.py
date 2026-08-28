import logging
import ftplib
import os
from io import BytesIO
from typing import Optional

from core.file import RemoteFile, RemoteFileSet
from remote import RemoteDriver

_logger = logging.getLogger(__name__)


class FTP(RemoteDriver):

    host: str
    port: int
    login: str
    password: str
    tls: bool = False
    response_timeout: int = 30
    passive_mode: bool = True
    encoding: str = 'utf-8'
    _ftp: Optional[ftplib.FTP] = None

    def __init__(self, host: str, port: int, login: str, password: str, passive_mode: bool = True, response_timeout: int = 30, encoding: str = 'utf-8', tls: bool = False):
        """
        :param host: Hostname or IP-address
        :param port: FTP-port
        :type port int
        :param response_timeout: In seconds
        :type response_timeout int
        :param login: FTP username
        :param password: FTP password
        :param passive_mode: Force using passive mode for ftp connection
        :param encoding: Force using passive mode for ftp connection
        :param tls: Use TLS/SSL (make it FTPS)
        :type tls bool
        """
        _logger.debug("Init FTP")
        super().__init__(host=host, port=port, login=login, password=password, passive_mode=passive_mode, response_timeout=response_timeout, encoding=encoding, tls=tls)

    def connect(self):
        self.disconnect()

        if self.tls:
            fc = ftplib.FTP_TLS()
        else:
            fc = ftplib.FTP()
        if not self.passive_mode:
            fc.set_pasv(False)
        fc_port = self.port if self.port is not None else ftplib.FTP_PORT
        fc.connect(host=self.host, port=fc_port, timeout=self.response_timeout)
        fc.login(user=self.login, passwd=self.password)
        if self.tls:
            fc.prot_p()
        return fc

    def disconnect(self):
        if self._ftp:
            try:
                self._ftp.close()
            except ftplib.all_errors:
                _logger.warning("Error closing FTP client")
            finally:
                self._ftp = None

    def _ensure_connection(self):
        """Ensure we have an active FTP connection."""
        if not self._ftp:
            return self.connect()
        return self._ftp

    def search(self, **kwargs) -> RemoteFileSet:
        return self.download(unlink=False, download_content=False, **kwargs)

    def download(self, unlink: bool = False, download_content: bool = True, **kwargs) -> RemoteFileSet:
        fc = self.connect()
        path_mask = str(os.path.join(self.path, self.mask))
        fileset = RemoteFileSet()
        for file_path in fc.nlst(path_mask):
            head, tail = os.path.split(file_path)
            # checkt the NLST command returns just file names
            if not head:
                file_path = os.path.join(self.path, file_path)
            file = BytesIO()
            if download_content:
                fc.retrbinary(f"RETR {file_path}", file.write, blocksize=32768)
            fileset.add(RemoteFile(
                content=file.getvalue(),
                name=tail,
                size=fc.size(file_path) or 0,
            ))
            if unlink:
                fc.delete(file_path)
        fc.close()
        return fileset

    def upload(self, **kwargs) -> 'RemoteDriver':
        assert self.files
        fc = self.connect()
        for file in self.files:
            assert isinstance(file, RemoteFile)
            file_path = os.path.join(self.path, file.name)
            fc.storbinary(f'STOR {file_path}', BytesIO(file.content))
        fc.close()
        return self

    def move(self, destination: str, **kwargs) -> 'RemoteDriver':
        assert self.files
        fc = self.connect()
        for file in self.files:
            assert isinstance(file, RemoteFile)
            source_path = os.path.join(self.path, file.name)
            destination_path = os.path.join(destination, file.name)
            fc.rename(source_path, destination_path)
        fc.close()
        self.set_path(destination)
        return self

    def delete(self, **kwargs) -> 'RemoteDriver':
        assert self.files
        fc = self.connect()
        for file in self.files:
            assert isinstance(file, RemoteFile)
            source_path = os.path.join(self.path, file.name)
            fc.delete(source_path)
        fc.close()
        return self


class FTPS(FTP):
    def __init__(self, host: str, port: int, login: str, password: str, passive_mode: bool = True, response_timeout: int = 30, encoding: str = 'utf-8'):
        super().__init__(host=host, port=port, login=login, password=password, passive_mode=passive_mode, response_timeout=response_timeout, encoding=encoding, tls=True)
