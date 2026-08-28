import fnmatch
import logging
import os
from io import BytesIO, StringIO
from stat import S_ISDIR
from typing import Optional

try:
    import paramiko
except ImportError:
    paramiko = None

from core.exceptions import (  # DownloadingError,
    MovingError,
    SSHPasswordRSAError,
    UploadingError,
)
from core.file import RemoteFile, RemoteFileSet
from remote import RemoteDriver

_logger = logging.getLogger(__name__)


class SFTP(RemoteDriver):
    """SFTP (SSH File Transfer Protocol) driver."""

    host: str
    port: int
    login: str
    password: Optional[str] = None
    rsa: Optional[bytes] = None
    response_timeout: int = 30
    _transport: Optional[paramiko.Transport] = None
    _sftp: Optional[paramiko.SFTPClient] = None

    def __init__(
        self,
        host: str,
        port: int,
        login: str,
        password: Optional[str] = None,
        rsa: Optional[bytes] = None,
        response_timeout: int = 30,
    ):
        """
        Initialize SFTP driver.

        :param host: Hostname or IP-address
        :param port: SSH-port (usually 22)
        :param login: SSH username
        :param password: Optional SSH password
        :param rsa: Optional SSH private key as bytes
        :param response_timeout: Connection timeout in seconds
        """
        _logger.debug('Init SFTP Driver')

        if not (password or rsa):
            raise SSHPasswordRSAError()

        super().__init__(
            host=host,
            port=port,
            login=login,
            password=password,
            rsa=rsa,
            response_timeout=response_timeout,
        )
        self._transport = None
        self._sftp = None

    def connect(self):
        """Establish SFTP connection and store transport for cleanup."""
        self.disconnect()

        rsa_key = None

        if self.rsa:
            try:
                rsa_object = StringIO(str(self.rsa, 'utf-8'))
                rsa_key = paramiko.RSAKey.from_private_key(rsa_object)
            except ValueError as e:
                _logger.error(f'Invalid RSA key: {str(e)}')
                raise ValueError(f'Invalid RSA key: {str(e)}')

        self._transport = paramiko.Transport((self.host, self.port))
        self._transport.set_log_channel(__name__)
        try:
            self._transport.connect(
                username=self.login,
                pkey=rsa_key,
                password=self.password,
                # timeout=self.response_timeout
            )
            self._sftp = paramiko.SFTPClient.from_transport(self._transport)
            self._sftp.chdir(self._sftp.normalize('.'))
            return self._sftp
        except Exception as e:
            self.disconnect()
            _logger.error(f'SFTP connection failed: {str(e)}')
            raise

    def disconnect(self):
        """Clean up SFTP and transport connections."""
        if self._sftp:
            try:
                self._sftp.close()
            except Exception as e:
                _logger.warning(f'Error closing SFTP client: {e}')
            finally:
                self._sftp = None
        if self._transport:
            try:
                self._transport.close()
            except Exception as e:
                _logger.warning(f'Error closing transport: {e}')
            finally:
                self._transport = None

    def _ensure_connection(self):
        """Ensure we have an active SFTP connection."""
        if not self._sftp or not self._transport or not self._transport.is_active():
            return self.connect()
        return self._sftp

    def search(self, **kwargs) -> RemoteFileSet:
        """Search for files without downloading content."""
        return self.download(unlink=False, download_content=False, **kwargs)

    def download(
        self, unlink: bool = False, download_content: bool = True, **kwargs
    ) -> RemoteFileSet:
        """Download files from SFTP server."""
        sftp = self._ensure_connection()
        fileset = RemoteFileSet()

        try:
            path_mask = self.path or '.'

            for entry in sftp.listdir_attr(path_mask):
                mode = entry.st_mode
                if S_ISDIR(mode):
                    continue

                file_name = entry.filename
                _logger.debug(f'Listed file {file_name}')

                if fnmatch.fnmatch(file_name, self.mask or '*'):
                    _logger.debug(f'File {file_name} matches mask {self.mask}')
                    try:
                        file_path = os.path.join(path_mask, file_name)
                        _logger.debug(f'Processing file path: {file_path}')

                        file_content = b''
                        if download_content:
                            file = BytesIO()
                            sftp.getfo(remotepath=file_path, fl=file)
                            file_content = file.getvalue()

                        remote_file = RemoteFile(
                            name=file_name,
                            content=file_content,
                            size=entry.st_size or 0,
                        )
                        fileset.add(remote_file)

                        if unlink:
                            sftp.unlink(file_path)
                            _logger.debug(f'Deleted file {file_path}')

                    except IOError as eio:
                        _logger.warning(f'IOError for file {file_name}: {str(eio)}')
                        continue
                    except Exception as e:
                        _logger.error(f'Error processing file {file_name}: {str(e)}')
                        continue

        except Exception as e:
            _logger.error(f'Error during download: {str(e)}')
            raise

        return fileset

    def upload(self, **kwargs) -> 'RemoteDriver':
        """Upload files to SFTP server."""
        if not self.files:
            _logger.warning('No files to upload')
            return self

        sftp = self._ensure_connection()

        try:
            for file in self.files:
                if not isinstance(file, RemoteFile):
                    _logger.warning(f'Skipping non-RemoteFile object: {type(file)}')
                    continue

                file_path = os.path.join(self.path or '.', file.name)

                try:
                    file_obj = BytesIO(file.content)
                    result = sftp.putfo(fl=file_obj, remotepath=file_path, confirm=True)
                    _logger.debug(f'Uploaded {file_path}, size: {result.st_size}')

                except Exception as e:
                    _logger.error(f'Error uploading file {file.name}: {str(e)}')
                    raise UploadingError(file.name, str(e))

        except Exception as e:
            _logger.error(f'Error during upload: {str(e)}')
            raise

        return self

    def move(self, destination: str, **kwargs) -> 'RemoteDriver':
        """Move files to a new location on SFTP server."""
        if not self.files:
            _logger.warning('No files to move')
            return self

        sftp = self._ensure_connection()

        try:
            for file in self.files:
                if not isinstance(file, RemoteFile):
                    _logger.warning(f'Skipping non-RemoteFile object: {type(file)}')
                    continue

                source_path = os.path.join(self.path or '.', file.name)
                destination_path = os.path.join(destination, file.name)

                try:
                    sftp.rename(source_path, destination_path)
                    _logger.debug(
                        f'Moved file from {source_path} to {destination_path}'
                    )

                except Exception as e:
                    _logger.error(f'Error moving file {file.name}: {str(e)}')
                    raise MovingError(file.name, str(e))

        except Exception as e:
            _logger.error(f'Error during move: {str(e)}')
            raise

        # Update the path to the new location
        self.set_path(destination)
        return self

    def delete(self, **kwargs) -> 'RemoteDriver':
        """Delete files from SFTP server."""
        if not self.files:
            _logger.warning('No files to delete')
            return self

        sftp = self._ensure_connection()

        try:
            for file in self.files:
                if not isinstance(file, RemoteFile):
                    _logger.warning(f'Skipping non-RemoteFile object: {type(file)}')
                    continue

                file_path = os.path.join(self.path or '.', file.name)

                try:
                    sftp.unlink(file_path)
                    _logger.debug(f'Deleted file {file_path}')

                except Exception as e:
                    _logger.error(f'Error deleting file {file.name}: {str(e)}')
                    continue

        except Exception as e:
            _logger.error(f'Error during delete: {str(e)}')
            raise

        return self

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup."""
        self.disconnect()
