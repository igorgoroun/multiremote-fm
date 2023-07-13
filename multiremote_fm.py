import os
import mimetypes
import glob
import ftplib
import traceback
import paramiko
import fnmatch
import requests
import uuid
import logging
from typing import List
from urllib3.util import parse_url, Url
from urllib3.util.url import _NORMALIZABLE_SCHEMES
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth
from io import BytesIO, StringIO
from stat import S_ISDIR

_logger = logging.getLogger('RemoteConnection')


class NothingToUploadException(Exception):
    def __str__(self, *args, **kwargs):
        return "Nothing to upload"


class SSHPasswordRSAError(ValueError):
    def __str__(self, *args, **kwargs):
        return "One of the attributes `password` or `rsa` should be defined"


class DownloadingError(Exception):
    def __init__(self, filename, message):
        self.message = message
        self.filename = filename

    def __str__(self, *args, **kwargs):
        return f"Cannot download file {self.filename}: {self.message}"


class UploadingError(DownloadingError):
    def __str__(self, *args, **kwargs):
        return f"Cannot upload file {self.filename}: {self.message}"


class MovingError(DownloadingError):
    def __str__(self, *args, **kwargs):
        return f"Cannot move file {self.filename}: {self.message}"


class InvalidResponseCodeError(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self, *args, **kwargs):
        return f"Invalid response code {self.code} instead of 200"


class InvalidJSONResponseError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self, *args, **kwargs):
        return f'Response content is not a valid JSON string: {self.message}'


class FileObj(object):
    file_content: bytes = None
    file_name: str = None
    file_mimetype: str = None
    file_size: int = None

    def __init__(self, file_content: bytes, file_name: str, file_size: int = 0, file_mimetype: str = None):
        self.file_content = file_content
        self.file_name = file_name
        self.file_size = file_size
        self.file_mimetype = file_mimetype


class RemoteInterface(object):
    host: str = None
    port: int = 0
    path: str = ''
    mask: str = ''
    login: str = None
    password: str = None
    token: str = None
    tls: bool = False
    rsa: bytes = None
    domain: str = ''
    http_scheme: str = 'https'
    http_auth: str = 'token'
    http_verify_cert: bool = False
    request_type: str = 'get'
    request_data: dict = None
    ftp_passive_mode: bool = False
    connect_timeout: int = 10
    response_timeout: int = 30

    _http_request_url: Url = None
    _http_request_kwargs: dict = None
    _http_response: requests.Response = None

    _response: List[FileObj] = None
    _error: list = []

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
        self._response = []
        self._error = []

    @property
    def http_response(self):
        return self._http_response

    @property
    def http_request_url(self):
        return self._http_request_url

    @property
    def http_request_kwargs(self):
        return self._http_request_kwargs

    @property
    def response(self):
        return self._response

    @property
    def error(self):
        return self._error

    def connect(self):
        pass

    def test(self) -> bool:
        fc = self.connect()
        if fc:
            fc.close()
            return True
        return False

    def list(self, **kwargs):
        self._response = []
        assert self.path

    def download_single(self, **kwargs):
        self._response = []
        assert self.path

    def download(self, **kwargs):
        self._response = []
        assert self.path

    def upload(self, **kwargs):
        self._response = []
        assert self.path

    def move(self, destination=None, **kwargs):
        self._response = []
        assert self.path
        assert destination is not None

    def request(self):
        pass


class LocalDir(RemoteInterface):
    def __init__(self, path: str = '', mask: str = '*'):
        super().__init__(path=path, mask=mask)

    def list(self, **kwargs) -> RemoteInterface:
        super().list(**kwargs)
        path_pattern = os.path.join(self.path or '', self.mask or '')
        for file_path in glob.glob(pathname=path_pattern):
            try:
                assert os.path.isfile(file_path)
                _, tail = os.path.split(file_path)
                self.response.append(FileObj(
                    file_content=bytes(),
                    file_name=tail,
                    file_size=os.stat(file_path).st_size,
                    file_mimetype=mimetypes.guess_type(file_path)[0]
                ))
            except AssertionError:
                _logger.debug(f"{file_path} is not a regular file, let's skip it")
            except Exception as e:
                self.error.append(DownloadingError(file_path, str(e)))
                _logger.error(traceback.format_exc())
        return self

    def download(self, unlink: bool = False, **kwargs) -> RemoteInterface:
        super().download(unlink=unlink, **kwargs)
        path_pattern = os.path.join(self.path or '', self.mask or '')
        for file_path in glob.glob(pathname=path_pattern):
            try:
                assert os.path.isfile(file_path)
                with open(file_path, mode='rb') as f:
                    _, tail = os.path.split(file_path)
                    self.response.append(FileObj(
                        file_content=f.read(),
                        file_name=tail,
                        file_size=os.stat(file_path).st_size,
                        file_mimetype=mimetypes.guess_type(file_path)[0]
                    ))
                if unlink:
                    os.unlink(file_path)
            except AssertionError:
                _logger.debug(f"{file_path} is not a regular file, let's skip it")
            except Exception as e:
                self.error.append(DownloadingError(file_path, str(e)))
                _logger.error(traceback.format_exc())
        return self

    def download_single(self, unlink: bool = False, **kwargs):
        super().download_single(unlink=unlink, **kwargs)
        try:
            assert os.path.isfile(self.path)
            with open(self.path, mode='rb') as f:
                _, tail = os.path.split(self.path)
                self.response.append(FileObj(
                    file_content=f.read(),
                    file_name=tail,
                    file_size=os.stat(self.path).st_size,
                    file_mimetype=mimetypes.guess_type(self.path)[0]
                ))
            if unlink:
                os.unlink(self.path)
        except Exception as e:
            self.error.append(DownloadingError(self.path, str(e)))
            _logger.error(traceback.format_exc())
        return self

    def upload(self, files: List[FileObj], **kwargs) -> RemoteInterface:
        super().upload(files=files, **kwargs)
        for record in files:
            try:
                file_path = os.path.join(self.path, record.file_name)
                with open(file_path, mode='wb') as f:
                    f.write(record.file_content)
            except Exception as e:
                _logger.error(traceback.format_exc())
                self.error.append(UploadingError(record.file_name, str(e)))
        return self


class FTP(RemoteInterface):
    ftp_passive_mode: bool = False
    ftp_encoding: str = 'utf-8'

    def __init__(self, host, port, response_timeout, login, password, mask='', ftp_passive_mode=True, ftp_encoding='utf-8', tls=False):
        """
        :param host: Hostname or IP-address
        :param port: FTP-port
        :type port int
        :param response_timeout: In seconds
        :type response_timeout int
        :param login: FTP username
        :param password: FTP password
        :param mask: Filename mask: *.json, *_order_*.xml, etc..
        :param ftp_passive_mode: Force using passive mode for ftp connection
        :param ftp_encoding: Force using passive mode for ftp connection
        :param tls: Use TLS/SSL (make it FTPS)
        :type tls bool
        """
        _logger.debug("Start FTP connection")
        super().__init__(host=host, port=int(port), response_timeout=int(response_timeout), login=login, passw=password, mask=mask, ftp_passive_mode=ftp_passive_mode, ftp_encoding=ftp_encoding, tls=tls)

    def connect(self):
        if self.tls:
            _logger.debug("Using TLS (secure connection)")
            fc = ftplib.FTP_TLS()
        else:
            fc = ftplib.FTP()

        if not self.ftp_passive_mode:
            fc.set_pasv(False)
        fc.connect(host=self.host, port=self.port or ftplib.FTP_PORT, timeout=self.response_timeout)
        _logger.debug("Connected")
        fc.login(user=self.login, passwd=self.password)
        _logger.debug("Logged in")
        if self.tls:
            fc.prot_p()
        return fc

    def download_single(self, unlink=False, **kwargs) -> RemoteInterface:
        super().download_single(unlink=unlink, **kwargs)
        fc = self.connect()
        try:
            head, tail = os.path.split(self.path)
            file = BytesIO()
            fc.retrbinary(f"RETR {self.path}", file.write, blocksize=32)
            record = FileObj(
                file_content=file.getvalue(),
                file_name=tail,
                file_mimetype=mimetypes.guess_type(self.path)[0]
            )
            self._response.append(record)
            if unlink:
                fc.delete(self.path)
        except IOError:
            pass
        except Exception as e:
            _logger.error(traceback.format_exc())
            self.error.append(DownloadingError(self.path, str(e)))
            pass
        fc.close()
        return self

    def download(self, unlink=False, **kwargs) -> RemoteInterface:
        super().download(unlink=unlink, **kwargs)
        fc = self.connect()
        path_mask = os.path.join(self.path, self.mask)
        for file_path in fc.nlst(path_mask):
            try:
                head, tail = os.path.split(file_path)
                # check if nlst returns just file names
                if not head:
                    file_path = os.path.join(self.path, file_path)
                file = BytesIO()
                fc.retrbinary(f"RETR {file_path}", file.write, blocksize=32)
                record = FileObj(
                    file_content=file.getvalue(),
                    file_name=tail,
                    file_mimetype=mimetypes.guess_type(file_path)[0]
                )
                # self._response.append(record.__dict__)
                self._response.append(record)
                if unlink:
                    fc.delete(file_path)
            except IOError:
                pass
            except Exception as e:
                _logger.error(traceback.format_exc())
                # self.error.append(DownloadingError(file_path, str(e)))
                pass
        fc.close()
        return self

    def upload(self, files=None, **kwargs):
        super().upload(files=files)
        fc = self.connect()
        for record in files:
            try:
                assert type(record) == FileObj
                file_path = os.path.join(self.path, record.file_name)
                file = BytesIO(record.file_content)
                fc.storbinary(f'STOR {file_path}', file)
            except Exception as e:
                _logger.error(traceback.format_exc())
                self.error.append(UploadingError(record.file_name, str(e)))
                pass
        fc.close()
        return self

    def move(self, files=None, destination=None, **kwargs):
        super().move(destination=destination)
        fc = self.connect()
        for record in files:
            try:
                assert type(record) == FileObj
                file_path = os.path.join(self.path, record.file_name)
                destination_path = os.path.join(destination, record.file_name)
                fc.rename(file_path, destination_path)
            except Exception as e:
                _logger.error(traceback.format_exc())
                self.error.append(MovingError(record.file_name, str(e)))
                pass
        fc.close()
        return self


class FTPS(FTP):
    def __init__(self, host, port, response_timeout, login, password, mask='', ftp_passive_mode=True, ftp_encoding='utf-8'):
        """
        :param host: Hostname or IP-address
        :param port: FTP-port
        :type port int
        :param response_timeout: In seconds
        :type response_timeout int
        :param login: FTP username
        :param password: FTP password
        :param mask: Filename mask: *.json, *_order_*.xml, etc..
        :param ftp_passive_mode: Force using passive mode for ftp connection
        """
        super().__init__(host=host, port=port, response_timeout=response_timeout, login=login, password=password, mask=mask, ftp_passive_mode=ftp_passive_mode, ftp_encoding=ftp_encoding, tls=True)


class SFTP(RemoteInterface):
    def __init__(self, host, port, response_timeout, login, mask='*', password=None, rsa=None):
        """
        :param host: Hostname or IP-address
        :param port: SSH-port
        :type port int
        :param response_timeout: In seconds
        :type response_timeout int
        :param login: SSH username
        :param mask: Filename mask: *.json, *_order_*.xml, etc..
        :param password: Optional SSH password
        :param rsa: Optional SSH private key
        :type rsa bytearray
        """
        _logger.debug("Start SFTP connection")
        if not (password or rsa):
            raise SSHPasswordRSAError
        super().__init__(host=host, port=port, response_timeout=response_timeout, login=login, passw=password, mask=mask, rsa=rsa)

    def connect(self):
        rsa = None
        if self.rsa:
            try:
                rsa_object = StringIO(str(self.rsa, 'utf-8'))
                rsa = paramiko.RSAKey.from_private_key(rsa_object)
            except ValueError as e:
                self.error.append(f"Invalid RSA key: {str(e)}")
        transport = paramiko.Transport((self.host, self.port))
        transport.set_log_channel(__name__)
        transport.connect(username=self.login, pkey=rsa, password=self.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.chdir(sftp.normalize('.'))
        return sftp

    def upload(self, files=None, **kwargs):
        super().upload(files=files)
        sftp = self.connect()
        for record in files:
            try:
                assert type(record) == FileObj
                file_path = os.path.join(self.path, record.file_name)
                file = BytesIO(record.file_content)
                result = sftp.putfo(fl=file, remotepath=file_path, confirm=True)
                self.response.append(f"Uploaded {file_path}, size: {result.st_size}")
            except Exception as e:
                _logger.error(traceback.format_exc())
                self.error.append(UploadingError(record.file_name, str(e)))
                pass
        sftp.close()
        return self

    def move(self, files=None, destination=None, **kwargs):
        super().move(destination=destination)
        sftp = self.connect()
        for record in files:
            try:
                source_path = os.path.join(self.path, record.file_name)
                destination_path = os.path.join(destination, record.file_name)
                sftp.rename(source_path, destination_path)
            except Exception as e:
                _logger.error(traceback.format_exc())
                self.error.append(MovingError(record.file_name, str(e)))
                pass
        sftp.close()
        return self

    def download_single(self, unlink=False, **kwargs):
        super().download_single(unlink=unlink, **kwargs)
        sftp = self.connect()
        try:
            head, tail = os.path.split(self.path)
            file = BytesIO()
            sftp.getfo(remotepath=self.path, fl=file)
            record = FileObj(
                file_content=file.getvalue(),
                file_name=tail,
                file_mimetype=mimetypes.guess_type(self.path)[0]
            )
            # self._response.append(record.__dict__)
            self._response.append(record)
            if unlink:
                sftp.unlink(self.path)
        except IOError:
            pass
        except Exception as e:
            _logger.error(traceback.format_exc())
            self.error.append(DownloadingError(self.path, str(e)))
            pass
        sftp.close()
        return self

    def download(self, unlink=False, **kwargs):
        super().download(unlink=unlink, **kwargs)
        sftp = self.connect()
        path_mask = os.path.join(self.path)
        for entry in sftp.listdir_attr(path_mask):
            mode = entry.st_mode
            if S_ISDIR(mode):
                continue
            file_name = entry.filename
            _logger.info(f"Listed file {file_name}")
            if fnmatch.fnmatch(file_name, self.mask):
                _logger.info(f"Find file {file_name} in {self.mask}")
                try:
                    file_path = os.path.join(path_mask, file_name)
                    _logger.info(f"File path: {file_path}")
                    file = BytesIO()
                    sftp.getfo(remotepath=file_path, fl=file)
                    _, tail = os.path.split(file_path)
                    record = FileObj(
                        file_content=file.getvalue(),
                        file_name=tail,
                        file_mimetype=mimetypes.guess_type(file_path)[0]
                    )
                    self._response.append(record)
                    if unlink:
                        sftp.unlink(file_path)
                except IOError as eio:
                    _logger.warning(f'IOError for file {file_name}: {str(eio)}')
                    # self.error.append(DownloadingError(file_name, str(eio)))
                    pass
                except Exception as e:
                    _logger.warning(traceback.format_exc())
                    self.error.append(DownloadingError(file_name, str(e)))
                    pass
        sftp.close()
        return self


def get_remote_driver(remote):
    """
    Defining the driver to connect to remote
    :return: RemoteInterface object
    :rtype: RemoteInterface
    """
    credentials = {
        'host': remote.get('host'),
        'port': int(remote.get('port')),
        'response_timeout': 60,
        'login': remote.get('user'),
        'password': remote.get('password')
    }
    if remote.get('type') == 'ftp':
        driver = FTP(
            ftp_passive_mode=remote.get('passive_mode'),
            ftp_encoding=remote.get('encoding'),
            **credentials
        )
    elif remote.get('type') == 'ftps':
        driver = FTPS(
            ftp_passive_mode=remote.get('passive_mode'),
            ftp_encoding=remote.get('encoding'),
            **credentials
        )
    elif remote.get('type') == 'sftp':
        driver = SFTP(
            rsa=bytearray(remote.get('rsa'), 'utf-8') if remote.get('rsa', False) else False,
            **credentials
        )
    else:
        raise Exception("Incorrect connection type")
    return driver


class HTTP(RemoteInterface):

    def __init__(self, host, basepath, port=None, http_auth='token', login=None, password=None, token=None, rsa=None, domain=None, http_verify_cert=True):
        """
        :param host: Hostname or IP-address, i.e. https://api-host.com
        :param basepath: API basepath, i.e. /api/v1
        :param port: Custom port number
        :param http_auth: HTTP Auth type, ['none', 'basic', 'digest', 'token', 'aws', 'jwt', etc...], default: 'token'
        :param login: Username
        :param password: Password
        :param token: Token
        :param rsa: RSA-key
        :param domain: Unused yet
        :param http_verify_cert: True by default
        """
        super().__init__(host=host, port=port, basepath=basepath, http_scheme=None, http_auth=http_auth, login=login, passw=password, token=token, rsa=rsa, domain=domain, http_verify_cert=http_verify_cert)
        self.http_scheme, self.host, port = self.makehost(host)
        if self.http_scheme not in _NORMALIZABLE_SCHEMES:
            self.http_scheme = 'https'
        if port:
            self.port = port
        if self.http_auth in ['jwt']:
            self.auth()

    class AuthBearerToken(AuthBase):
        def __init__(self, token):
            self.token = token

        def __call__(self, r):
            r.headers.update({
                'Authorization': f"Bearer {self.token}"
            })
            return r

    def auth(self):
        if self.http_auth == 'token' and self.token:
            return self.AuthBearerToken(self.token)
        elif self.http_auth == 'basic' and self.login and self.password:
            return HTTPBasicAuth(username=self.login, password=self.password)
        elif self.http_auth == 'digest' and self.login and self.password:
            return HTTPDigestAuth(username=self.login, password=self.password)
        return None

    @staticmethod
    def makehost(host):
        h = parse_url(host)
        return h.scheme, h.host, h.port

    @staticmethod
    def makepath(*parts):
        parts_list = []
        for part in parts:
            if not part:
                continue
            parts_list.extend(list(filter(lambda p: p not in [None, False, ''], part.split('/'))))
        return '/'.join(parts_list)

    def request(self, path=None, request_type='get', request_query: dict = None, request_data: dict = None, request_json: dict = None, request_headers: dict = None, **kwargs):
        """
        Make an HTTP request
        :param path: URL endpoint, that comes after basepath, i.e. /entity/12
        :param request_type: Request method code [get, post, put, patch, delete, options]
        :param request_query: A dict of GET-request parameters
        :param request_data: A dict with raw data to be placed into request body
        :param request_json: A dict with data to be converted into JSON and place into request body
        :param request_headers: A dict with a list of custom HTTP request headers
        :param kwargs: Unused yet
        :return: self
        :rtype: HTTP
        """
        self._error = []
        self._http_request_url = Url(
            scheme=self.http_scheme,
            host=self.host,
            port=self.port,
            path=self.makepath(self.basepath, path)
        )
        _logger.debug(f"Url: {self._http_request_url}")
        self._http_request_kwargs = {
            'method': request_type,
            'url': self._http_request_url.url,
            'headers': request_headers,
            'auth': self.auth(),
            'params': request_query,
            'data': request_data,
            'json': request_json
        }
        _logger.debug(f"Request kwargs: {self._http_request_kwargs}")
        self._http_response = requests.api.request(**self._http_request_kwargs)
        if self.http_response.status_code != 200:
            self.error.append(InvalidResponseCodeError(code=self.http_response.status_code))
        try:
            record = FileObj(
                file_content=self.http_response.content,
                file_name=f'{uuid.uuid4()}',
                file_mimetype=self.http_response.headers.get('content-type', None)
            )
            self.response.append(record.__dict__)
        except Exception as e:
            _logger.error(traceback.format_exc())
            self.error.append(InvalidJSONResponseError(message=str(e)))
        return self

    download = request
    upload = request
