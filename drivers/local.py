import logging
import glob
import os
from core.file import RemoteFile, RemoteFileSet
from remote import RemoteDriver

_logger = logging.getLogger(__name__)


class Local(RemoteDriver):

    def __init__(self, *args, **kwargs):
        _logger.debug("Init Local Driver")
        super().__init__(*args, **kwargs)

    def search(self, **kwargs) -> RemoteFileSet:
        return self.download(unlink=False, download_content=False, **kwargs)

    def download(self, unlink: bool = False, download_content: bool = True,  **kwargs) -> RemoteFileSet:
        path_mask = os.path.join(self.path, self.mask)
        fileset = RemoteFileSet()
        for file_path in glob.glob(pathname=path_mask):
            _logger.debug(f"Found local file {file_path}")
            try:
                assert os.path.isfile(file_path)
                _, tail = os.path.split(file_path)
                f_content = bytes()
                if download_content:
                    with open(file_path, mode='rb') as f:
                        f_content = f.read()
                fileset.add(RemoteFile(
                    content=f_content,
                    name=tail,
                    size=os.stat(file_path).st_size,
                ))
                if unlink:
                    _logger.debug(f"Deleting file {file_path}")
                    os.unlink(file_path)
            except AssertionError:
                _logger.debug(f"{file_path} is not a regular file, let's skip it")
                continue
            except Exception as e:
                _logger.warning("Exception while downloading file %s", file_path)
                raise e
        return fileset

    def upload(self, **kwargs) -> 'RemoteDriver':
        assert self.files
        for file in self.files:
            assert isinstance(file, RemoteFile)
            file_path = os.path.join(self.path, file.name)
            with open(file_path, mode='wb') as f:
                f.write(file.content)
        return self

    def move(self, destination: str, **kwargs) -> 'RemoteDriver':
        assert self.files
        for file in self.files:
            assert isinstance(file, RemoteFile)
            source_path = os.path.join(self.path, file.name)
            destination_path = os.path.join(destination, file.name)
            os.rename(source_path, destination_path)
        self.set_path(destination)
        return self

    def delete(self, **kwargs) -> 'RemoteDriver':
        assert self.files
        for file in self.files:
            assert isinstance(file, RemoteFile)
            source_path = os.path.join(self.path, file.name)
            os.unlink(source_path)
        return self
