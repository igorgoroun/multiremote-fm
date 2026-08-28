from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .file import RemoteFileSet


class BaseDriver(ABC):
    """Base abstract class for all remote drivers."""
    
    @abstractmethod
    def set_files(self, *args, **kwargs) -> None:
        """Set files for the driver to work with."""
        raise NotImplementedError()

    @abstractmethod
    def search(self, *args, **kwargs) -> 'RemoteFileSet':
        """Search for files matching criteria."""
        raise NotImplementedError()
    
    @abstractmethod
    def download(self, *args, **kwargs) -> 'RemoteFileSet':
        """Download files."""
        raise NotImplementedError()
    
    @abstractmethod
    def upload(self, *args, **kwargs) -> 'BaseDriver':
        """Upload files."""
        raise NotImplementedError()
    
    @abstractmethod
    def move(self, destination: str, **kwargs) -> 'BaseDriver':
        """Move files to destination."""
        raise NotImplementedError()
    
    @abstractmethod
    def delete(self, *args, **kwargs) -> 'BaseDriver':
        """Delete files."""
        raise NotImplementedError()

    @abstractmethod
    def with_path(self, path: str) -> 'BaseDriver':
        """Set the path for operations.
        
        :param path: Path to set
        :type path: str
        :rtype: BaseDriver
        """
        raise NotImplementedError()

    @abstractmethod
    def with_mask(self, mask: str) -> 'BaseDriver':
        """Set the file mask for filtering.
        
        :param mask: File mask pattern
        :type mask: str
        :rtype: BaseDriver
        """
        raise NotImplementedError()
