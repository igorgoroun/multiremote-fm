
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
