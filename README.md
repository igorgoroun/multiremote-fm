# Multi-Remote File Manager

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern Python library for seamless file manipulation across multiple remote locations with a unified API.

## Features

- **Unified API** - Single interface for all remote types
- **Multiple Protocols** - Support for Local, FTP, FTPS, SFTP
- **File Operations** - Search, download, upload, move, delete
- **Batch Processing** - Handle multiple files efficiently
- **Flexible Filtering** - File masks and path-based filtering
- **Type Safe** - Full type hints support

## Supported Remotes

| Protocol | Status | Description |
|----------|--------|--------------|
| Local Directory | ✅ Supported | Local filesystem operations |
| FTP | ✅ Supported | Standard FTP protocol |
| FTPS | ✅ Supported | FTP over SSL/TLS |
| SFTP | ✅ Supported | SSH File Transfer Protocol |
| REST API | 🔄 Planned | HTTP-based file operations |
| Amazon S3 | 🔄 Planned | AWS S3 storage |
| Dropbox | 🔄 Planned | Dropbox cloud storage |

## Installation

```bash
pip install multiremote-fm
```

### Development Installation

```bash
git clone https://github.com/igorgoroun/multiremote-fm
cd multiremote-fm
python -m venv venv
venv/bin/pip install -e ".[dev]"
venv/bin/pytest tests/ -v
```

The published version is stamped by CI, which rewrites the `version = ` line in
`pyproject.toml` from the release tag before building.

## Quick Start

### Basic Usage

```python
from multiremote_fm import Local, FTP, RemoteFile

# Initialize drivers
local = Local()
ftp = FTP(host='ftp.example.com', port=21, login='user', password='pass')

# Search for files
files = local.with_path('/home/user/documents').with_mask('*.pdf').search()
print(f"Found {len(files)} PDF files")

# Download files with content
files = local.with_path('/home/user/documents').with_mask('*.txt').download()
for file in files:
    print(f"File: {file.name}, Size: {file.size}, Type: {file.mimetype}")

# Get file list without loading content into memory
files = local.with_path('/home/user/documents').with_mask('*.txt').download(download_content=False)
```

### Working with Multiple Remotes

```python
from multiremote_fm import Local, FTP

# Get files from FTP
ftp = FTP(host='source.example.com', port=21, login='user', password='pass')
remote_files = ftp.with_path('/incoming').with_mask('*.xml').download()

# Process and upload to local
local = Local()
local.with_path('/processed').with_files(remote_files).upload()

# Clean up source (move processed files)
ftp.with_files(remote_files).move('/archive')
```

### Advanced File Operations

```python
from multiremote_fm import Local, RemoteFile, RemoteFileSet

# Create files programmatically
file1 = RemoteFile(name='data.txt', content=b'Hello World', size=11)
file2 = RemoteFile(name='config.json', content=b'{"key": "value"}', size=16)

fileset = RemoteFileSet(file1, file2)

# Upload to multiple destinations
local = Local()
local.with_path('/backup').with_files(fileset).upload()

# Chain operations
files = (local
    .with_path('/source')
    .with_mask('*.log')
    .download(unlink=True)  # Download and delete source
)

processed_files = process_logs(files)  # Your processing function

(local
    .with_path('/archive')
    .with_files(processed_files)
    .upload()
)
```

## API Reference

### Core Classes

#### RemoteFile

Represents a single file from any remote source.

```python
file = RemoteFile(name='document.pdf', content=b'...', size=1024)

# Properties
print(file.name)      # 'document.pdf'
print(file.size)      # 1024
print(file.mimetype)  # 'application/pdf'
print(file.content)   # b'...'

# Convert to dict
data = file.to_dict()
```

#### RemoteFileSet

A collection of RemoteFile objects with set-like operations.

```python
fileset = RemoteFileSet(file1, file2)

# Iterate
for file in fileset:
    print(file.name)

# Access by index
first_file = fileset[0]

# Get count
count = len(fileset)

# Add more files
fileset.add(file3, file4)
```

### Driver Classes

#### Local Driver

```python
local = Local()

# Chain methods for fluent API
files = (local
    .with_path('/home/user/documents')
    .with_mask('*.pdf')
    .search()
)
```

#### FTP Driver

```python
ftp = FTP(
    host='ftp.example.com',
    port=21,
    login='username',
    password='password',
    passive_mode=True,      # Default: True
    response_timeout=30,    # Default: 30
    encoding='utf-8'        # Default: 'utf-8'
)
```

#### FTPS Driver (FTP over SSL/TLS)

```python
ftps = FTPS(
    host='ftps.example.com',
    port=21,
    login='username',
    password='password'
)
# Inherits all FTP functionality with TLS encryption
```

#### SFTP Driver (SSH File Transfer Protocol)

```python
# With password authentication
sftp = SFTP(
    host='sftp.example.com',
    port=22,                    # Default: 22
    login='username',
    password='password',
    response_timeout=30         # Default: 30
)

# With RSA key authentication
with open('/path/to/private_key', 'rb') as f:
    rsa_key = f.read()

sftp = SFTP(
    host='sftp.example.com',
    port=22,
    login='username',
    rsa=rsa_key,
    response_timeout=30
)

# Note: Requires the optional 'sftp' extra
# Install with: pip install multiremote-fm[sftp]
```

### Common Methods

All drivers support these methods:

| Method | Description | Returns |
|--------|-------------|----------|
| `search(**kwargs)` | Find files without downloading content | `RemoteFileSet` |
| `download(unlink=False, download_content=True)` | Download files with optional deletion | `RemoteFileSet` |
| `upload(**kwargs)` | Upload files to remote | `Driver` |
| `move(destination, **kwargs)` | Move files to new location | `Driver` |
| `delete(**kwargs)` | Delete files | `Driver` |
| `with_path(path)` | Set working directory | `Driver` |
| `with_mask(mask)` | Set file filter mask | `Driver` |
| `with_files(fileset)` | Set files to work with | `Driver` |

## Use Cases

### ETL Pipelines

```python
# Extract from FTP, Transform, Load to local
ftp = FTP(host='data-source.com', port=21, login='etl', password='pass')
source_files = ftp.with_path('/daily-exports').with_mask('*.csv').download()

# Transform data
transformed = transform_csv_data(source_files)

# Load to local storage
local = Local()
local.with_path('/data-warehouse').with_files(transformed).upload()

# Cleanup source
ftp.with_files(source_files).move('/processed')
```

### File Synchronization

```python
# Sync between two FTP servers
source = FTP(host='source.com', port=21, login='user1', password='pass1')
target = FTP(host='target.com', port=21, login='user2', password='pass2')

# Get new files from source
new_files = source.with_path('/incoming').search()

# Upload to target
target.with_path('/received').with_files(new_files).upload()

# Archive on source
source.with_files(new_files).move('/archived')
```

### Batch Processing

```python
# Process multiple file types
local = Local()

# Process images
images = local.with_path('/uploads').with_mask('*.jpg').download()
resized_images = resize_images(images)
local.with_path('/thumbnails').with_files(resized_images).upload()

# Process documents
docs = local.with_path('/uploads').with_mask('*.pdf').download(unlink=True)
processed_docs = extract_text(docs)
local.with_path('/processed').with_files(processed_docs).upload()
```

## Testing

### Running Tests

```bash
# Set up test environment
export LOCAL_DIR_PATH=/tmp/multiremote-test
mkdir -p $LOCAL_DIR_PATH

# Run tests
python -m pytest tests/ -v
```

### Running Specific Tests

```bash
# Test local driver only
python -m pytest tests/test_local_dir.py -v

# Test file objects
python -m pytest tests/test_remote_files.py -v
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/igorgoroun/multiremote-fm
cd multiremote-fm
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v0.2.0 (Current)
- ✅ Real installable `multiremote_fm` package
- ✅ The five operations implemented once over a backend protocol
- ✅ Fluent methods are copy-on-write; no state leaks between chains
- ✅ `RemoteFileSet` deduplicates by file name
- ✅ SFTP moved to the optional `sftp` extra with an actionable ImportError
- ✅ Ships `py.typed`

### v0.1.0
- ✅ Initial release
- ✅ Local, FTP, FTPS, SFTP drivers
- ✅ Core file operations
- ✅ Fluent API design
- ✅ Type hints support

### Planned Features
- 🔄 REST API driver
- 🔄 AWS S3 driver
- 🔄 Async support
- 🔄 Progress callbacks
- 🔄 Connection pooling

## Support

- 📖 [Documentation](https://github.com/igorgoroun/multiremote-fm)
- 🐛 [Issue Tracker](https://github.com/igorgoroun/multiremote-fm/issues)
- 💬 [Discussions](https://github.com/igorgoroun/multiremote-fm/discussions)

---

**Made with ❤️ by [Ihor Horun](mailto:igor.goroun@gmail.com)**
