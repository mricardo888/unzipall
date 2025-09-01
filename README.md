# UnzipAll - Universal Archive Extractor

[![PyPI version](https://badge.fury.io/py/unzipall.svg)](https://badge.fury.io/py/unzipall)
[![Python versions](https://img.shields.io/pypi/pyversions/unzipall.svg)](https://pypi.org/project/unzipall/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Coverage](https://codecov.io/gh/mricardo/unzipall/branch/main/graph/badge.svg)](https://codecov.io/gh/mricardo/unzipall)

A comprehensive Python library for extracting archive files in **30+ formats** with a simple, unified API. No more juggling multiple extraction libraries or dealing with format-specific quirks.

## ✨ Features

- **🗃️ Universal Format Support**: ZIP, RAR, 7Z, TAR (all variants), ISO, MSI, and 25+ more formats
- **🛡️ Security First**: Built-in protection against path traversal attacks (zip bombs)
- **🔐 Password Support**: Handle encrypted archives seamlessly
- **⚡ Simple API**: One function call to extract any supported archive
- **🔧 CLI Tool**: Extract archives from command line with `unzipall` command
- **🌍 Cross-Platform**: Works on Windows, macOS, and Linux
- **🏗️ Type Safe**: Full type hints for better IDE support and development experience
- **📊 Graceful Degradation**: Optional dependencies - missing libraries don't break functionality

## 🚀 Quick Start

### Installation

```bash
pip install unzipall
```

### Basic Usage

```python
import unzipall

# Extract any archive format - it just works!
unzipall.extract('archive.zip')
unzipall.extract('data.tar.gz', 'output_folder')
unzipall.extract('encrypted.7z', password='secret')

# Check if format is supported
if unzipall.is_supported('mystery_file.xyz'):
    unzipall.extract('mystery_file.xyz')

# List all supported formats  
formats = unzipall.list_supported_formats()
print(f"Supports {len(formats)} formats!")
```

### Command Line Usage

```bash
# Extract to current directory
unzipall archive.zip

# Extract to specific directory
unzipall archive.tar.gz /path/to/output

# Extract password-protected archive
unzipall -p mypassword encrypted.7z

# List supported formats
unzipall --list-formats

# Verbose output
unzipall -v archive.rar output_dir
```

## 📁 Supported Formats

| Category | Formats | Status |
|----------|---------|--------|
| **ZIP Family** | `.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.epub`, `.cbz` | ✅ Built-in |
| **RAR Family** | `.rar`, `.cbr` | ✅ Full Support |
| **7-Zip** | `.7z`, `.cb7` | ✅ Full Support |
| **TAR Archives** | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.z`, `.tar.lzma` | ✅ Built-in |
| **Compression** | `.gz`, `.bz2`, `.xz`, `.lzma`, `.z` | ✅ Built-in |
| **Other Archives** | `.arj`, `.cab`, `.chm`, `.cpio`, `.deb`, `.rpm`, `.lzh`, `.lha` | ✅ Via patool |
| **Disk Images** | `.iso`, `.vhd`, `.udf` | ✅ Full Support |
| **Microsoft** | `.msi`, `.exe` (self-extracting), `.wim` | ✅ Platform-aware |
| **Specialized** | `.xar`, `.zpaq`, `.cso`, `.pkg`, `.cbt` | ✅ Via patool |

> **30+ formats supported!** If a format isn't working, it may require additional system tools (see [System Dependencies](#-system-dependencies)).

## 🛠 Advanced Usage

### Programmatic API

```python
from unzipall import ArchiveExtractor, ArchiveExtractionError

# Create extractor with custom settings
extractor = ArchiveExtractor(verbose=True)

# Check available features
features = extractor.get_available_features()
for feature, available in features.items():
    status = "✅" if available else "❌"
    print(f"{status} {feature}")

# Extract with error handling
try:
    success = extractor.extract(
        archive_path='large_archive.rar',
        extract_to='output_directory',
        password='optional_password'
    )
    if success:
        print("Extraction completed successfully!")
        
except ArchiveExtractionError as e:
    print(f"Extraction failed: {e}")
```

### Error Handling

UnzipAll provides specific exceptions for different failure scenarios:

```python
from unzipall import (
    ArchiveExtractionError, UnsupportedFormatError, 
    CorruptedArchiveError, PasswordRequiredError,
    InvalidPasswordError, ExtractionPermissionError, 
    DiskSpaceError
)

try:
    unzipall.extract('archive.zip')
except UnsupportedFormatError:
    print("This archive format is not supported")
except PasswordRequiredError:
    password = input("Enter password: ")
    unzipall.extract('archive.zip', password=password)
except CorruptedArchiveError:
    print("Archive file is corrupted")
except DiskSpaceError:
    print("Not enough disk space")
except ArchiveExtractionError as e:
    print(f"Extraction failed: {e}")
```

### Security Features

UnzipAll automatically protects against common archive-based attacks:

```python
# Path traversal protection (zip bombs)
# Malicious archives with paths like "../../etc/passwd" are safely handled
unzipall.extract('potentially_malicious.zip', 'safe_output_dir')

# Files are extracted only within the target directory
# Dangerous paths are logged and skipped
```

## 🔧 System Dependencies

While UnzipAll works out of the box for common formats (ZIP, TAR, GZIP, etc.), some formats require additional system tools:

### Windows
```bash
# Install via Windows Package Manager
winget install 7zip.7zip
winget install RARLab.WinRAR

# Or install via Chocolatey
choco install 7zip winrar
```

### macOS
```bash
# Using Homebrew
brew install p7zip unrar

# For additional formats
brew install cabextract unshield
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install p7zip-full unrar-free

# For additional formats
sudo apt install cabextract unshield cpio
```

### Linux (RHEL/CentOS/Fedora)
```bash
sudo dnf install p7zip p7zip-plugins unrar

# For additional formats  
sudo dnf install cabextract unshield cpio
```

### Docker Usage

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    p7zip-full \
    unrar-free \
    cabextract \
    && rm -rf /var/lib/apt/lists/*

# Install unzipall
RUN pip install unzipall

# Your application code
COPY . /app
WORKDIR /app
```

## 📊 Performance

UnzipAll is designed for reliability and format support over raw speed. Benchmarks on typical archives:

- **ZIP files**: ~80 extractions/second
- **TAR.GZ files**: ~60 extractions/second
- **7Z files**: ~40 extractions/second
- **RAR files**: ~35 extractions/second

Performance varies based on archive size, compression ratio, and available system resources.

## 🧪 Development & Testing

```bash
# Clone the repository
git clone https://github.com/mricardo/unzipall.git
cd unzipall

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=src/unzipall --cov-report=html

# Format code
black src/ tests/

# Type checking
mypy src/

# Lint code
flake8 src/ tests/
```

### Running Specific Tests

```bash
# Test basic functionality
pytest tests/test_smoke.py -v

# Test specific archive format
pytest tests/test_core.py::test_extract_valid_zip -v

# Performance benchmarks
pytest tests/test_performance.py --benchmark-only

# Skip slow tests
pytest -m "not slow"
```

## 🔗 API Reference

### Main Functions

#### `extract(archive_path, extract_to=None, password=None, verbose=False)`
Extract an archive to the specified directory.

**Parameters:**
- `archive_path` (str|Path): Path to the archive file
- `extract_to` (str|Path, optional): Output directory (defaults to archive stem name)
- `password` (str, optional): Password for encrypted archives
- `verbose` (bool): Enable detailed logging

**Returns:** `bool` - True if successful

**Example:**
```python
# Extract to default location (archive stem name)
unzipall.extract('myfiles.zip')  # Creates ./myfiles/

# Extract to specific directory
unzipall.extract('myfiles.zip', 'custom_output')

# Extract encrypted archive
unzipall.extract('secret.7z', password='mypassword')
```

#### `is_supported(file_path)`
Check if a file format is supported.

**Parameters:**
- `file_path` (str|Path): Path to file to check

**Returns:** `bool` - True if format is supported

**Example:**
```python
if unzipall.is_supported('data.xyz'):
    print("This format is supported!")
else:
    print("Unsupported format")
```

#### `list_supported_formats()`
Get list of all supported file extensions.

**Returns:** `List[str]` - Sorted list of supported extensions

**Example:**
```python
formats = unzipall.list_supported_formats()
print(f"Supported: {', '.join(formats)}")
```

### ArchiveExtractor Class

For advanced usage with custom configuration:

```python
from unzipall import ArchiveExtractor

extractor = ArchiveExtractor(verbose=True)

# Check what features are available
features = extractor.get_available_features()

# Extract with custom settings
success = extractor.extract('archive.zip', 'output_dir')
```

### Exception Hierarchy

```
ArchiveExtractionError (base)
├── UnsupportedFormatError
├── CorruptedArchiveError  
├── PasswordRequiredError
├── InvalidPasswordError
├── ExtractionPermissionError
└── DiskSpaceError
```

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork the repository** on GitHub
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Install development dependencies**: `pip install -e ".[dev]"`
4. **Make your changes** and add tests
5. **Run the test suite**: `pytest`
6. **Commit your changes**: `git commit -m "Add amazing feature"`
7. **Push to the branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### Development Guidelines

- Write tests for new features
- Follow PEP 8 style guidelines (use `black` for formatting)
- Add type hints for new functions
- Update documentation for API changes
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on top of excellent libraries: [`py7zr`](https://github.com/miurahr/py7zr), [`rarfile`](https://github.com/markokr/rarfile), [`patool`](https://github.com/wummel/patool), [`libarchive-c`](https://github.com/Changaco/python-libarchive-c), and others
- Inspired by the need for a simple, unified archive extraction interface
- Thanks to all contributors and users who help improve this library

## 🔗 Related Projects

- **[patool](https://github.com/wummel/patool)** - Command-line archive tool
- **[py7zr](https://github.com/miurahr/py7zr)** - Pure Python 7-zip library
- **[rarfile](https://github.com/markokr/rarfile)** - RAR archive reader
- **[zipfile](https://docs.python.org/3/library/zipfile.html)** - Python standard library ZIP support

## 📞 Support

- **Documentation**: Check this README and docstrings
- **Issues**: [GitHub Issues](https://github.com/mricardo/unzipall/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mricardo/unzipall/discussions)
- **Email**: ricardo.lee.cm@gmail.com

---

**Star this repo if you find it useful! ⭐**

Made with ❤️ by [mricardo](https://github.com/mricardo)
