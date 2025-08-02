# UnzipAll - Universal Archive Extractor

[![PyPI version](https://badge.fury.io/py/unzipall.svg)](https://badge.fury.io/py/unzipall)
[![Python versions](https://img.shields.io/pypi/pyversions/unzipall.svg)](https://pypi.org/project/unzipall/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Python library for extracting archive files in 30+ formats with a simple, unified API. No more juggling multiple extraction libraries or dealing with format-specific quirks.

## ✨ Features

- **Universal Format Support**: ZIP, RAR, 7Z, TAR (all variants), ISO, MSI, and 25+ more
- **Simple API**: One function call to extract any supported archive
- **Password Protection**: Handle encrypted archives seamlessly
- **Error Handling**: Detailed exceptions for different failure scenarios
- **CLI Tool**: Extract archives from command line
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Type Safe**: Full type hints for better IDE support

## 🚀 Quick Start

### Installation

```bash
pip install unzipall
```

**Note**: Some formats require additional system tools. See [System Dependencies](#system-dependencies) below.

### Basic Usage

```python
import unzipall

# Extract any archive format
unzipall.extract('archive.zip')
unzipall.extract('data.tar.gz', 'output_folder')
unzipall.extract('encrypted.7z', password='secret')

# Check if format is supported
if unzipall.is_supported('mystery_file.xyz'):
    unzipall.extract('mystery_file.xyz')

# List all supported formats
formats = unzipall.list_supported_formats()
print(f"Supports {len(formats)} formats: {formats}")
```

### Advanced Usage

```python
from unzipall import ArchiveExtractor, ArchiveExtractionError

extractor = ArchiveExtractor(verbose=True)

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

| Category | Formats |
|----------|---------|
| **ZIP Family** | `.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.epub`, `.cbz` |
| **RAR Family** | `.rar`, `.cbr` |
| **7-Zip** | `.7z`, `.cb7` |
| **TAR Archives** | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.z`, `.tar.lzma` |
| **Compression** | `.gz`, `.bz2`, `.xz`, `.lzma`, `.z` |
| **Other Archives** | `.arj`, `.cab`, `.chm`, `.cpio`, `.deb`, `.rpm`, `.lzh`, `.lha` |
| **Disk Images** | `.iso`, `.vhd`, `.udf` |
| **Microsoft** | `.msi`, `.exe` (self-extracting), `.wim` |
| **Specialized** | `.xar`, `.zpaq`, `.cso`, `.pkg`, `.cbt` |

## 🛠 System Dependencies

While the library works out of the box for common formats (ZIP, TAR, GZIP, etc.), some formats require additional system tools:

### Windows
```bash
# Install 7-Zip (for advanced format support)
winget install 7zip.7zip

# Install WinRAR or unrar (for RAR support)
winget install RARLab.WinRAR
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

## 🔧 API Reference

### Main Functions

#### `extract(archive_path, extract_to=None, password=None, verbose=False)`
Extract an archive to the specified directory.

**Parameters:**
- `archive_path` (str|Path): Path to the archive file
- `extract_to` (str|Path, optional): Output directory (defaults to archive parent directory)
- `password` (str, optional): Password for encrypted archives
- `verbose` (bool): Enable detailed logging

**Returns:** `bool` - True if successful

**Raises:**
- `ArchiveExtractionError`: Base exception for extraction failures
- `UnsupportedFormatError`: Archive format not supported
- `CorruptedArchiveError`: Archive is damaged or invalid
- `PasswordRequiredError`: Archive needs password
- `InvalidPasswordError`: Wrong password provided
- `ExtractionPermissionError`: Insufficient permissions
- `DiskSpaceError`: Not enough disk space

#### `is_supported(file_path)`
Check if a file format is supported.

#### `list_supported_formats()`
Get list of all supported file extensions.

### ArchiveExtractor Class

For advanced usage with custom configuration:

```python
from unzipall import ArchiveExtractor

extractor = ArchiveExtractor(verbose=True)
extractor.extract('archive.zip', 'output_dir', 'password')
```

## 🧪 Error Handling

The library provides specific exceptions for different failure scenarios:

```python
import unzipall
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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on top of excellent libraries: `py7zr`, `rarfile`, `patool`, `libarchive-c`, and others
- Inspired by the need for a simple, unified archive extraction interface
- Thanks to all contributors and users who help improve this library

## 📊 Performance

UnzipAll prioritizes reliability and format support over raw speed. For performance-critical applications with specific format requirements, consider using format-specific libraries directly.

## 🔗 Related Projects

- [patool](https://github.com/wummel/patool) - Command-line archive tool
- [py7zr](https://github.com/miurahr/py7zr) - Pure Python 7-zip library
- [rarfile](https://github.com/markokr/rarfile) - RAR archive reader

---

**Star this repo if you find it useful! ⭐**