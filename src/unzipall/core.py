"""
Universal Archive Extractor Library

A comprehensive Python library for extracting various archive formats including:
ZIP, RAR, 7Z, TAR, TGZ, TAR.gz, TAR.bz2, TAR.Z, TAR.lzma, TAR.xz,
APK, ARJ, BZ2, CAB, CB7, CBR, CBT, CBZ, CHM, CPIO, CSO, DEB, EPUB,
EXE, GZ, ISO, LZH, MSI, PKG, RPM, TBZ2, TXZ, UDF, VHD, WIM, XAR,
XZ, Z, ZPAQ and more.

Requirements:
    pip install py7zr rarfile patool libarchive-c python-magic pycdlib

Usage:
    from archive_extractor import ArchiveExtractor

    extractor = ArchiveExtractor()
    extractor.extract('archive.zip', 'output_directory')
"""

import bz2
import gzip
import logging
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional, List, Union

# Optional imports with fallbacks
try:
    import libarchive
    HAS_LIBARCHIVE = True
except (ImportError, OSError, TypeError) as e:
    HAS_LIBARCHIVE = False
    libarchive = None

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

try:
    import patoolib
    HAS_PATOOL = True
except ImportError:
    HAS_PATOOL = False
    patoolib = None

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False
    py7zr = None

try:
    import pycdlib
    HAS_PYCDLIB = True
except ImportError:
    HAS_PYCDLIB = False
    pycdlib = None

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False
    rarfile = None

from .exceptions import *

class ArchiveExtractor:
    """
    Universal archive extractor supporting multiple formats.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the ArchiveExtractor.

        Args:
            verbose (bool): Enable verbose logging
        """
        self.verbose = verbose
        self.logger = self._setup_logger()
        self.format_handlers = self._build_format_handlers()

    def _build_format_handlers(self):
        """Build format handlers based on available dependencies."""
        handlers = {
            # Always available formats (built into Python)
            '.tar': self._extract_tar,
            '.tar.gz': self._extract_tar,
            '.tgz': self._extract_tar,
            '.tar.bz2': self._extract_tar,
            '.tbz2': self._extract_tar,
            '.tar.xz': self._extract_tar,
            '.txz': self._extract_tar,
            '.tar.z': self._extract_tar,
            '.tar.lzma': self._extract_tar,
            '.gz': self._extract_gzip,
            '.bz2': self._extract_bz2,
            '.xz': self._extract_xz,
            '.lzma': self._extract_lzma,
            '.zip': self._extract_zip,
            '.jar': self._extract_zip,
            '.war': self._extract_zip,
            '.ear': self._extract_zip,
            '.apk': self._extract_zip,
            '.epub': self._extract_zip,
            '.cbz': self._extract_zip,
        }

        # Add handlers based on available dependencies
        if HAS_RARFILE:
            handlers.update({
                '.rar': self._extract_rar,
                '.cbr': self._extract_rar,
            })

        if HAS_PY7ZR:
            handlers.update({
                '.7z': self._extract_7z,
                '.cb7': self._extract_7z,
            })

        if HAS_PYCDLIB:
            handlers['.iso'] = self._extract_iso

        if HAS_LIBARCHIVE:
            handlers['.cpio'] = self._extract_cpio

        # Patool-dependent formats
        if HAS_PATOOL:
            handlers.update({
                '.arj': self._extract_with_patool,
                '.cab': self._extract_with_patool,
                '.chm': self._extract_with_patool,
                '.deb': self._extract_with_patool,
                '.rpm': self._extract_with_patool,
                '.lzh': self._extract_with_patool,
                '.lha': self._extract_with_patool,
                '.vhd': self._extract_with_patool,
                '.udf': self._extract_with_patool,
                '.wim': self._extract_with_patool,
                '.xar': self._extract_with_patool,
                '.zpaq': self._extract_with_patool,
                '.cso': self._extract_with_patool,
                '.pkg': self._extract_with_patool,
                '.cbt': self._extract_with_patool,
            })

        # Add system-dependent formats
        if self._has_command('uncompress'):
            handlers['.z'] = self._extract_z
        elif HAS_PATOOL:
            handlers['.z'] = self._extract_with_patool

        if sys.platform == 'win32' or HAS_PATOOL:
            handlers.update({
                '.msi': self._extract_msi,
                '.exe': self._extract_exe,
            })

        return handlers

    def _has_command(self, command: str) -> bool:
        """Check if a system command is available."""
        return shutil.which(command) is not None

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('ArchiveExtractor')
        if self.verbose and not logger.handlers:
            logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _is_safe_path(self, path: str, extract_to: Path) -> bool:
        """Check if extraction path is safe (no directory traversal)."""
        # Normalize the path
        normalized = os.path.normpath(path)

        # Check for absolute paths or parent directory references
        if os.path.isabs(normalized) or normalized.startswith('..'):
            return False

        # Ensure the final path is within extract_to
        final_path = extract_to / normalized
        try:
            final_path.resolve().relative_to(extract_to.resolve())
            return True
        except ValueError:
            return False

    def _safe_extract_zip(self, zip_ref, extract_to: Path):
        """Safely extract ZIP file with path traversal protection."""
        for member in zip_ref.infolist():
            if not self._is_safe_path(member.filename, extract_to):
                self.logger.warning(f"Skipping unsafe path: {member.filename}")
                continue
            zip_ref.extract(member, extract_to)

    def _safe_extract_tar(self, tar_ref, extract_to: Path):
        """Safely extract TAR file with path traversal protection."""
        for member in tar_ref.getmembers():
            if not self._is_safe_path(member.name, extract_to):
                self.logger.warning(f"Skipping unsafe path: {member.name}")
                continue
            tar_ref.extract(member, extract_to)

    def extract(self, archive_path: Union[str, Path],
                extract_to: Union[str, Path],
                password: Optional[str] = None) -> bool:
        """
        Extract an archive to the specified directory.

        Args:
            archive_path: Path to the archive file
            extract_to: Directory to extract files to
            password: Password for encrypted archives

        Returns:
            bool: True if extraction successful, False otherwise

        Raises:
            ArchiveExtractionError: If extraction fails
            UnsupportedFormatError: If archive format is not supported
            CorruptedArchiveError: If archive is corrupted
            PasswordRequiredError: If archive requires password
            InvalidPasswordError: If password is incorrect
            ExtractionPermissionError: If permission denied
            DiskSpaceError: If insufficient disk space
        """
        archive_path = Path(archive_path)
        extract_to = Path(extract_to)

        if not archive_path.exists():
            raise ArchiveExtractionError(f"Archive file not found: {archive_path}")

        # Create extraction directory
        try:
            extract_to.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise ExtractionPermissionError(f"Permission denied creating directory: {extract_to}")
        except OSError as e:
            if "No space left on device" in str(e):
                raise DiskSpaceError(f"Insufficient disk space: {extract_to}")
            raise ArchiveExtractionError(f"Failed to create directory {extract_to}: {e}")

        # Detect format
        format_ext = self._detect_format(archive_path)

        if format_ext not in self.format_handlers:
            # Try to suggest what's needed
            missing_dep = self._get_missing_dependency(format_ext)
            if missing_dep:
                raise UnsupportedFormatError(
                    f"Unsupported archive format: {format_ext}. "
                    f"Please install: {missing_dep}"
                )
            else:
                raise UnsupportedFormatError(f"Unsupported archive format: {format_ext}")

        self.logger.info(f"Extracting {archive_path} to {extract_to}")

        try:
            handler = self.format_handlers[format_ext]
            return handler(archive_path, extract_to, password)
        except (PasswordRequiredError, InvalidPasswordError, ExtractionPermissionError,
                DiskSpaceError, UnsupportedFormatError, CorruptedArchiveError):
            # Re-raise specific exceptions as-is
            raise
        except Exception as e:
            # Convert other exceptions to appropriate types
            error_msg = str(e).lower()
            if "password" in error_msg and "required" in error_msg:
                raise PasswordRequiredError(f"Archive requires password: {archive_path}")
            elif "password" in error_msg or "wrong password" in error_msg:
                raise InvalidPasswordError(f"Invalid password for archive: {archive_path}")
            elif "permission denied" in error_msg:
                raise ExtractionPermissionError(f"Permission denied extracting: {archive_path}")
            elif "no space" in error_msg or "disk full" in error_msg:
                raise DiskSpaceError(f"Insufficient disk space extracting: {archive_path}")
            elif "corrupt" in error_msg or "damaged" in error_msg or "invalid" in error_msg:
                raise CorruptedArchiveError(f"Archive appears to be corrupted: {archive_path}")
            else:
                raise ArchiveExtractionError(f"Failed to extract {archive_path}: {e}")

    def _get_missing_dependency(self, format_ext: str) -> Optional[str]:
        """Get missing dependency for unsupported format."""
        format_deps = {
            '.rar': 'rarfile',
            '.cbr': 'rarfile',
            '.7z': 'py7zr',
            '.cb7': 'py7zr',
            '.iso': 'pycdlib',
            '.cpio': 'libarchive-c',
            '.arj': 'patool',
            '.cab': 'patool',
            '.chm': 'patool',
            '.deb': 'patool',
            '.rpm': 'patool',
        }
        return format_deps.get(format_ext)

    def _detect_format(self, archive_path: Path) -> str:
        """
        Detect archive format based on file extension and magic bytes.

        Args:
            archive_path: Path to archive file

        Returns:
            str: Detected format extension
        """
        # Check compound extensions first
        name_lower = archive_path.name.lower()

        compound_extensions = ['.tar.gz', '.tar.bz2', '.tar.xz', '.tar.z', '.tar.lzma']
        for ext in compound_extensions:
            if name_lower.endswith(ext):
                return ext

        # Check simple extension
        ext = archive_path.suffix.lower()

        # Use magic bytes if python-magic is available
        if ext not in self.format_handlers and HAS_MAGIC:
            try:
                mime_type = magic.from_file(str(archive_path), mime=True)
                detected_ext = self._mime_to_extension(mime_type)
                if detected_ext:
                    ext = detected_ext
            except Exception:
                pass

        return ext

    def _mime_to_extension(self, mime_type: str) -> str:
        """Convert MIME type to file extension."""
        mime_map = {
            'application/zip': '.zip',
            'application/x-rar-compressed': '.rar',
            'application/x-7z-compressed': '.7z',
            'application/x-tar': '.tar',
            'application/gzip': '.gz',
            'application/x-bzip2': '.bz2',
            'application/x-xz': '.xz',
            'application/x-lzma': '.lzma',
            'application/x-iso9660-image': '.iso',
            'application/x-msi': '.msi',
            'application/x-deb': '.deb',
            'application/x-rpm': '.rpm',
        }
        return mime_map.get(mime_type, '')

    def _extract_zip(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract ZIP archives."""
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                if password:
                    zip_ref.setpassword(password.encode())
                self._safe_extract_zip(zip_ref, extract_to)
            return True
        except zipfile.BadZipFile:
            raise CorruptedArchiveError(f"ZIP file is corrupted or invalid: {archive_path}")
        except RuntimeError as e:
            error_msg = str(e).lower()
            if "bad password" in error_msg:
                raise InvalidPasswordError(f"Invalid password for ZIP file: {archive_path}")
            elif "requires a password" in error_msg:
                raise PasswordRequiredError(f"ZIP file requires password: {archive_path}")
            raise ArchiveExtractionError(f"ZIP extraction failed: {e}")
        except PermissionError:
            raise ExtractionPermissionError(f"Permission denied extracting ZIP file: {archive_path}")

    def _extract_rar(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract RAR archives."""
        if not HAS_RARFILE:
            raise UnsupportedFormatError("RAR support requires 'rarfile' package")

        try:
            with rarfile.RarFile(archive_path) as rar_ref:
                if password:
                    rar_ref.setpassword(password)
                rar_ref.extractall(extract_to)
            return True
        except rarfile.BadRarFile:
            raise CorruptedArchiveError(f"RAR file is corrupted or invalid: {archive_path}")
        except rarfile.PasswordRequired:
            raise PasswordRequiredError(f"RAR file requires password: {archive_path}")
        except rarfile.WrongPassword:
            raise InvalidPasswordError(f"Invalid password for RAR file: {archive_path}")
        except Exception as e:
            self.logger.error(f"RAR extraction failed: {e}")
            return False

    def _extract_7z(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract 7Z archives."""
        if not HAS_PY7ZR:
            raise UnsupportedFormatError("7Z support requires 'py7zr' package")

        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password=password) as archive:
                archive.extractall(path=extract_to)
            return True
        except py7zr.Bad7zFile:
            raise CorruptedArchiveError(f"7Z file is corrupted or invalid: {archive_path}")
        except py7zr.PasswordRequired:
            raise PasswordRequiredError(f"7Z file requires password: {archive_path}")
        except py7zr.WrongPassword:
            raise InvalidPasswordError(f"Invalid password for 7Z file: {archive_path}")
        except Exception as e:
            self.logger.error(f"7Z extraction failed: {e}")
            return False

    def _extract_tar(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract TAR archives (including compressed variants)."""
        try:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                self._safe_extract_tar(tar_ref, extract_to)
            return True
        except tarfile.ReadError:
            raise CorruptedArchiveError(f"TAR file is corrupted or invalid: {archive_path}")
        except Exception as e:
            self.logger.error(f"TAR extraction failed: {e}")
            return False

    def _extract_gzip(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract GZIP files."""
        try:
            output_file = extract_to / archive_path.stem
            with gzip.open(archive_path, 'rb') as gz_file:
                with open(output_file, 'wb') as out_file:
                    shutil.copyfileobj(gz_file, out_file)
            return True
        except gzip.BadGzipFile:
            raise CorruptedArchiveError(f"GZIP file is corrupted or invalid: {archive_path}")
        except Exception as e:
            self.logger.error(f"GZIP extraction failed: {e}")
            return False

    def _extract_bz2(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract BZ2 files."""
        try:
            output_file = extract_to / archive_path.stem
            with bz2.open(archive_path, 'rb') as bz2_file:
                with open(output_file, 'wb') as out_file:
                    shutil.copyfileobj(bz2_file, out_file)
            return True
        except OSError as e:
            if "Invalid data stream" in str(e):
                raise CorruptedArchiveError(f"BZ2 file is corrupted or invalid: {archive_path}")
            raise ArchiveExtractionError(f"BZ2 extraction failed: {e}")

    def _extract_xz(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract XZ files."""
        try:
            output_file = extract_to / archive_path.stem
            with lzma.open(archive_path, 'rb') as xz_file:
                with open(output_file, 'wb') as out_file:
                    shutil.copyfileobj(xz_file, out_file)
            return True
        except lzma.LZMAError:
            raise CorruptedArchiveError(f"XZ file is corrupted or invalid: {archive_path}")
        except Exception as e:
            self.logger.error(f"XZ extraction failed: {e}")
            return False

    def _extract_lzma(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract LZMA files."""
        return self._extract_xz(archive_path, extract_to, password)

    def _extract_z(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract Z (compress) files."""
        if not self._has_command('uncompress'):
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            raise UnsupportedFormatError("Z format requires 'uncompress' command or patool")

        try:
            output_file = extract_to / archive_path.stem
            result = subprocess.run(['uncompress', '-c', str(archive_path)],
                                    capture_output=True, check=True)
            with open(output_file, 'wb') as out_file:
                out_file.write(result.stdout)
            return True
        except subprocess.CalledProcessError:
            raise CorruptedArchiveError(f"Z file is corrupted or uncompress failed: {archive_path}")
        except FileNotFoundError:
            # Fallback to patool if uncompress not available
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            raise UnsupportedFormatError("Z format requires 'uncompress' command or patool")
        except Exception as e:
            self.logger.error(f"Z extraction failed: {e}")
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            return False

    def _extract_cpio(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract CPIO archives."""
        if not HAS_LIBARCHIVE:
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            raise UnsupportedFormatError("CPIO format requires 'libarchive-c' package")

        try:
            with libarchive.file_reader(str(archive_path)) as archive:
                for entry in archive:
                    if not self._is_safe_path(entry.name, extract_to):
                        self.logger.warning(f"Skipping unsafe path: {entry.name}")
                        continue

                    output_path = extract_to / entry.name
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    if entry.isfile():
                        with open(output_path, 'wb') as f:
                            for block in entry.get_blocks():
                                f.write(block)
            return True
        except Exception as e:
            self.logger.error(f"CPIO extraction failed: {e}")
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            return False

    def _extract_iso(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract ISO images."""
        if not HAS_PYCDLIB:
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            raise UnsupportedFormatError("ISO format requires 'pycdlib' package")

        try:
            iso = pycdlib.PyCdlib()
            iso.open(str(archive_path))

            for child in iso.list_children(encoding='utf-8'):
                if child.is_file():
                    filename = child.file_identifier()
                    if not self._is_safe_path(filename, extract_to):
                        self.logger.warning(f"Skipping unsafe path: {filename}")
                        continue

                    output_path = extract_to / filename
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    with output_path.open('wb') as f:
                        iso.get_file_from_iso_fp(f, filename=filename)

            iso.close()
            return True
        except Exception as e:
            self.logger.error(f"ISO extraction failed: {e}")
            if HAS_PATOOL:
                return self._extract_with_patool(archive_path, extract_to, password)
            return False

    def _extract_msi(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract MSI files."""
        if sys.platform == 'win32' and self._has_command('msiexec'):
            try:
                result = subprocess.run([
                    'msiexec', '/a', str(archive_path), '/qn',
                    f'TARGETDIR={extract_to.absolute()}'
                ], check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError:
                pass

        if HAS_PATOOL:
            return self._extract_with_patool(archive_path, extract_to, password)

        raise UnsupportedFormatError("MSI extraction requires msiexec (Windows) or patool")

    def _extract_exe(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract self-extracting EXE files."""
        # Many EXE files are actually ZIP archives or can be extracted with 7z
        try:
            return self._extract_zip(archive_path, extract_to, password)
        except Exception:
            pass

        if HAS_PY7ZR:
            try:
                return self._extract_7z(archive_path, extract_to, password)
            except Exception:
                pass

        if HAS_PATOOL:
            return self._extract_with_patool(archive_path, extract_to, password)

        raise UnsupportedFormatError("EXE extraction failed with all methods")

    def _extract_with_patool(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract using patool as fallback."""
        if not HAS_PATOOL:
            raise UnsupportedFormatError("This format requires 'patool' package")

        try:
            # Change to extraction directory for patool
            old_cwd = os.getcwd()
            os.chdir(extract_to)

            if password:
                patoolib.extract_archive(str(archive_path), outdir=str(extract_to),
                                         program_args=[f'-p{password}'])
            else:
                patoolib.extract_archive(str(archive_path), outdir=str(extract_to))

            os.chdir(old_cwd)
            return True
        except Exception as e:
            if 'old_cwd' in locals():
                os.chdir(old_cwd)
            error_msg = str(e).lower()
            if "password" in error_msg:
                if password:
                    raise InvalidPasswordError(f"Invalid password for archive: {archive_path}")
                else:
                    raise PasswordRequiredError(f"Archive requires password: {archive_path}")
            elif "not found" in error_msg or "no such file" in error_msg:
                raise UnsupportedFormatError(f"Required extraction tool not found for: {archive_path}")
            elif "corrupt" in error_msg or "damaged" in error_msg:
                raise CorruptedArchiveError(f"Archive appears corrupted: {archive_path}")

            self.logger.error(f"Patool extraction failed: {e}")
            return False

    def list_supported_formats(self) -> List[str]:
        """
        Get a list of supported archive formats.

        Returns:
            List[str]: List of supported file extensions
        """
        return sorted(self.format_handlers.keys())

    def is_supported(self, file_path: Union[str, Path]) -> bool:
        """
        Check if a file format is supported.

        Args:
            file_path: Path to file to check

        Returns:
            bool: True if format is supported
        """
        try:
            format_ext = self._detect_format(Path(file_path))
            return format_ext in self.format_handlers
        except Exception:
            return False

    def get_available_features(self) -> dict:
        """Get information about available optional features."""
        return {
            'rarfile': HAS_RARFILE,
            'py7zr': HAS_PY7ZR,
            'patool': HAS_PATOOL,
            'libarchive': HAS_LIBARCHIVE,
            'pycdlib': HAS_PYCDLIB,
            'python-magic': HAS_MAGIC,
            'uncompress_command': self._has_command('uncompress'),
            'msiexec_command': self._has_command('msiexec'),
        }


# Example usage and testing
if __name__ == "__main__":
    # Example usage
    extractor = ArchiveExtractor(verbose=True)

    print("Supported formats:")
    for fmt in extractor.list_supported_formats():
        print(f"  {fmt}")

    print("\nAvailable features:")
    features = extractor.get_available_features()
    for feature, available in features.items():
        status = "✅" if available else "❌"
        print(f"  {status} {feature}")

    # Example extraction
    # extractor.extract('example.zip', 'output_dir')
    # extractor.extract('example.tar.gz', 'output_dir')
    # extractor.extract('encrypted.7z', 'output_dir', password='secret')