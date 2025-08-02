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

import libarchive
import magic
import patoolib
import py7zr
import pycdlib
import rarfile

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

        # Format mappings
        self.format_handlers = {
            # ZIP family
            '.zip': self._extract_zip,
            '.jar': self._extract_zip,
            '.war': self._extract_zip,
            '.ear': self._extract_zip,
            '.apk': self._extract_zip,
            '.epub': self._extract_zip,
            '.cbz': self._extract_zip,

            # RAR family
            '.rar': self._extract_rar,
            '.cbr': self._extract_rar,

            # 7Z family
            '.7z': self._extract_7z,
            '.cb7': self._extract_7z,

            # TAR family
            '.tar': self._extract_tar,
            '.tar.gz': self._extract_tar,
            '.tgz': self._extract_tar,
            '.tar.bz2': self._extract_tar,
            '.tbz2': self._extract_tar,
            '.tar.xz': self._extract_tar,
            '.txz': self._extract_tar,
            '.tar.z': self._extract_tar,
            '.tar.lzma': self._extract_tar,

            # Single file compression
            '.gz': self._extract_gzip,
            '.bz2': self._extract_bz2,
            '.xz': self._extract_xz,
            '.lzma': self._extract_lzma,
            '.z': self._extract_z,

            # Archive formats
            '.arj': self._extract_with_patool,
            '.cab': self._extract_with_patool,
            '.chm': self._extract_with_patool,
            '.cpio': self._extract_cpio,
            '.deb': self._extract_with_patool,
            '.rpm': self._extract_with_patool,
            '.lzh': self._extract_with_patool,
            '.lha': self._extract_with_patool,

            # Disk images
            '.iso': self._extract_iso,
            '.vhd': self._extract_with_patool,
            '.udf': self._extract_with_patool,

            # Microsoft formats
            '.msi': self._extract_msi,
            '.exe': self._extract_exe,
            '.wim': self._extract_with_patool,

            # Other formats
            '.xar': self._extract_with_patool,
            '.zpaq': self._extract_with_patool,
            '.cso': self._extract_with_patool,
            '.pkg': self._extract_with_patool,
            '.cbt': self._extract_tar,  # Comic Book TAR
        }

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('ArchiveExtractor')
        if self.verbose:
            logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

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
        if ext not in self.format_handlers:
            try:
                mime_type = magic.from_file(str(archive_path), mime=True)
                ext = self._mime_to_extension(mime_type)
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
                zip_ref.extractall(extract_to)
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
                tar_ref.extractall(extract_to)
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
        try:
            # Use system uncompress command
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
            return self._extract_with_patool(archive_path, extract_to, password)
        except Exception as e:
            self.logger.error(f"Z extraction failed: {e}")
            return self._extract_with_patool(archive_path, extract_to, password)

    def _extract_cpio(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract CPIO archives."""
        try:
            with libarchive.file_reader(str(archive_path)) as archive:
                for entry in archive:
                    # Extract each entry
                    output_path = extract_to / entry.name
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    if entry.isfile():
                        with open(output_path, 'wb') as f:
                            for block in entry.get_blocks():
                                f.write(block)
            return True
        except Exception as e:
            self.logger.error(f"CPIO extraction failed: {e}")

        return self._extract_with_patool(archive_path, extract_to, password)

    def _extract_iso(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract ISO images."""
        try:
            iso = pycdlib.PyCdlib()
            iso.open(str(archive_path))

            for child in iso.list_children(encoding='utf-8'):
                if child.is_file():
                    output_path = extract_to / child.file_identifier()
                    iso.get_file_from_iso_fp(output_path.open('wb'),
                                             filename=child.file_identifier())

            iso.close()
            return True
        except Exception as e:
            self.logger.error(f"ISO extraction failed: {e}")

        # Fallback to system mount or 7z
        return self._extract_with_patool(archive_path, extract_to, password)

    def _extract_msi(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract MSI files."""
        try:
            # Try using msiexec on Windows
            if sys.platform == 'win32':
                result = subprocess.run([
                    'msiexec', '/a', str(archive_path), '/qn',
                    f'TARGETDIR={extract_to.absolute()}'
                ], check=True, capture_output=True)
                return True
        except Exception:
            pass

        return self._extract_with_patool(archive_path, extract_to, password)

    def _extract_exe(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract self-extracting EXE files."""
        # Many EXE files are actually ZIP archives or can be extracted with 7z
        try:
            return self._extract_zip(archive_path, extract_to, password)
        except Exception:
            pass

        try:
            return self._extract_7z(archive_path, extract_to, password)
        except Exception:
            pass

        return self._extract_with_patool(archive_path, extract_to, password)

    def _extract_with_patool(self, archive_path: Path, extract_to: Path, password: Optional[str] = None) -> bool:
        """Extract using patool as fallback."""
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
            bool: True if a format is supported
        """
        try:
            format_ext = self._detect_format(Path(file_path))
            return format_ext in self.format_handlers
        except Exception:
            return False


# Example usage and testing
if __name__ == "__main__":
    # Example usage
    extractor = ArchiveExtractor(verbose=True)

    print("Supported formats:")
    for fmt in extractor.list_supported_formats():
        print(f"  {fmt}")

    # Example extraction
    # extractor.extract('example.zip', 'output_dir')
    # extractor.extract('example.tar.gz', 'output_dir')
    # extractor.extract('encrypted.7z', 'output_dir', password='secret')