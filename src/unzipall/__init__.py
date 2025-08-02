"""Universal Archive Extractor Library."""

from .core import ArchiveExtractor, ArchiveExtractionError
from .exceptions import *
from pathlib import Path
from typing import Optional, Union, List

__version__ = "1.0.0"
__author__ = "mricardo"
__email__ = "ricardo.lee.cm@gmail.com"

# Create a default instance for direct function calls
_default_extractor = ArchiveExtractor()

def extract(archive_path: Union[str, Path],
            extract_to: Union[str, Path, None] = None,
            password: Optional[str] = None,
            verbose: bool = False) -> bool:
    """
    Extract an archive to the specified directory.

    Args:
        archive_path: Path to the archive file
        extract_to: Directory to extract files to (default: same directory as archive)
        password: Password for encrypted archives
        verbose: Enable verbose logging

    Returns:
        bool: True if extraction successful, False otherwise

    Raises:
        ArchiveExtractionError: If extraction fails

    Example:
        import unzipall
        unzipall.extract('archive.zip')
        unzipall.extract('archive.zip', 'output_folder')
        unzipall.extract('encrypted.7z', password='secret')
    """
    global _default_extractor

    # Create new extractor if verbose setting changed
    if verbose != _default_extractor.verbose:
        _default_extractor = ArchiveExtractor(verbose=verbose)

    # Default extract_to to same directory as archive
    if extract_to is None:
        archive_path_obj = Path(archive_path)
        extract_to = archive_path_obj.parent / archive_path_obj.stem

    return _default_extractor.extract(archive_path, extract_to, password)

def list_supported_formats() -> List[str]:
    """
    Get a list of supported archive formats.

    Returns:
        List[str]: List of supported file extensions

    Example:
        import unzipall
        formats = unzipall.list_supported_formats()
        print(formats)
    """
    return _default_extractor.list_supported_formats()

def is_supported(file_path: Union[str, Path]) -> bool:
    """
    Check if a file format is supported.

    Args:
        file_path: Path to file to check

    Returns:
        bool: True if format is supported

    Example:
        import unzipall
        if unzipall.is_supported('archive.zip'):
            unzipall.extract('archive.zip')
    """
    return _default_extractor.is_supported(file_path)

__all__ = [
    "ArchiveExtractor",
    "ArchiveExtractionError",
    "UnsupportedFormatError",
    "CorruptedArchiveError",
    "PasswordRequiredError",
    "InvalidPasswordError",
    "ExtractionPermissionError",
    "DiskSpaceError",
    "extract",
    "list_supported_formats",
    "is_supported",
]