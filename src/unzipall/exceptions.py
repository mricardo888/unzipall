"""Custom exceptions for unzipall library."""


class ArchiveExtractionError(Exception):
    """Base exception for archive extraction errors."""
    pass


class UnsupportedFormatError(ArchiveExtractionError):
    """Raised when an archive format is not supported."""
    pass


class CorruptedArchiveError(ArchiveExtractionError):
    """Raised when archive is corrupted or invalid."""
    pass


class PasswordRequiredError(ArchiveExtractionError):
    """Raised when archive requires a password but none provided."""
    pass


class InvalidPasswordError(ArchiveExtractionError):
    """Raised when provided password is incorrect."""
    pass


class ExtractionPermissionError(ArchiveExtractionError):
    """Raised when extraction fails due to permission issues."""
    pass


class DiskSpaceError(ArchiveExtractionError):
    """Raised when extraction fails due to insufficient disk space."""
    pass
