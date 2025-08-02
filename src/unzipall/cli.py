"""Command-line interface for unzipall."""

import argparse
import sys
from pathlib import Path

from .core import ArchiveExtractor, ArchiveExtractionError


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Universal archive extractor supporting 30+ formats"
    )
    parser.add_argument(
        "archive",
        nargs="?",  # Make archive optional
        help="Path to archive file"
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="Output directory (default: current directory)"
    )
    parser.add_argument(
        "-p", "--password",
        help="Password for encrypted archives"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--list-formats",
        action="store_true",
        help="List supported formats"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )

    args = parser.parse_args()

    extractor = ArchiveExtractor(verbose=args.verbose)

    if args.list_formats:
        print("Supported formats:")
        for fmt in extractor.list_supported_formats():
            print(f"  {fmt}")
        return 0

    if not args.archive:
        parser.print_help()
        return 1

    archive_path = Path(args.archive)
    output_path = Path(args.output) if args.output else Path.cwd()

    try:
        success = extractor.extract(archive_path, output_path, args.password)
        if success:
            print(f"Successfully extracted {archive_path} to {output_path}")
            return 0
        else:
            print(f"Failed to extract {archive_path}", file=sys.stderr)
            return 1
    except ArchiveExtractionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())