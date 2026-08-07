"""PEiD signature database parser for PackerScope.

Parses PEiD-format signature databases (userdb.txt) into structured
signature objects for byte-pattern matching. Supports hex patterns
with ``??`` wildcards.

PEiD format::

    [Packer Name v1.0]
    signature = 60 E8 00 00 00 00 5D 83 ED 06
    ep_only = true
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from packerscope.utils.logger import get_logger

logger = get_logger(__name__)


class PEiDSignature(NamedTuple):
    """A parsed PEiD signature entry.

    Attributes:
        name: The packer/compiler name from the signature header.
        pattern: Byte pattern as list of ints. None = wildcard (``??``).
        ep_only: If True, match only at entry point. If False, scan file.
    """

    name: str
    pattern: list[int | None]
    ep_only: bool


class PEiDParser:
    """Parser for PEiD-format signature databases.

    Reads a PEiD ``userdb.txt`` file and produces a list of
    ``PEiDSignature`` objects for use by the SignatureDetector.

    Example:
        >>> parser = PEiDParser(Path("signatures/peid_userdb.txt"))
        >>> sigs = parser.load()
        >>> len(sigs)
        42
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._signatures: list[PEiDSignature] = []

    def load(self) -> list[PEiDSignature]:
        """Parse the signature database file.

        Returns:
            List of parsed PEiDSignature objects.

        Raises:
            FileNotFoundError: If the database file doesn't exist.
        """
        if not self._db_path.exists():
            logger.warning("peid_db_not_found", path=str(self._db_path))
            return []

        self._signatures = []
        current_name: str | None = None
        current_sig: str | None = None
        current_ep: bool = True

        try:
            with open(self._db_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith(";") or line.startswith("#"):
                        continue

                    # Section header: [Packer Name]
                    if line.startswith("[") and line.endswith("]"):
                        # Save previous entry if complete
                        if current_name and current_sig:
                            self._add_signature(current_name, current_sig, current_ep, line_num)

                        current_name = line[1:-1].strip()
                        current_sig = None
                        current_ep = True
                        continue

                    # Key = Value pairs
                    if "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip().lower()
                        value = value.strip()

                        if key == "signature":
                            current_sig = value
                        elif key == "ep_only":
                            current_ep = value.lower() in ("true", "1", "yes")

                # Don't forget the last entry
                if current_name and current_sig:
                    self._add_signature(current_name, current_sig, current_ep, -1)

        except Exception as e:
            logger.error("peid_parse_error", error=str(e), path=str(self._db_path))

        logger.info("peid_signatures_loaded", count=len(self._signatures))
        return self._signatures

    def _add_signature(
        self, name: str, sig_str: str, ep_only: bool, line_num: int
    ) -> None:
        """Parse a hex signature string and add to the list."""
        pattern = self._parse_pattern(sig_str)
        if pattern:
            self._signatures.append(PEiDSignature(
                name=name,
                pattern=pattern,
                ep_only=ep_only,
            ))
        else:
            logger.warning(
                "peid_invalid_signature",
                name=name,
                line=line_num,
            )

    @staticmethod
    def _parse_pattern(sig_str: str) -> list[int | None]:
        """Convert a hex signature string to a byte pattern list.

        Args:
            sig_str: Space-separated hex bytes, e.g. ``"60 E8 ?? 00 00"``.

        Returns:
            List of int values (0-255) or None for wildcards.
            Empty list if parsing fails.
        """
        pattern: list[int | None] = []
        tokens = sig_str.split()
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if token == "??" or token == "?":
                pattern.append(None)
            else:
                try:
                    val = int(token, 16)
                    if 0 <= val <= 255:
                        pattern.append(val)
                    else:
                        return []
                except ValueError:
                    return []
        return pattern
