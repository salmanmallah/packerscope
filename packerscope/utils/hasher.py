"""Cryptographic and fuzzy hash computation for PE binary analysis.

Provides :class:`FileHasher` with static methods that compute MD5, SHA-1,
SHA-256, import hashes (imphash), and — when ``ppdeep`` is installed — ssdeep
fuzzy hashes.

Typical usage::

    from packerscope.utils.hasher import FileHasher

    data = Path("sample.exe").read_bytes()
    hashes = FileHasher.compute_all(data)
    # {'md5': '…', 'sha1': '…', 'sha256': '…'}
"""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

__all__ = [
    "FileHasher",
]

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Optional ppdeep availability check
# ---------------------------------------------------------------------------
_PPDEEP_AVAILABLE: bool = False
try:
    import ppdeep as _ppdeep  # type: ignore[import-untyped]

    _PPDEEP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ppdeep = None  # type: ignore[assignment]


def _ssdeep_available() -> bool:
    """Return ``True`` when the ``ppdeep`` library is importable."""
    return _PPDEEP_AVAILABLE


class FileHasher:
    """Static helper class for computing common file hashes.

    All public methods are ``@staticmethod`` — no instance state is needed.
    """

    # ------------------------------------------------------------------
    # Aggregate helper
    # ------------------------------------------------------------------

    @staticmethod
    def compute_all(data: bytes) -> dict[str, str]:
        """Compute MD5, SHA-1, and SHA-256 hashes in a single pass.

        Args:
            data: Raw file bytes.

        Returns:
            A dictionary with keys ``"md5"``, ``"sha1"``, ``"sha256"``
            mapped to their lowercase hex-digest strings.

        Examples:
            >>> hashes = FileHasher.compute_all(b"hello")
            >>> sorted(hashes.keys())
            ['md5', 'sha1', 'sha256']
        """
        md5_ctx = hashlib.md5(data, usedforsecurity=False)
        sha1_ctx = hashlib.sha1(data, usedforsecurity=False)
        sha256_ctx = hashlib.sha256(data)

        return {
            "md5": md5_ctx.hexdigest(),
            "sha1": sha1_ctx.hexdigest(),
            "sha256": sha256_ctx.hexdigest(),
        }

    # ------------------------------------------------------------------
    # Individual hash algorithms
    # ------------------------------------------------------------------

    @staticmethod
    def compute_md5(data: bytes) -> str:
        """Return the MD5 hex digest of *data*.

        Args:
            data: Raw file bytes.

        Returns:
            32-character lowercase hex string.
        """
        return hashlib.md5(data, usedforsecurity=False).hexdigest()

    @staticmethod
    def compute_sha1(data: bytes) -> str:
        """Return the SHA-1 hex digest of *data*.

        Args:
            data: Raw file bytes.

        Returns:
            40-character lowercase hex string.
        """
        return hashlib.sha1(data, usedforsecurity=False).hexdigest()

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        """Return the SHA-256 hex digest of *data*.

        Args:
            data: Raw file bytes.

        Returns:
            64-character lowercase hex string.
        """
        return hashlib.sha256(data).hexdigest()

    # ------------------------------------------------------------------
    # PE-specific hashes
    # ------------------------------------------------------------------

    @staticmethod
    def compute_imphash(pe: Any) -> str:
        """Compute the import hash (*imphash*) of a parsed PE.

        Relies on ``pefile.PE.get_imphash()``.  If the PE has no import
        directory or the computation fails, an empty string is returned.

        Args:
            pe: A :class:`pefile.PE` instance (already parsed).

        Returns:
            40-character lowercase imphash hex string, or ``""`` on failure.
        """
        try:
            imphash: str = pe.get_imphash()
            return imphash if imphash else ""
        except Exception:
            logger.warning("imphash_computation_failed", exc_info=True)
            return ""

    # ------------------------------------------------------------------
    # Fuzzy hashing (optional dependency)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_ssdeep(data: bytes) -> str:
        """Compute an ssdeep fuzzy hash via the ``ppdeep`` library.

        If ``ppdeep`` is not installed the method returns an empty string
        and logs a debug-level notice on the first call.

        Args:
            data: Raw file bytes.

        Returns:
            The ssdeep hash string, or ``""`` if unavailable / on error.
        """
        if not _PPDEEP_AVAILABLE:
            logger.debug("ppdeep_not_installed", hint="install with: pip install ppdeep")
            return ""

        try:
            return str(_ppdeep.hash(data))
        except Exception:
            logger.warning("ssdeep_computation_failed", exc_info=True)
            return ""
