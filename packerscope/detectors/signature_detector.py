"""Byte-pattern signature matching for PackerScope.

Matches PEiD-format signatures against PE file entry point bytes
and (optionally) the full file body. Supports wildcard bytes (``??``).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, SignatureMatch
from packerscope.signatures.peid_parser import PEiDParser, PEiDSignature
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Map common packer name substrings to PackerType enum
_NAME_KEYWORDS: list[tuple[str, PackerType]] = [
    ("upx", PackerType.UPX),
    ("aspack", PackerType.ASPACK),
    ("mpress", PackerType.MPRESS),
    ("fsg", PackerType.FSG),
    ("pecompact", PackerType.PECOMPACT),
    ("petite", PackerType.PETITE),
    ("nspack", PackerType.NSPACK),
    ("themida", PackerType.THEMIDA),
    ("vmprotect", PackerType.VMPROTECT),
    ("mew", PackerType.MEW),
    ("armadillo", PackerType.ARMADILLO),
    ("enigma", PackerType.ENIGMA),
    ("obsidium", PackerType.OBSIDIUM),
    ("upack", PackerType.UPACK),
    ("winupack", PackerType.WINUPACK),
    ("molebox", PackerType.MOLEBOX),
]


class SignatureDetector(BaseDetector):
    """Detect packing via byte-pattern signature matching.

    Loads PEiD-format signatures and matches them against the entry
    point bytes (ep_only=true) or the full file (ep_only=false).
    """

    name: str = "signatures"
    description: str = "Matches byte-pattern signatures against known packers"
    version: str = "1.0.0"
    priority: int = 55

    def __init__(self, signatures_dir: Path | None = None) -> None:
        self._signatures_dir = signatures_dir
        self._sigs: list[PEiDSignature] | None = None  # lazy loaded

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Match signatures against the PE file.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with signature match findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0
        packer_hint = PackerType.NONE

        if not ctx.pe or not ctx.pe.is_valid:
            return DetectionResult.empty(self.name, DetectionMethod.SIGNATURE_SCAN)

        # Lazy-load signatures
        if self._sigs is None:
            self._sigs = self._load_signatures()

        if not self._sigs:
            reasons.append("No signatures loaded — skipping signature scan")
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.SIGNATURE_SCAN,
                is_packed=False,
                reasons=reasons,
                duration_seconds=time.monotonic() - start,
            )

        # Read entry point bytes
        ep_data = ctx.pe.entry_point_data(512)
        matches: list[SignatureMatch] = []

        for sig in self._sigs:
            if sig.ep_only:
                # Match against entry point bytes
                if self._match_pattern(ep_data, sig.pattern):
                    match = SignatureMatch(
                        signature_name=sig.name,
                        packer_name=sig.name,
                        offset=ctx.pe.entry_point_offset,
                        database="peid_userdb",
                        confidence=0.85,
                        ep_only=True,
                    )
                    matches.append(match)
                    ctx.add_signature_match(match)
            else:
                # Scan full file (limited to first 4KB for performance)
                scan_region = ctx.raw_data[:4096]
                offset = self._find_pattern(scan_region, sig.pattern)
                if offset >= 0:
                    match = SignatureMatch(
                        signature_name=sig.name,
                        packer_name=sig.name,
                        offset=offset,
                        database="peid_userdb",
                        confidence=0.75,
                        ep_only=False,
                    )
                    matches.append(match)
                    ctx.add_signature_match(match)

        if matches:
            is_packed = True
            best = max(matches, key=lambda m: m.confidence)
            packer_hint = self._name_to_packer(best.signature_name)
            confidence = best.confidence
            for m in matches:
                reasons.append(f"Signature match: {m.signature_name} (at offset {m.offset:#x})")
        else:
            reasons.append(f"No signature matches ({len(self._sigs)} signatures tested)")

        duration = time.monotonic() - start
        logger.info(
            "signature_scan_complete",
            matches=len(matches),
            total_sigs=len(self._sigs),
            packer_hint=packer_hint.value,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.SIGNATURE_SCAN,
            is_packed=is_packed,
            packer_hint=packer_hint,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "match_count": len(matches),
                "total_signatures": len(self._sigs),
                "matched_names": [m.signature_name for m in matches],
            },
            duration_seconds=round(duration, 6),
        )

    def _load_signatures(self) -> list[PEiDSignature]:
        """Load PEiD signatures from the configured directory."""
        search_dirs = []
        if self._signatures_dir:
            search_dirs.append(self._signatures_dir)

        # Also try default location relative to this file
        pkg_dir = Path(__file__).parent.parent / "signatures"
        if pkg_dir.exists():
            search_dirs.append(pkg_dir)

        all_sigs: list[PEiDSignature] = []
        for d in search_dirs:
            for db_file in d.glob("*.txt"):
                parser = PEiDParser(db_file)
                all_sigs.extend(parser.load())

        logger.info("signatures_loaded_total", count=len(all_sigs))
        return all_sigs

    @staticmethod
    def _match_pattern(data: bytes, pattern: list[int | None]) -> bool:
        """Match a pattern against the start of a data buffer.

        Args:
            data: Byte buffer to match against.
            pattern: Pattern list (int for exact byte, None for wildcard).

        Returns:
            True if pattern matches at offset 0.
        """
        if len(data) < len(pattern):
            return False
        for i, expected in enumerate(pattern):
            if expected is not None and data[i] != expected:
                return False
        return True

    @staticmethod
    def _find_pattern(data: bytes, pattern: list[int | None]) -> int:
        """Search for a pattern anywhere in a data buffer.

        Returns:
            Offset of the first match, or -1 if not found.
        """
        pat_len = len(pattern)
        if pat_len == 0 or len(data) < pat_len:
            return -1

        for offset in range(len(data) - pat_len + 1):
            match = True
            for i, expected in enumerate(pattern):
                if expected is not None and data[offset + i] != expected:
                    match = False
                    break
            if match:
                return offset
        return -1

    @staticmethod
    def _name_to_packer(name: str) -> PackerType:
        """Map a signature name string to a PackerType enum value."""
        lower = name.lower()
        for keyword, ptype in _NAME_KEYWORDS:
            if keyword in lower:
                return ptype
        if "generic" in lower or "pushad" in lower or "pushfd" in lower:
            return PackerType.GENERIC_PACKED
        return PackerType.UNKNOWN
