"""Entropy-based packer detection for PackerScope.

Analyzes Shannon entropy at the whole-file and per-section level to detect
compression or encryption — the hallmark of packed executables. Packed
files exhibit uniformly high entropy (>6.5) because compression and
encryption produce near-random byte distributions.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from packerscope.core.enums import DetectionMethod, EntropyClass
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import (
    DetectionResult,
    EntropyResult,
    SectionEntropy,
    SectionInfo,
)
from packerscope.utils.entropy import calculate_entropy, classify_entropy
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Thresholds
_HIGH_FILE_ENTROPY = 6.5
_VERY_HIGH_SECTION_ENTROPY = 7.0
_HIGH_SECTION_ENTROPY = 6.8
_ENTROPY_SPREAD_THRESHOLD = 3.0  # difference between min and max section entropy


class EntropyDetector(BaseDetector):
    """Detect packing via Shannon entropy analysis.

    Calculates entropy for the entire file and each PE section individually.
    High entropy across multiple sections strongly indicates packing.
    """

    name: str = "entropy"
    description: str = "Analyzes Shannon entropy to detect compression or encryption"
    version: str = "1.0.0"
    priority: int = 10

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Run entropy analysis on the PE file.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with entropy findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0

        # Whole-file entropy
        whole_entropy = calculate_entropy(ctx.raw_data)
        whole_class = classify_entropy(whole_entropy)

        # Per-section entropy
        section_entropies: list[SectionEntropy] = []
        section_infos: list[SectionInfo] = []

        if ctx.pe and ctx.pe.is_valid:
            for sec in ctx.pe.sections:
                sec_data = sec.data if sec.data else b""
                sec_ent = calculate_entropy(sec_data) if sec_data else 0.0
                sec_class = classify_entropy(sec_ent)

                section_entropies.append(
                    SectionEntropy(
                        name=sec.name,
                        entropy=round(sec_ent, 4),
                        entropy_class=sec_class,
                        offset=sec.raw_offset,
                        size=sec.raw_size,
                    )
                )

                # Build SectionInfo for context
                chars = sec.characteristics
                is_exec = bool(chars & 0x20000000)
                is_write = bool(chars & 0x80000000)
                is_read = bool(chars & 0x40000000)
                raw = sec.raw_size if sec.raw_size > 0 else 1
                section_infos.append(
                    SectionInfo(
                        name=sec.name,
                        virtual_address=sec.virtual_address,
                        virtual_size=sec.virtual_size,
                        raw_size=sec.raw_size,
                        raw_offset=sec.raw_offset,
                        entropy=round(sec_ent, 4),
                        entropy_class=sec_class,
                        is_executable=is_exec,
                        is_writable=is_write,
                        is_readable=is_read,
                        is_rwx=is_exec and is_write and is_read,
                        flags=self._build_flags(chars),
                        size_ratio=round(sec.virtual_size / raw, 2),
                    )
                )

        # Store sections in context
        ctx.sections = section_infos

        # Statistics
        ent_values = [se.entropy for se in section_entropies] if section_entropies else [0.0]
        max_ent = max(ent_values)
        min_ent = min(ent_values)
        mean_ent = sum(ent_values) / len(ent_values)

        # Build and store EntropyResult
        ctx.entropy = EntropyResult(
            whole_file_entropy=round(whole_entropy, 4),
            whole_file_class=whole_class,
            section_entropies=section_entropies,
            max_section_entropy=round(max_ent, 4),
            min_section_entropy=round(min_ent, 4),
            mean_section_entropy=round(mean_ent, 4),
        )

        # --- Decision Logic ---
        if whole_class == EntropyClass.VERY_HIGH:
            is_packed = True
            confidence = 0.85
            reasons.append(f"Very high whole-file entropy: {whole_entropy:.4f}")
        elif whole_class == EntropyClass.HIGH:
            is_packed = True
            confidence = 0.60
            reasons.append(f"High whole-file entropy: {whole_entropy:.4f}")

        # Count high-entropy sections (excluding .rsrc which naturally contains compressed data)
        high_sections = [
            s
            for s in section_entropies
            if s.entropy >= _HIGH_SECTION_ENTROPY and ".rsrc" not in s.name.lower()
        ]
        very_high = [
            s
            for s in section_entropies
            if s.entropy >= _VERY_HIGH_SECTION_ENTROPY and ".rsrc" not in s.name.lower()
        ]

        if very_high:
            is_packed = True
            confidence = max(confidence, 0.75)
            names = ", ".join(s.name for s in very_high)
            reasons.append(f"{len(very_high)} section(s) with very high entropy (>7.0): {names}")

        if len(high_sections) > 1:
            is_packed = True
            confidence = max(confidence, 0.70)
            reasons.append(f"{len(high_sections)} sections with high entropy (>6.8)")

        # Large spread between min and max section entropy
        spread = max_ent - min_ent
        if spread > _ENTROPY_SPREAD_THRESHOLD and max_ent > _HIGH_SECTION_ENTROPY:
            confidence = max(confidence, 0.55)
            reasons.append(f"Large entropy spread between sections: {min_ent:.2f} — {max_ent:.2f}")

        if not reasons:
            reasons.append(f"Normal entropy levels (file: {whole_entropy:.4f})")

        duration = time.monotonic() - start
        logger.info(
            "entropy_analysis_complete",
            whole_entropy=round(whole_entropy, 4),
            max_section=round(max_ent, 4),
            is_packed=is_packed,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.ENTROPY,
            is_packed=is_packed,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "whole_file_entropy": round(whole_entropy, 4),
                "whole_file_class": whole_class.value,
                "max_section_entropy": round(max_ent, 4),
                "min_section_entropy": round(min_ent, 4),
                "mean_section_entropy": round(mean_ent, 4),
                "high_entropy_sections": len(high_sections),
                "section_count": len(section_entropies),
            },
            duration_seconds=round(duration, 6),
        )

    @staticmethod
    def _build_flags(characteristics: int) -> list[str]:
        """Convert PE section characteristics bitmask to flag names."""
        flags = []
        flag_map = {
            0x00000020: "CNT_CODE",
            0x00000040: "CNT_INITIALIZED_DATA",
            0x00000080: "CNT_UNINITIALIZED_DATA",
            0x02000000: "MEM_DISCARDABLE",
            0x04000000: "MEM_NOT_CACHED",
            0x08000000: "MEM_NOT_PAGED",
            0x10000000: "MEM_SHARED",
            0x20000000: "MEM_EXECUTE",
            0x40000000: "MEM_READ",
            0x80000000: "MEM_WRITE",
        }
        for mask, name in flag_map.items():
            if characteristics & mask:
                flags.append(name)
        return flags
