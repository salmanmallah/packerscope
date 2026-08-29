"""Section-based packer detection for PackerScope.

Detects suspicious PE section names, characteristics, and anomalies that
indicate packing. Many packers use distinctive section names (UPX0, .vmp0,
.aspack) that serve as strong identification signals.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from packerscope.constants import SUSPICIOUS_SECTION_NAMES
from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Map packer name strings from constants to PackerType enum
_PACKER_NAME_MAP: dict[str, PackerType] = {
    "UPX": PackerType.UPX,
    "ASPack": PackerType.ASPACK,
    "VMProtect": PackerType.VMPROTECT,
    "MPRESS": PackerType.MPRESS,
    "Themida": PackerType.THEMIDA,
    "PECompact": PackerType.PECOMPACT,
    "FSG": PackerType.FSG,
    "MEW": PackerType.MEW,
    "NSPack": PackerType.NSPACK,
    "Petite": PackerType.PETITE,
    "UPack": PackerType.UPACK,
    "Armadillo": PackerType.ARMADILLO,
    "Enigma": PackerType.ENIGMA,
    "MoleBox": PackerType.MOLEBOX,
    "Obsidium": PackerType.OBSIDIUM,
}


class SectionDetector(BaseDetector):
    """Detect packing via section name and characteristic analysis.

    Checks section names against a database of known packer signatures,
    detects RWX sections, blank names, and abnormal size ratios.
    """

    name: str = "sections"
    description: str = "Detects suspicious section names and characteristics"
    version: str = "1.0.0"
    priority: int = 20

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Analyze PE sections for packing indicators.

        Args:
            ctx: Shared analysis context (sections populated by EntropyDetector).

        Returns:
            DetectionResult with section-based findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0
        packer_hint = PackerType.NONE
        packer_scores: dict[PackerType, int] = {}

        sections = ctx.sections
        if not sections:
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.SECTION_ANALYSIS,
                is_packed=False,
                reasons=["No sections available for analysis"],
                duration_seconds=time.monotonic() - start,
            )

        section_names = [s.name.strip().rstrip("\x00") for s in sections]

        # --- Check known packer section names ---
        for packer_name, known_names in SUSPICIOUS_SECTION_NAMES.items():
            matched = [n for n in section_names if n in known_names]
            if matched:
                ptype = _PACKER_NAME_MAP.get(packer_name, PackerType.GENERIC_PACKED)
                packer_scores[ptype] = packer_scores.get(ptype, 0) + len(matched) * 10
                is_packed = True
                reasons.append(f"Packer section name(s) [{packer_name}]: {', '.join(matched)}")

        # --- RWX sections ---
        rwx_sections = [s for s in sections if s.is_rwx]
        if rwx_sections:
            is_packed = True
            confidence = max(confidence, 0.40)
            names = ", ".join(s.name for s in rwx_sections)
            reasons.append(f"{len(rwx_sections)} RWX section(s): {names}")

        # --- Blank / null section names ---
        blank = [s for s in sections if not s.name.strip() or s.name.strip("\x00") == ""]
        if blank:
            is_packed = True
            confidence = max(confidence, 0.35)
            reasons.append(f"{len(blank)} section(s) with blank/null names")

        # --- Abnormal size ratios (virtual >> raw) ---
        abnormal_ratio = [s for s in sections if s.raw_size > 0 and s.size_ratio > 10.0]
        if abnormal_ratio:
            is_packed = True
            confidence = max(confidence, 0.45)
            for s in abnormal_ratio:
                reasons.append(
                    f"Section '{s.name}' has abnormal size ratio "
                    f"(virtual/raw = {s.size_ratio:.1f}x)"
                )

        # --- Sections with raw_size = 0 but large virtual_size ---
        hollow = [s for s in sections if s.raw_size == 0 and s.virtual_size > 4096]
        if hollow:
            confidence = max(confidence, 0.35)
            reasons.append(
                f"{len(hollow)} section(s) with zero raw size but "
                f"large virtual size (unpacking target)"
            )

        # --- Very few sections (common in packed files) ---
        if len(sections) <= 2:
            confidence = max(confidence, 0.25)
            reasons.append(f"Unusually few sections: {len(sections)}")

        # --- Very many sections (some protectors add many sections) ---
        if len(sections) > 10:
            confidence = max(confidence, 0.20)
            reasons.append(f"Unusually many sections: {len(sections)}")

        # --- Determine best packer hint from scores ---
        if packer_scores:
            best_packer = max(packer_scores, key=packer_scores.get)  # type: ignore[arg-type]
            packer_hint = best_packer
            # Scale confidence by number of matched names
            match_count = packer_scores[best_packer] // 10
            confidence = max(confidence, min(0.50 + match_count * 0.15, 0.90))

        if not reasons:
            reasons.append("Section names and characteristics appear normal")

        duration = time.monotonic() - start
        logger.info(
            "section_analysis_complete",
            is_packed=is_packed,
            packer_hint=packer_hint.value,
            section_count=len(sections),
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.SECTION_ANALYSIS,
            is_packed=is_packed,
            packer_hint=packer_hint,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "section_names": section_names,
                "rwx_count": len(rwx_sections),
                "blank_count": len(blank),
                "abnormal_ratio_count": len(abnormal_ratio),
                "total_sections": len(sections),
                "packer_scores": {k.value: v for k, v in packer_scores.items()},
            },
            duration_seconds=round(duration, 6),
        )
