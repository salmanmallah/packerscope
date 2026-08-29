"""Heuristic detection engine for PackerScope.

Implements a weighted composite scoring system that aggregates results
from all prior detectors into a final packing confidence score and
packer identification verdict.

The heuristic engine runs LAST in the detection pipeline (highest priority
number) so it can access all prior detection results via the PEContext.

Design Pattern: Strategy (weights are configurable)
    The weight of each feature is configurable via ``Config.heuristic_weights``,
    allowing users to tune the engine for their specific malware corpus.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from packerscope.constants import (
    DEFAULT_HEURISTIC_WEIGHTS,
)
from packerscope.core.enums import (
    ConfidenceLevel,
    DetectionMethod,
    EntropyClass,
    PackerType,
)
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, PackerVerdict
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.config import HeuristicWeights
    from packerscope.context import PEContext

logger = get_logger(__name__)


class HeuristicDetector(BaseDetector):
    """Weighted composite heuristic engine for packer detection.

    This detector runs last in the pipeline and aggregates signals from
    all prior detectors into a single confidence score. Each signal
    contributes a configurable weight to the total score.

    The engine also performs packer identification by correlating
    signals across detectors (e.g., UPX section names + UPX signature
    match + high entropy = high-confidence UPX detection).

    Attributes:
        name: "heuristic"
        description: Human-readable description.
        priority: 200 (runs last).
        weights: Configurable weight values for each feature.
    """

    name: str = "heuristic"
    description: str = "Weighted composite heuristic engine aggregating all detection signals"
    version: str = "1.0.0"
    priority: int = 200  # Runs last

    def __init__(self, weights: HeuristicWeights | None = None) -> None:
        """Initialize with optional custom weights.

        Args:
            weights: Custom heuristic weights. If None, defaults from
                constants are used.
        """
        if weights is not None:
            self._weights = {
                field: getattr(weights, field) for field in weights.__class__.model_fields
            }
            self._max_score = weights.max_score
        else:
            self._weights = dict(DEFAULT_HEURISTIC_WEIGHTS)
            self._max_score = sum(DEFAULT_HEURISTIC_WEIGHTS.values())

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Aggregate all prior detection results into a composite score.

        Evaluates each feature signal from prior detectors, applies
        configurable weights, normalizes the score, and produces a
        final packer verdict.

        Args:
            ctx: Analysis context with all prior detection results.

        Returns:
            DetectionResult with composite confidence and packer verdict.
        """
        start = time.monotonic()
        score = 0.0
        reasons: list[str] = []
        packer_votes: dict[PackerType, float] = {}

        # --- Feature: High Entropy ---
        score, reasons = self._check_entropy(ctx, score, reasons, packer_votes)

        # --- Feature: Suspicious Section Names ---
        score, reasons = self._check_sections(ctx, score, reasons, packer_votes)

        # --- Feature: Tiny IAT ---
        score, reasons = self._check_iat(ctx, score, reasons, packer_votes)

        # --- Feature: RWX Sections ---
        score, reasons = self._check_rwx_sections(ctx, score, reasons, packer_votes)

        # --- Feature: Signature Match ---
        score, reasons = self._check_signatures(ctx, score, reasons, packer_votes)

        # --- Feature: YARA Match ---
        score, reasons = self._check_yara(ctx, score, reasons, packer_votes)

        # --- Feature: Entry Point Stub ---
        score, reasons = self._check_entrypoint(ctx, score, reasons, packer_votes)

        # --- Feature: EP Outside .text ---
        score, reasons = self._check_ep_location(ctx, score, reasons, packer_votes)

        # --- Feature: Large Overlay ---
        score, reasons = self._check_overlay(ctx, score, reasons, packer_votes)

        # --- Feature: No Relocations ---
        score, reasons = self._check_relocations(ctx, score, reasons, packer_votes)

        # --- Feature: Abnormal Alignment ---
        score, reasons = self._check_alignment(ctx, score, reasons, packer_votes)

        # --- Feature: Missing Debug Info ---
        score, reasons = self._check_debug_info(ctx, score, reasons, packer_votes)

        # --- Feature: Suspicious Timestamp ---
        score, reasons = self._check_timestamp(ctx, score, reasons, packer_votes)

        # Normalize score to 0.0–1.0
        normalized_score = min(score / self._max_score, 1.0) if self._max_score > 0 else 0.0
        confidence_level = ConfidenceLevel.from_score(normalized_score)
        is_packed = normalized_score >= 0.40  # MEDIUM threshold

        # Determine packer from votes
        packer = self._determine_packer(packer_votes)

        # Build verdict and store in context
        contributing = {
            name: result.confidence
            for name, result in ctx.detection_results.items()
            if result.is_packed
        }

        verdict = PackerVerdict(
            is_packed=is_packed,
            packer=packer,
            confidence=normalized_score,
            confidence_level=confidence_level,
            reasons=reasons,
            contributing_detectors=contributing,
        )
        ctx.verdict = verdict

        duration = time.monotonic() - start

        logger.info(
            "heuristic_analysis_complete",
            score=round(normalized_score, 4),
            is_packed=is_packed,
            packer=packer.value,
            confidence_level=confidence_level.value,
            num_reasons=len(reasons),
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.HEURISTIC,
            is_packed=is_packed,
            packer_hint=packer,
            confidence=normalized_score,
            reasons=reasons,
            details={
                "raw_score": round(score, 2),
                "max_score": self._max_score,
                "normalized_score": round(normalized_score, 4),
                "confidence_level": confidence_level.value,
                "packer_votes": {k.value: round(v, 3) for k, v in packer_votes.items()},
            },
            duration_seconds=duration,
        )

    def _check_entropy(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check entropy signals from the entropy detector."""
        if ctx.entropy is None:
            return score, reasons

        if ctx.entropy.whole_file_class in (EntropyClass.HIGH, EntropyClass.VERY_HIGH):
            weight = self._weights.get("high_entropy", 25)
            score += weight
            reasons.append(
                f"High whole-file entropy: {ctx.entropy.whole_file_entropy:.2f} "
                f"({ctx.entropy.whole_file_class.value})"
            )

        # Check for multiple high-entropy sections
        high_sections = [
            se
            for se in ctx.entropy.section_entropies
            if se.entropy_class in (EntropyClass.HIGH, EntropyClass.VERY_HIGH)
        ]
        if len(high_sections) > 1:
            score += 5  # Bonus for multiple high-entropy sections
            reasons.append(f"{len(high_sections)} sections with high entropy")

        return score, reasons

    def _check_sections(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check section name signals."""
        section_result = ctx.get_detection("sections")
        if section_result is None:
            return score, reasons

        if section_result.is_packed and section_result.packer_hint != PackerType.NONE:
            weight = self._weights.get("known_packer_sections", 20)
            score += weight
            packer = section_result.packer_hint
            votes[packer] = votes.get(packer, 0) + weight
            reasons.append(f"Known packer section names detected: {packer.value}")
        elif section_result.is_packed:
            weight = self._weights.get("suspicious_section_names", 20)
            score += weight
            reasons.append("Suspicious section names detected")

        # Check for blank/null section names
        blank_sections = [
            s for s in ctx.sections if not s.name.strip() or s.name.strip("\x00") == ""
        ]
        if blank_sections:
            score += 5
            reasons.append(f"{len(blank_sections)} sections with blank names")

        return score, reasons

    def _check_iat(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check IAT signals."""
        if ctx.imports is None:
            return score, reasons

        if ctx.imports.total_imports < 10:
            weight = self._weights.get("tiny_iat", 15)
            score += weight
            reasons.append(
                f"Very small IAT: {ctx.imports.total_imports} total imports "
                f"({ctx.imports.dll_count} DLLs, {ctx.imports.api_count} APIs)"
            )

        if ctx.imports.has_dynamic_loading:
            score += 10
            reasons.append("Dynamic loading pattern detected (LoadLibrary + GetProcAddress only)")

        if ctx.imports.suspicious_apis:
            score += min(len(ctx.imports.suspicious_apis) * 2, 10)
            reasons.append(
                f"{len(ctx.imports.suspicious_apis)} suspicious APIs: "
                f"{', '.join(ctx.imports.suspicious_apis[:5])}"
            )

        return score, reasons

    def _check_rwx_sections(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for read-write-execute sections."""
        rwx = [s for s in ctx.sections if s.is_rwx]
        if rwx:
            weight = self._weights.get("rwx_sections", 10)
            score += weight
            reasons.append(
                f"{len(rwx)} section(s) with RWX permissions: {', '.join(s.name for s in rwx)}"
            )
        return score, reasons

    def _check_signatures(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check signature match signals."""
        if ctx.signature_matches:
            weight = self._weights.get("signature_match", 30)
            best = max(ctx.signature_matches, key=lambda m: m.confidence)
            score += weight * best.confidence
            reasons.append(
                f"Signature match: {best.signature_name} (confidence: {best.confidence:.0%})"
            )
            # Vote for the packer from signature
            sig_result = ctx.get_detection("signatures")
            if sig_result and sig_result.packer_hint != PackerType.NONE:
                packer = sig_result.packer_hint
                votes[packer] = votes.get(packer, 0) + weight * best.confidence
        return score, reasons

    def _check_yara(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check YARA match signals."""
        if ctx.yara_matches:
            weight = self._weights.get("yara_match", 25)
            best = max(ctx.yara_matches, key=lambda m: m.confidence)
            score += weight * best.confidence
            reasons.append(f"YARA rule match: {best.rule_name} (confidence: {best.confidence:.0%})")
            yara_result = ctx.get_detection("yara")
            if yara_result and yara_result.packer_hint != PackerType.NONE:
                packer = yara_result.packer_hint
                votes[packer] = votes.get(packer, 0) + weight * best.confidence
        return score, reasons

    def _check_entrypoint(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check entry point stub signals."""
        if ctx.entrypoint is None:
            return score, reasons

        if ctx.entrypoint.stub_detected:
            weight = self._weights.get("entry_point_stub", 15)
            score += weight
            stub_info = f" ({ctx.entrypoint.stub_type})" if ctx.entrypoint.stub_type else ""
            reasons.append(f"Packer stub detected at entry point{stub_info}")

        if ctx.entrypoint.jump_chain_detected:
            score += 5
            reasons.append("Jump chain detected at entry point")

        if ctx.entrypoint.nop_sled_detected:
            score += 3
            reasons.append("NOP sled detected at entry point")

        return score, reasons

    def _check_ep_location(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check if entry point is outside the .text section."""
        if ctx.entrypoint is None:
            return score, reasons

        if not ctx.entrypoint.is_in_code_section:
            weight = self._weights.get("ep_outside_text", 10)
            score += weight
            reasons.append(f"Entry point in non-code section: {ctx.entrypoint.entry_point_section}")
        return score, reasons

    def _check_overlay(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for large overlay data."""
        if ctx.structure is None:
            return score, reasons

        if ctx.structure.has_overlay and ctx.structure.overlay_size > 4096:
            weight = self._weights.get("large_overlay", 5)
            score += weight
            size_kb = ctx.structure.overlay_size / 1024
            reasons.append(f"Large overlay data: {size_kb:.1f} KB")
        return score, reasons

    def _check_relocations(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for missing relocations."""
        if ctx.structure is None:
            return score, reasons

        # Missing relocations in a DLL is especially suspicious
        if not ctx.structure.has_relocations and ctx.structure.is_dll:
            weight = self._weights.get("no_relocations", 5)
            score += weight * 2  # Double weight for DLLs
            reasons.append("DLL missing relocations (highly suspicious)")
        elif not ctx.structure.has_relocations:
            weight = self._weights.get("no_relocations", 5)
            score += weight
            reasons.append("Missing relocation table")
        return score, reasons

    def _check_alignment(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for abnormal section/file alignment."""
        if ctx.structure is None:
            return score, reasons

        # Check section alignment is power of 2
        sa = ctx.structure.section_alignment
        if sa > 0 and (sa & (sa - 1)) != 0:
            weight = self._weights.get("abnormal_alignment", 5)
            score += weight
            reasons.append(f"Abnormal section alignment: {sa:#x}")

        fa = ctx.structure.file_alignment
        if fa > 0 and (fa & (fa - 1)) != 0:
            score += 3
            reasons.append(f"Abnormal file alignment: {fa:#x}")

        return score, reasons

    def _check_debug_info(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for missing debug information."""
        if ctx.structure is None:
            return score, reasons

        if not ctx.structure.has_debug_info:
            weight = self._weights.get("missing_debug_info", 3)
            score += weight
            reasons.append("No debug information present")
        return score, reasons

    def _check_timestamp(
        self,
        ctx: PEContext,
        score: float,
        reasons: list[str],
        votes: dict[PackerType, float],
    ) -> tuple[float, list[str]]:
        """Check for suspicious compile timestamp."""
        if ctx.structure is None:
            return score, reasons

        if not ctx.structure.compile_timestamp_valid:
            weight = self._weights.get("suspicious_timestamp", 3)
            score += weight
            ts = ctx.structure.compile_timestamp
            reasons.append(f"Suspicious compile timestamp: {ts}")
        return score, reasons

    def _determine_packer(self, votes: dict[PackerType, float]) -> PackerType:
        """Select the packer with the highest weighted vote.

        Args:
            votes: Packer type to cumulative vote weight mapping.

        Returns:
            The PackerType with the highest total votes, or
            GENERIC_PACKED if votes exist but no clear winner,
            or UNKNOWN if no votes.
        """
        if not votes:
            return PackerType.UNKNOWN

        # Filter out NONE and UNKNOWN
        valid_votes = {
            k: v for k, v in votes.items() if k not in (PackerType.NONE, PackerType.UNKNOWN)
        }

        if not valid_votes:
            return PackerType.GENERIC_PACKED

        best = max(valid_votes, key=valid_votes.get)  # type: ignore[arg-type]

        # Require a minimum vote threshold
        if valid_votes[best] < 10:
            return PackerType.GENERIC_PACKED

        return best
