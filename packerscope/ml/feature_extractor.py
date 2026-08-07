"""Feature extraction pipeline for ML-based packer detection.

Extracts numerical features from a PEContext (after detection pipeline
has run) and produces a FeatureVector suitable for model training and
inference.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from packerscope.core.enums import EntropyClass
from packerscope.core.models import FeatureVector
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


class FeatureExtractor:
    """Extract numerical features from an analyzed PE context.

    After the detection pipeline has populated the PEContext with
    entropy, section, import, and structure data, this extractor
    converts those findings into a flat numerical feature vector
    suitable for ML model training and inference.

    Feature categories:
    1. Entropy features (6)
    2. Section features (8)
    3. Import features (6)
    4. Structure features (10)
    5. Entry point features (5)

    Total: ~35 features
    """

    def extract(self, ctx: PEContext) -> FeatureVector:
        """Extract features from an analyzed PEContext.

        Args:
            ctx: Analysis context with detection results.

        Returns:
            FeatureVector with named numerical features.
        """
        features: dict[str, float | int | str] = {}

        # --- Entropy features ---
        if ctx.entropy:
            features["whole_file_entropy"] = ctx.entropy.whole_file_entropy
            features["max_section_entropy"] = ctx.entropy.max_section_entropy
            features["min_section_entropy"] = ctx.entropy.min_section_entropy
            features["mean_section_entropy"] = ctx.entropy.mean_section_entropy
            features["entropy_spread"] = (
                ctx.entropy.max_section_entropy - ctx.entropy.min_section_entropy
            )
            features["high_entropy_section_count"] = sum(
                1 for se in ctx.entropy.section_entropies
                if se.entropy_class in (EntropyClass.HIGH, EntropyClass.VERY_HIGH)
            )
        else:
            features.update({
                "whole_file_entropy": 0.0, "max_section_entropy": 0.0,
                "min_section_entropy": 0.0, "mean_section_entropy": 0.0,
                "entropy_spread": 0.0, "high_entropy_section_count": 0,
            })

        # --- Section features ---
        sections = ctx.sections
        features["section_count"] = len(sections)
        features["rwx_section_count"] = sum(1 for s in sections if s.is_rwx)
        features["executable_section_count"] = sum(1 for s in sections if s.is_executable)
        features["writable_section_count"] = sum(1 for s in sections if s.is_writable)
        features["blank_name_count"] = sum(
            1 for s in sections if not s.name.strip() or s.name.strip("\x00") == ""
        )
        features["max_size_ratio"] = max(
            (s.size_ratio for s in sections), default=0.0
        )
        features["total_virtual_size"] = sum(s.virtual_size for s in sections)
        features["total_raw_size"] = sum(s.raw_size for s in sections)

        # --- Import features ---
        if ctx.imports:
            features["total_imports"] = ctx.imports.total_imports
            features["dll_count"] = ctx.imports.dll_count
            features["suspicious_api_count"] = len(ctx.imports.suspicious_apis)
            features["has_dynamic_loading"] = int(ctx.imports.has_dynamic_loading)
            features["import_anomaly_score"] = ctx.imports.anomaly_score
            features["api_per_dll_ratio"] = (
                ctx.imports.api_count / max(ctx.imports.dll_count, 1)
            )
        else:
            features.update({
                "total_imports": 0, "dll_count": 0, "suspicious_api_count": 0,
                "has_dynamic_loading": 0, "import_anomaly_score": 0.0,
                "api_per_dll_ratio": 0.0,
            })

        # --- Structure features ---
        if ctx.structure:
            features["has_overlay"] = int(ctx.structure.has_overlay)
            features["overlay_size"] = ctx.structure.overlay_size
            features["has_tls"] = int(ctx.structure.has_tls)
            features["tls_callback_count"] = ctx.structure.tls_callback_count
            features["has_relocations"] = int(ctx.structure.has_relocations)
            features["has_resources"] = int(ctx.structure.has_resources)
            features["has_debug_info"] = int(ctx.structure.has_debug_info)
            features["has_certificates"] = int(ctx.structure.has_certificates)
            features["checksum_valid"] = int(ctx.structure.checksum_valid)
            features["anomaly_count"] = len(ctx.structure.anomalies)
        else:
            features.update({
                "has_overlay": 0, "overlay_size": 0, "has_tls": 0,
                "tls_callback_count": 0, "has_relocations": 0, "has_resources": 0,
                "has_debug_info": 0, "has_certificates": 0, "checksum_valid": 0,
                "anomaly_count": 0,
            })

        # --- Entry point features ---
        if ctx.entrypoint:
            features["ep_in_code_section"] = int(ctx.entrypoint.is_in_code_section)
            features["ep_stub_detected"] = int(ctx.entrypoint.stub_detected)
            features["ep_jump_chain"] = int(ctx.entrypoint.jump_chain_detected)
            features["ep_nop_sled"] = int(ctx.entrypoint.nop_sled_detected)
            features["ep_rva"] = ctx.entrypoint.entry_point_rva
        else:
            features.update({
                "ep_in_code_section": 1, "ep_stub_detected": 0,
                "ep_jump_chain": 0, "ep_nop_sled": 0, "ep_rva": 0,
            })

        fv = FeatureVector(features=features)
        ctx.features = fv

        logger.debug("features_extracted", count=len(features))
        return fv
