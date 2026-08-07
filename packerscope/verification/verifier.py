"""Unpacking verification for PackerScope.

After an unpacker produces output, this module validates the quality
of the unpacked PE by comparing entropy, import table size, section
characteristics, and basic PE validity against the original.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pefile

from packerscope.core.interfaces import BaseVerifier
from packerscope.core.models import VerificationResult
from packerscope.utils.entropy import calculate_entropy
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


class UnpackVerifier(BaseVerifier):
    """Verify the quality of an unpacked PE file.

    Runs a battery of checks comparing the unpacked file against the
    original packed file:
    1. PE validity check
    2. Entropy reduction
    3. IAT restoration
    4. Section normalization
    5. Size sanity
    """

    name: str = "default"

    def verify(self, ctx: PEContext, unpacked_path: Path) -> VerificationResult:
        """Run all verification checks on the unpacked file.

        Args:
            ctx: Original analysis context (packed file).
            unpacked_path: Path to the unpacked PE file.

        Returns:
            VerificationResult with check outcomes.
        """
        checks_passed = 0
        total_checks = 5
        comparison: dict[str, Any] = {}

        # Original metrics
        orig_entropy = ctx.entropy.whole_file_entropy if ctx.entropy else 0.0
        orig_imports = ctx.imports.total_imports if ctx.imports else 0

        # Check 1: Is it a valid PE?
        is_valid_pe = False
        try:
            unpacked_pe = pefile.PE(str(unpacked_path))
            is_valid_pe = True
            checks_passed += 1
            comparison["pe_valid"] = True
        except Exception as e:
            comparison["pe_valid"] = False
            comparison["pe_error"] = str(e)
            logger.warning("verify_pe_invalid", error=str(e))
            # Can't continue without valid PE
            return VerificationResult(
                is_valid_pe=False,
                entropy_reduced=False,
                iat_restored=False,
                sections_normal=False,
                original_entropy=orig_entropy,
                unpacked_entropy=0.0,
                original_imports=orig_imports,
                unpacked_imports=0,
                comparison=comparison,
                checks_passed=0,
                total_checks=total_checks,
            )

        # Check 2: Entropy reduction
        unpacked_data = unpacked_path.read_bytes()
        unpacked_entropy = calculate_entropy(unpacked_data)
        entropy_reduced = unpacked_entropy < orig_entropy - 0.5  # At least 0.5 reduction
        if entropy_reduced:
            checks_passed += 1
        comparison["entropy_original"] = round(orig_entropy, 4)
        comparison["entropy_unpacked"] = round(unpacked_entropy, 4)
        comparison["entropy_delta"] = round(orig_entropy - unpacked_entropy, 4)

        # Check 3: IAT restoration (more imports in unpacked)
        unpacked_imports = 0
        try:
            if hasattr(unpacked_pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in unpacked_pe.DIRECTORY_ENTRY_IMPORT:
                    unpacked_imports += len(entry.imports)
        except Exception:
            pass

        iat_restored = unpacked_imports > orig_imports
        if iat_restored:
            checks_passed += 1
        comparison["imports_original"] = orig_imports
        comparison["imports_unpacked"] = unpacked_imports

        # Check 4: Sections normal (no very-high entropy sections)
        sections_normal = True
        try:
            for section in unpacked_pe.sections:
                sec_data = section.get_data()
                sec_entropy = calculate_entropy(sec_data) if sec_data else 0.0
                if sec_entropy > 7.2:
                    sections_normal = False
                    break
        except Exception:
            sections_normal = False

        if sections_normal:
            checks_passed += 1
        comparison["sections_normal"] = sections_normal

        # Check 5: File size sanity (unpacked should be similar or larger)
        orig_size = len(ctx.raw_data)
        unpacked_size = len(unpacked_data)
        size_sane = unpacked_size >= orig_size * 0.3  # At least 30% of original
        if size_sane:
            checks_passed += 1
        comparison["size_original"] = orig_size
        comparison["size_unpacked"] = unpacked_size
        comparison["size_ratio"] = round(unpacked_size / max(orig_size, 1), 2)

        try:
            unpacked_pe.close()
        except Exception:
            pass

        logger.info(
            "verification_complete",
            checks_passed=checks_passed,
            total_checks=total_checks,
            entropy_reduced=entropy_reduced,
            iat_restored=iat_restored,
        )

        return VerificationResult(
            is_valid_pe=is_valid_pe,
            entropy_reduced=entropy_reduced,
            iat_restored=iat_restored,
            sections_normal=sections_normal,
            original_entropy=round(orig_entropy, 4),
            unpacked_entropy=round(unpacked_entropy, 4),
            original_imports=orig_imports,
            unpacked_imports=unpacked_imports,
            comparison=comparison,
            checks_passed=checks_passed,
            total_checks=total_checks,
        )
