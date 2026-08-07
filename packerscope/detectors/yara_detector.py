"""YARA rule-based detection for PackerScope.

Compiles and scans YARA rules from multiple directories against PE files.
Gracefully handles the case where yara-python is not installed.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, YARAMatch
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Map YARA rule names/tags to PackerType
_YARA_PACKER_MAP: dict[str, PackerType] = {
    "upx": PackerType.UPX,
    "aspack": PackerType.ASPACK,
    "mpress": PackerType.MPRESS,
    "fsg": PackerType.FSG,
    "pecompact": PackerType.PECOMPACT,
    "petite": PackerType.PETITE,
    "nspack": PackerType.NSPACK,
    "themida": PackerType.THEMIDA,
    "vmprotect": PackerType.VMPROTECT,
    "mew": PackerType.MEW,
    "armadillo": PackerType.ARMADILLO,
    "enigma": PackerType.ENIGMA,
    "obsidium": PackerType.OBSIDIUM,
    "upack": PackerType.UPACK,
    "molebox": PackerType.MOLEBOX,
}


def _yara_available() -> bool:
    """Check if yara-python is importable."""
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


class YARADetector(BaseDetector):
    """Detect packing via YARA rule scanning.

    Compiles YARA rules from configured directories and scans the PE
    file data against them. Caches compiled rules for reuse.
    """

    name: str = "yara"
    description: str = "Scans PE file against YARA rules for packer identification"
    version: str = "1.0.0"
    priority: int = 60

    def __init__(self, rules_dirs: list[Path] | None = None) -> None:
        self._rules_dirs = rules_dirs or []
        self._compiled_rules: Any | None = None
        self._rules_loaded = False

    def is_available(self) -> bool:
        """Check if yara-python is installed."""
        return _yara_available()

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Scan the PE file against compiled YARA rules.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with YARA match findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0
        packer_hint = PackerType.NONE

        if not self.is_available():
            reasons.append("yara-python not installed — YARA scanning disabled")
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.YARA_SCAN,
                is_packed=False,
                reasons=reasons,
                duration_seconds=time.monotonic() - start,
            )

        # Compile rules (lazy, cached)
        if not self._rules_loaded:
            self._compile_rules()
            self._rules_loaded = True

        if self._compiled_rules is None:
            reasons.append("No YARA rules available")
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.YARA_SCAN,
                is_packed=False,
                reasons=reasons,
                duration_seconds=time.monotonic() - start,
            )

        # Scan
        try:
            raw_matches = self._compiled_rules.match(data=ctx.raw_data, timeout=30)
        except Exception as e:
            logger.error("yara_scan_error", error=str(e))
            reasons.append(f"YARA scan error: {e}")
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.YARA_SCAN,
                is_packed=False,
                reasons=reasons,
                duration_seconds=time.monotonic() - start,
            )

        yara_matches: list[YARAMatch] = []
        for m in raw_matches:
            meta = m.meta if hasattr(m, "meta") else {}
            match_confidence = float(meta.get("confidence", 0.8))

            strings_info = []
            if hasattr(m, "strings"):
                for s in m.strings:
                    if hasattr(s, "instances"):
                        for inst in s.instances:
                            strings_info.append({
                                "identifier": s.identifier,
                                "offset": inst.offset,
                                "matched_data": inst.matched_data.hex()[:64],
                            })
                    else:
                        strings_info.append({"identifier": str(s)})

            tags = list(m.tags) if hasattr(m, "tags") else []

            ym = YARAMatch(
                rule_name=m.rule,
                namespace=m.namespace if hasattr(m, "namespace") else "default",
                author=str(meta.get("author", "")),
                description=str(meta.get("description", "")),
                tags=tags,
                strings_matched=strings_info,
                confidence=match_confidence,
            )
            yara_matches.append(ym)
            ctx.add_yara_match(ym)

        if yara_matches:
            is_packed = True
            best = max(yara_matches, key=lambda ym: ym.confidence)
            confidence = best.confidence
            packer_hint = self._determine_packer(best)
            for ym in yara_matches:
                reasons.append(f"YARA match: {ym.rule_name} — {ym.description}")
        else:
            reasons.append("No YARA rule matches")

        duration = time.monotonic() - start
        logger.info(
            "yara_scan_complete",
            matches=len(yara_matches),
            packer_hint=packer_hint.value,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.YARA_SCAN,
            is_packed=is_packed,
            packer_hint=packer_hint,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "match_count": len(yara_matches),
                "matched_rules": [m.rule_name for m in yara_matches],
            },
            duration_seconds=round(duration, 6),
        )

    def _compile_rules(self) -> None:
        """Compile YARA rules from configured directories."""
        try:
            import yara
        except ImportError:
            return

        # Discover rule files
        rule_files: dict[str, str] = {}
        search_dirs = list(self._rules_dirs)

        # Add default package directory
        pkg_rules = Path(__file__).parent.parent / "signatures" / "yara_rules"
        if pkg_rules.exists():
            search_dirs.append(pkg_rules)

        for d in search_dirs:
            if not d.exists():
                continue
            for yar_file in d.rglob("*.yar"):
                ns = yar_file.stem
                rule_files[ns] = str(yar_file)
            for yar_file in d.rglob("*.yara"):
                ns = yar_file.stem
                rule_files[ns] = str(yar_file)

        if not rule_files:
            logger.warning("no_yara_rules_found", dirs=[str(d) for d in search_dirs])
            return

        try:
            self._compiled_rules = yara.compile(filepaths=rule_files)
            logger.info("yara_rules_compiled", file_count=len(rule_files))
        except yara.SyntaxError as e:
            logger.error("yara_compile_error", error=str(e))
        except Exception as e:
            logger.error("yara_compile_unexpected", error=str(e))

    @staticmethod
    def _determine_packer(match: YARAMatch) -> PackerType:
        """Map a YARA match to a PackerType via rule name and tags."""
        lower_name = match.rule_name.lower()
        for keyword, ptype in _YARA_PACKER_MAP.items():
            if keyword in lower_name:
                return ptype
        for tag in match.tags:
            for keyword, ptype in _YARA_PACKER_MAP.items():
                if keyword in tag.lower():
                    return ptype
        return PackerType.GENERIC_PACKED
