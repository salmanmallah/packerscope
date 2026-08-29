"""Import Address Table analysis for PackerScope.

Packed executables typically have a minimal IAT containing only the APIs
needed by the unpacking stub (LoadLibraryA, GetProcAddress, VirtualAlloc).
The real imports are resolved dynamically after unpacking at runtime.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from packerscope.constants import SUSPICIOUS_APIS
from packerscope.core.enums import DetectionMethod
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, ImportAnalysis, ImportInfo
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Dynamic-loading stub pattern: only these APIs = almost certainly packed
_DYNAMIC_LOADING_DLLS = {"kernel32.dll", "ntdll.dll"}
_DYNAMIC_LOADING_APIS = {
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
}

_NORMAL_IMPORT_RANGE = (30, 300)  # typical range for normal PE imports


class IATDetector(BaseDetector):
    """Detect packing via Import Address Table anomalies.

    Packed files have abnormally small import tables because the packer
    stub only needs a few APIs to load libraries and resolve functions
    dynamically at runtime.
    """

    name: str = "iat"
    description: str = "Analyzes Import Address Table for packing indicators"
    version: str = "1.0.0"
    priority: int = 30

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Analyze PE imports for packing indicators.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with IAT-based findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0

        if not ctx.pe or not ctx.pe.is_valid:
            return DetectionResult.empty(self.name, DetectionMethod.IAT_ANALYSIS)

        # Parse imports
        raw_imports = ctx.pe.imports
        import_infos: list[ImportInfo] = []
        all_dlls: list[str] = []
        all_apis: list[str] = []
        suspicious_found: list[str] = []

        for imp in raw_imports:
            all_dlls.append(imp.dll_name)
            funcs = imp.functions
            all_apis.extend(funcs)
            import_infos.append(ImportInfo(dll_name=imp.dll_name, functions=funcs))

            # Check for suspicious APIs
            for func in funcs:
                if func in SUSPICIOUS_APIS and func not in suspicious_found:
                    suspicious_found.append(func)

        total_imports = len(all_apis)
        dll_count = len(all_dlls)
        api_count = total_imports

        # --- Check for dynamic loading pattern ---
        has_dynamic_loading = False
        if dll_count <= 3 and total_imports <= 10:
            imported_set = set(all_apis)
            if imported_set & _DYNAMIC_LOADING_APIS:
                has_dynamic_loading = True

        # --- Anomaly scoring ---
        anomaly_score = 0.0

        # Very small IAT
        if total_imports == 0:
            is_packed = True
            confidence = 0.80
            anomaly_score = 1.0
            reasons.append("No imports found (zero IAT)")
        elif total_imports < 5:
            is_packed = True
            confidence = 0.75
            anomaly_score = 0.9
            reasons.append(f"Extremely small IAT: {total_imports} imports")
        elif total_imports < 10:
            is_packed = True
            confidence = 0.65
            anomaly_score = 0.7
            reasons.append(f"Very small IAT: {total_imports} imports")
        elif total_imports < 20:
            confidence = 0.40
            anomaly_score = 0.5
            reasons.append(f"Small IAT: {total_imports} imports")

        # Dynamic loading pattern
        if has_dynamic_loading:
            is_packed = True
            confidence = max(confidence, 0.70)
            anomaly_score = max(anomaly_score, 0.8)
            reasons.append(
                "Dynamic loading stub pattern detected "
                "(LoadLibrary + GetProcAddress with minimal other imports)"
            )

        # Suspicious APIs
        if suspicious_found:
            sus_ratio = len(suspicious_found) / max(total_imports, 1)
            if sus_ratio > 0.5:
                confidence = max(confidence, 0.55)
                anomaly_score = max(anomaly_score, 0.6)
            reasons.append(
                f"{len(suspicious_found)} suspicious API(s): "
                f"{', '.join(suspicious_found[:8])}"
                + (f" (+{len(suspicious_found)-8} more)" if len(suspicious_found) > 8 else "")
            )

        # Very few DLLs
        if dll_count <= 2 and total_imports > 0:
            confidence = max(confidence, 0.45)
            reasons.append(f"Only {dll_count} DLL(s) imported")

        if not reasons:
            reasons.append(f"Import table appears normal ({total_imports} imports from {dll_count} DLLs)")

        # Build and store ImportAnalysis
        ctx.imports = ImportAnalysis(
            total_imports=total_imports,
            dll_count=dll_count,
            api_count=api_count,
            dlls=all_dlls,
            suspicious_apis=suspicious_found,
            has_dynamic_loading=has_dynamic_loading,
            anomaly_score=round(anomaly_score, 4),
            imports=import_infos,
        )

        duration = time.monotonic() - start
        logger.info(
            "iat_analysis_complete",
            total_imports=total_imports,
            dll_count=dll_count,
            suspicious_count=len(suspicious_found),
            is_packed=is_packed,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.IAT_ANALYSIS,
            is_packed=is_packed,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "total_imports": total_imports,
                "dll_count": dll_count,
                "suspicious_apis": suspicious_found,
                "has_dynamic_loading": has_dynamic_loading,
                "anomaly_score": round(anomaly_score, 4),
            },
            duration_seconds=round(duration, 6),
        )
