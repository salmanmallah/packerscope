"""PE structure anomaly detection for PackerScope.

Analyzes PE header fields, overlay data, TLS callbacks, relocations,
resources, certificates, and other structural elements for anomalies
that indicate packing, protection, or manipulation.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, StructureAnalysis
from packerscope.utils.entropy import calculate_entropy
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


class PEStructureDetector(BaseDetector):
    """Detect packing via PE structural anomalies.

    Examines headers, overlay, TLS, relocations, resources, timestamps,
    and checksums for signs of packing or protection.
    """

    name: str = "pe_structure"
    description: str = "Analyzes PE header and structure for anomalies"
    version: str = "1.0.0"
    priority: int = 50

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Analyze PE structure for anomalies.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with structural findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        anomalies: list[str] = []
        is_packed = False
        confidence = 0.0

        if not ctx.pe or not ctx.pe.is_valid:
            return DetectionResult.empty(self.name, DetectionMethod.PE_STRUCTURE)

        pe = ctx.pe

        # --- Overlay analysis ---
        has_overlay = pe.has_overlay
        overlay_size = 0
        overlay_entropy: float | None = None
        if has_overlay:
            overlay_data = pe.overlay_data
            if overlay_data:
                overlay_size = len(overlay_data)
                overlay_entropy = round(calculate_entropy(overlay_data), 4)
                if overlay_size > 4096:
                    anomalies.append(f"Large overlay: {overlay_size} bytes")
                    if overlay_entropy and overlay_entropy > 7.0:
                        anomalies.append(
                            f"High-entropy overlay ({overlay_entropy:.2f}) — "
                            "may contain encrypted payload"
                        )
                        confidence = max(confidence, 0.40)

        # --- TLS callbacks ---
        has_tls = pe.has_tls
        tls_count = 0
        if has_tls:
            try:
                tls_dir = pe.pe.DIRECTORY_ENTRY_TLS
                if hasattr(tls_dir, "struct"):
                    cb_start = tls_dir.struct.AddressOfCallBacks
                    if cb_start:
                        tls_count = 1  # At least one callback
                        anomalies.append(f"TLS callbacks present (anti-debug / unpacking)")
                        confidence = max(confidence, 0.30)
            except Exception:
                pass

        # --- Relocations ---
        has_relocs = pe.has_relocations
        reloc_count = 0
        if has_relocs:
            try:
                for entry in pe.pe.DIRECTORY_ENTRY_BASERELOC:
                    reloc_count += len(entry.entries)
            except Exception:
                pass

        # --- Resources ---
        has_resources = pe.has_resources
        resource_count = 0
        if has_resources:
            try:
                resource_count = self._count_resources(pe.pe)
            except Exception:
                pass

        # --- Debug info ---
        has_debug = pe.has_debug

        # --- Certificates ---
        has_certs = pe.has_certificates

        # --- Checksum ---
        pe_checksum = pe.checksum
        calc_checksum = pe.calculated_checksum
        checksum_valid = pe_checksum == calc_checksum or pe_checksum == 0

        if not checksum_valid and pe_checksum != 0:
            anomalies.append(
                f"Checksum mismatch: header={pe_checksum:#x}, "
                f"calculated={calc_checksum:#x}"
            )
            confidence = max(confidence, 0.20)

        # --- Timestamp analysis ---
        compile_ts = pe.compile_timestamp
        ts_valid = True
        if compile_ts:
            now = datetime.now(timezone.utc)
            year = compile_ts.year
            if year < 2000 or compile_ts > now.replace(year=now.year + 1):
                ts_valid = False
                anomalies.append(f"Suspicious compile timestamp: {compile_ts.isoformat()}")
                confidence = max(confidence, 0.25)
            # Check for zeroed timestamp
            if year == 1970:
                anomalies.append("Zeroed compile timestamp (epoch)")
                confidence = max(confidence, 0.20)
        else:
            ts_valid = False

        # --- Image/section sizes ---
        try:
            opt = pe.pe.OPTIONAL_HEADER
            section_alignment = opt.SectionAlignment
            file_alignment = opt.FileAlignment
            size_of_image = opt.SizeOfImage
            size_of_headers = opt.SizeOfHeaders
            image_base = opt.ImageBase

            # Check alignment is power of 2
            if section_alignment > 0 and (section_alignment & (section_alignment - 1)) != 0:
                anomalies.append(f"Non-power-of-2 section alignment: {section_alignment:#x}")
                confidence = max(confidence, 0.30)

            if file_alignment > 0 and (file_alignment & (file_alignment - 1)) != 0:
                anomalies.append(f"Non-power-of-2 file alignment: {file_alignment:#x}")
                confidence = max(confidence, 0.25)

            # Unusual image base
            if image_base == 0:
                anomalies.append("Image base is zero")
                confidence = max(confidence, 0.20)

        except Exception:
            section_alignment = 0x1000
            file_alignment = 0x200
            size_of_image = 0
            size_of_headers = 0
            image_base = 0

        # --- Number of sections ---
        num_sections = len(ctx.sections) if ctx.sections else 0

        # --- Determine packing from anomaly count ---
        if len(anomalies) >= 4:
            is_packed = True
            confidence = max(confidence, 0.55)
            reasons.append(f"{len(anomalies)} structural anomalies detected")
        elif len(anomalies) >= 2:
            confidence = max(confidence, 0.35)
            reasons.append(f"{len(anomalies)} structural anomalies detected")

        reasons.extend(anomalies)
        if not anomalies:
            reasons.append("PE structure appears normal")

        # --- Build and store StructureAnalysis ---
        is_64bit = pe.is_64bit
        ctx.structure = StructureAnalysis(
            has_overlay=has_overlay,
            overlay_size=overlay_size,
            overlay_entropy=overlay_entropy,
            has_tls=has_tls,
            tls_callback_count=tls_count,
            has_relocations=has_relocs,
            relocation_count=reloc_count,
            has_resources=has_resources,
            resource_count=resource_count,
            has_debug_info=has_debug,
            has_certificates=has_certs,
            checksum_valid=checksum_valid,
            pe_checksum=pe_checksum,
            calculated_checksum=calc_checksum,
            compile_timestamp=compile_ts,
            compile_timestamp_valid=ts_valid,
            linker_version=pe.linker_version,
            is_dll=bool(pe.pe.FILE_HEADER.Characteristics & 0x2000),
            is_64bit=is_64bit,
            machine_type=pe.machine_type,
            subsystem=pe.subsystem,
            image_base=image_base,
            section_alignment=section_alignment,
            file_alignment=file_alignment,
            number_of_sections=num_sections,
            size_of_image=size_of_image,
            size_of_headers=size_of_headers,
            anomalies=anomalies,
        )

        duration = time.monotonic() - start
        logger.info(
            "pe_structure_analysis_complete",
            anomaly_count=len(anomalies),
            is_packed=is_packed,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.PE_STRUCTURE,
            is_packed=is_packed,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "anomaly_count": len(anomalies),
                "has_overlay": has_overlay,
                "overlay_size": overlay_size,
                "has_tls": has_tls,
                "has_relocations": has_relocs,
                "checksum_valid": checksum_valid,
                "timestamp_valid": ts_valid,
            },
            duration_seconds=round(duration, 6),
        )

    @staticmethod
    def _count_resources(pe_obj) -> int:
        """Count total resource entries in the PE resource directory."""
        count = 0
        try:
            if hasattr(pe_obj, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe_obj.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(res_type, "directory"):
                        for res_id in res_type.directory.entries:
                            if hasattr(res_id, "directory"):
                                count += len(res_id.directory.entries)
                            else:
                                count += 1
                    else:
                        count += 1
        except Exception:
            pass
        return count
