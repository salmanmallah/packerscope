"""Entry point analysis for PackerScope.

Analyzes the PE entry point for packer stub patterns. Packers insert
a small stub at the entry point that decompresses or decrypts the
original code, then jumps to the Original Entry Point (OEP). Common
patterns include PUSHAD/POPAD, jump chains, NOP sleds, and PUSH/RET.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult, EntryPointAnalysis
from packerscope.utils.disasm import Disassembler
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)

# Common packer entry point byte signatures (first 1-4 bytes)
_PACKER_STUBS = {
    b"\x60": "PUSHAD (common packer prologue)",
    b"\x9c": "PUSHFD (common packer prologue)",
    b"\x60\xe8": "PUSHAD + CALL (UPX/ASPack-style)",
    b"\x9c\x60": "PUSHFD + PUSHAD (packer prologue)",
    b"\xeb\x02": "Short JMP (Obsidium-style)",
    b"\xe8\x00\x00\x00\x00": "CALL $+5 (position-independent stub)",
}


class EntryPointDetector(BaseDetector):
    """Detect packing via entry point stub analysis.

    Disassembles the first instructions at the entry point and checks
    for patterns characteristic of packer stubs.
    """

    name: str = "entrypoint"
    description: str = "Analyzes entry point for packer stubs and anomalies"
    version: str = "1.0.0"
    priority: int = 40

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Analyze entry point bytes for packer indicators.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with entry point findings.
        """
        start = time.monotonic()
        reasons: list[str] = []
        is_packed = False
        confidence = 0.0
        stub_detected = False
        stub_type: str | None = None
        jump_chain = False
        nop_sled = False
        disasm_lines: list[str] = []

        if not ctx.pe or not ctx.pe.is_valid:
            return DetectionResult.empty(self.name, DetectionMethod.ENTRYPOINT_ANALYSIS)

        ep_rva = ctx.pe.entry_point_rva
        ep_data = ctx.pe.entry_point_data(256)

        # Determine EP section
        ep_section = self._find_ep_section(ctx)
        is_in_code = ep_section.lower() in (".text", "code", ".code", "text")

        # --- Raw byte pattern checks (always available) ---
        for pattern, desc in _PACKER_STUBS.items():
            if ep_data.startswith(pattern):
                stub_detected = True
                stub_type = desc
                is_packed = True
                confidence = max(confidence, 0.55)
                reasons.append(f"Entry point stub pattern: {desc}")
                break

        # --- Disassembly-based analysis (if capstone available) ---
        disasm = Disassembler(is_64bit=ctx.pe.is_64bit)
        if disasm.is_available():
            instructions = disasm.disassemble(ep_data, address=ep_rva, count=30)
            disasm_lines = [
                f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in instructions
            ]

            # Check for jump chains
            if disasm.detect_jump_chain(ep_data, address=ep_rva):
                jump_chain = True
                is_packed = True
                confidence = max(confidence, 0.50)
                reasons.append("Jump chain detected at entry point")

            # Check for NOP sleds
            if disasm.detect_nop_sled(ep_data, threshold=5):
                nop_sled = True
                confidence = max(confidence, 0.30)
                reasons.append("NOP sled detected near entry point")

            # Check for PUSH/RET pattern
            if disasm.detect_push_ret(ep_data, address=ep_rva):
                is_packed = True
                confidence = max(confidence, 0.55)
                reasons.append("PUSH/RET pattern detected (indirect jump)")

            # Check for known stub patterns
            detected = disasm.detect_stub_pattern(ep_data, address=ep_rva)
            if detected and not stub_detected:
                stub_detected = True
                stub_type = detected
                is_packed = True
                confidence = max(confidence, 0.60)
                reasons.append(f"Known packer stub: {detected}")
        else:
            reasons.append("Capstone not available — using byte-pattern fallback only")

        # --- EP location check ---
        if not is_in_code and ep_section:
            is_packed = True
            confidence = max(confidence, 0.45)
            reasons.append(
                f"Entry point in non-code section: '{ep_section}' "
                f"(expected .text)"
            )

        # --- EP at unusual offset ---
        if ctx.pe.is_valid:
            try:
                ep_offset = ctx.pe.entry_point_offset
                file_size = len(ctx.raw_data)
                if file_size > 0:
                    ep_ratio = ep_offset / file_size
                    if ep_ratio > 0.8:
                        confidence = max(confidence, 0.40)
                        reasons.append(
                            f"Entry point near end of file "
                            f"(offset ratio: {ep_ratio:.2%})"
                        )
            except Exception:
                pass

        if not reasons:
            reasons.append("Entry point appears normal")

        # Store analysis in context
        ctx.entrypoint = EntryPointAnalysis(
            entry_point_rva=ep_rva,
            entry_point_section=ep_section,
            is_in_code_section=is_in_code,
            first_bytes_hex=ep_data[:32].hex(),
            stub_detected=stub_detected,
            stub_type=stub_type,
            jump_chain_detected=jump_chain,
            nop_sled_detected=nop_sled,
            disassembly=disasm_lines[:20],
        )

        duration = time.monotonic() - start
        logger.info(
            "entrypoint_analysis_complete",
            ep_section=ep_section,
            stub_detected=stub_detected,
            is_packed=is_packed,
        )

        return DetectionResult(
            detector_name=self.name,
            method=DetectionMethod.ENTRYPOINT_ANALYSIS,
            is_packed=is_packed,
            confidence=round(confidence, 4),
            reasons=reasons,
            details={
                "ep_rva": hex(ep_rva),
                "ep_section": ep_section,
                "is_in_code_section": is_in_code,
                "stub_detected": stub_detected,
                "stub_type": stub_type,
                "first_bytes": ep_data[:16].hex(),
            },
            duration_seconds=round(duration, 6),
        )

    @staticmethod
    def _find_ep_section(ctx: PEContext) -> str:
        """Determine which section the entry point resides in."""
        if not ctx.pe or not ctx.pe.is_valid:
            return ""
        ep_rva = ctx.pe.entry_point_rva
        for sec in ctx.pe.sections:
            sec_start = sec.virtual_address
            sec_end = sec_start + sec.virtual_size
            if sec_start <= ep_rva < sec_end:
                return sec.name.strip().rstrip("\x00")
        return "<unknown>"
