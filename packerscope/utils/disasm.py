"""Lightweight x86/x86-64 disassembly utilities for packer heuristics.

Uses the `Capstone <https://www.capstone-engine.org>`_ disassembly engine to
decode instructions and detect common packer entry-point patterns such as jump
chains, NOP sleds, and ``push … ret`` trampolines.

When Capstone is **not** installed the module degrades gracefully: all
detection methods return *false* / empty results and a warning is logged once.

Typical usage::

    from packerscope.utils.disasm import Disassembler, is_available

    if is_available():
        dis = Disassembler(is_64bit=False)
        insns = dis.disassemble(entry_bytes, address=0x00401000)
        if dis.detect_push_ret(entry_bytes, address=0x00401000):
            print("push/ret trampoline detected at entry point")
"""

from __future__ import annotations

from typing import NamedTuple

import structlog

__all__ = [
    "DisasmInstruction",
    "Disassembler",
    "is_available",
]

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Optional Capstone availability
# ---------------------------------------------------------------------------
_CAPSTONE_AVAILABLE: bool = False
try:
    import capstone as _cs

    _CAPSTONE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _cs = None  # type: ignore[assignment]

# A set of common jump mnemonics for heuristic matching.
_JUMP_MNEMONICS: frozenset[str] = frozenset(
    {
        "jmp",
        "je",
        "jne",
        "jz",
        "jnz",
        "ja",
        "jb",
        "jae",
        "jbe",
        "jg",
        "jl",
        "jge",
        "jle",
        "js",
        "jns",
        "jo",
        "jno",
        "jp",
        "jnp",
        "jcxz",
        "jecxz",
        "jrcxz",
        "loop",
        "loope",
        "loopne",
    }
)

# Known stub signatures: ``(pattern_name, mnemonic_sequence)``
_STUB_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    (
        "upx",
        (
            "pusha",
            "mov",
        ),
    ),
    (
        "upx_alt",
        (
            "pushad",
            "mov",
        ),
    ),
    ("aspack", ("pusha",)),
    ("aspack_alt", ("pushad",)),
    ("fsg", ("jmp",)),
    ("petite", ("mov", "push", "push", "call")),
    ("mew", ("push", "push", "push")),
    ("mpress", ("push", "call")),
    ("nspack", ("jmp",)),
    ("pecompact", ("push", "push", "call")),
    ("kkrunchy", ("push", "call")),
]


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


class DisasmInstruction(NamedTuple):
    """A single disassembled instruction.

    Attributes:
        address: Virtual address of the instruction.
        mnemonic: Instruction mnemonic (``mov``, ``jmp``, …).
        op_str: Operand string as formatted by Capstone.
        bytes_hex: Hex-encoded instruction bytes.
        size: Length of the instruction in bytes.
    """

    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int


# ---------------------------------------------------------------------------
# Module-level API
# ---------------------------------------------------------------------------


def is_available() -> bool:
    """Return ``True`` when the Capstone engine is importable."""
    return _CAPSTONE_AVAILABLE


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------


class Disassembler:
    """Thin wrapper around Capstone with packer-oriented heuristics.

    Args:
        is_64bit: Select x86-64 mode when ``True``, otherwise IA-32.
    """

    def __init__(self, is_64bit: bool = False) -> None:
        self._is_64bit = is_64bit
        self._md: object | None = None  # capstone.Cs instance

        if _CAPSTONE_AVAILABLE:
            mode = _cs.CS_MODE_64 if is_64bit else _cs.CS_MODE_32
            self._md = _cs.Cs(_cs.CS_ARCH_X86, mode)
            self._md.detail = False  # we only need mnemonics + operands
        else:
            logger.warning(
                "capstone_not_installed",
                hint="install with: pip install capstone",
            )

    def is_available(self) -> bool:
        """Return ``True`` when the Capstone engine is usable."""
        return _CAPSTONE_AVAILABLE and self._md is not None

    # ------------------------------------------------------------------
    # Core disassembly
    # ------------------------------------------------------------------

    def disassemble(
        self,
        data: bytes,
        address: int = 0,
        count: int = 20,
    ) -> list[DisasmInstruction]:
        """Disassemble up to *count* instructions from *data*.

        Args:
            data: Raw machine code bytes.
            address: Virtual address of the first byte in *data*.
            count: Maximum number of instructions to decode.

        Returns:
            List of :class:`DisasmInstruction` objects.  The list may be
            shorter than *count* if *data* is exhausted or if Capstone is
            unavailable (in which case an empty list is returned).
        """
        if not _CAPSTONE_AVAILABLE or self._md is None or not data:
            return []

        results: list[DisasmInstruction] = []
        for insn in self._md.disasm(data, address):
            results.append(
                DisasmInstruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes_hex=insn.bytes.hex(),
                    size=insn.size,
                )
            )
            if len(results) >= count:
                break
        return results

    # ------------------------------------------------------------------
    # Heuristic detectors
    # ------------------------------------------------------------------

    def detect_jump_chain(
        self,
        data: bytes,
        address: int = 0,
    ) -> bool:
        """Detect a chain of consecutive unconditional/conditional jumps.

        A *jump chain* (≥ 3 jumps in the first 10 instructions) is a common
        packer obfuscation to frustrate linear disassembly.

        Args:
            data: Raw machine code bytes at the entry point.
            address: Virtual address of the first byte.

        Returns:
            ``True`` when a jump chain is detected.
        """
        insns = self.disassemble(data, address, count=10)
        if not insns:
            return False

        consecutive = 0
        max_consecutive = 0
        for insn in insns:
            if insn.mnemonic in _JUMP_MNEMONICS:
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 0

        return max_consecutive >= 3

    def detect_nop_sled(
        self,
        data: bytes,
        threshold: int = 5,
    ) -> bool:
        """Detect a NOP sled — a run of *threshold* or more ``0x90`` bytes.

        NOP sleds may indicate alignment padding injected by a packer or
        shellcode payload.

        Args:
            data: Raw bytes to inspect (no disassembly needed).
            threshold: Minimum consecutive ``0x90`` bytes to qualify.

        Returns:
            ``True`` when a sled of at least *threshold* NOPs is found.
        """
        if not data or threshold < 1:
            return False

        nop_byte = 0x90
        consecutive = 0
        for b in data:
            if b == nop_byte:
                consecutive += 1
                if consecutive >= threshold:
                    return True
            else:
                consecutive = 0

        return False

    def detect_push_ret(
        self,
        data: bytes,
        address: int = 0,
    ) -> bool:
        """Detect a ``push <addr>; ret`` trampoline near the entry point.

        Many packers use this pair to transfer control to the unpacking stub
        without a direct ``jmp``.

        Args:
            data: Raw machine code bytes at the entry point.
            address: Virtual address of the first byte.

        Returns:
            ``True`` when a ``push … ; ret`` sequence is found within the
            first 10 decoded instructions.
        """
        insns = self.disassemble(data, address, count=10)
        if len(insns) < 2:
            return False

        for i in range(len(insns) - 1):
            if insns[i].mnemonic == "push" and insns[i + 1].mnemonic == "ret":
                return True

        return False

    def detect_stub_pattern(
        self,
        data: bytes,
        address: int = 0,
    ) -> str | None:
        """Attempt to identify a known packer stub by its mnemonic prologue.

        Compares the first decoded instructions against a library of known
        entry-point mnemonic sequences.

        Args:
            data: Raw machine code bytes at the entry point.
            address: Virtual address of the first byte.

        Returns:
            The name of the matching stub pattern (e.g. ``"upx"``), or
            ``None`` if no pattern matches.
        """
        insns = self.disassemble(data, address, count=15)
        if not insns:
            return None

        mnemonics = [i.mnemonic for i in insns]

        for name, pattern in _STUB_PATTERNS:
            pattern_len = len(pattern)
            if len(mnemonics) < pattern_len:
                continue
            if tuple(mnemonics[:pattern_len]) == pattern:
                logger.debug(
                    "stub_pattern_matched",
                    pattern=name,
                    address=hex(address),
                )
                return name

        return None
