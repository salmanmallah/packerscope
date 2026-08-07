"""PackerScope constants — thresholds, known signatures, API lists, and default configuration.

This module centralises every magic number, threshold, and lookup table used
across the framework so that detector / unpacker modules never contain
hard-coded literals.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Section-name → packer mapping
# ---------------------------------------------------------------------------

SUSPICIOUS_SECTION_NAMES: Final[dict[str, list[str]]] = {
    "UPX": ["UPX0", "UPX1", "UPX2", "UPX!", ".UPX0", ".UPX1"],
    "ASPack": [".aspack", ".adata", ".ASPack"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2", ".VMProtect"],
    "MPRESS": [".MPRESS1", ".MPRESS2"],
    "Themida": [".themida", ".Themida"],
    "PECompact": [".pec", ".pec1", ".pec2", "PEC2"],
    "FSG": [".fsg", "FSG!"],
    "MEW": [".mew", "MEW"],
    "NSPack": [".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1"],
    "Petite": [".petite"],
    "UPack": [".Upack", ".ByDwing"],
    "Armadillo": [".text1", ".adata", "ADATA"],
    "Enigma": [".enigma1", ".enigma2"],
    "MoleBox": [".mbox", ".mole"],
    "Obsidium": [".obsi"],
}
"""Maps packer family names to their characteristic PE section names."""

# Reverse lookup: section name → set of packer families (built once at import)
SECTION_TO_PACKERS: Final[dict[str, set[str]]] = {}
for _packer, _sections in SUSPICIOUS_SECTION_NAMES.items():
    for _sec in _sections:
        SECTION_TO_PACKERS.setdefault(_sec, set()).add(_packer)

# ---------------------------------------------------------------------------
# Suspicious Win32 / NT API imports
# ---------------------------------------------------------------------------

SUSPICIOUS_APIS: Final[list[str]] = [
    # Dynamic loading
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    # Memory manipulation
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualFree",
    # Thread / process injection
    "CreateThread",
    "CreateRemoteThread",
    "WriteProcessMemory",
    # NT-layer equivalents
    "NtProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    # Decompression / memory copy
    "RtlDecompressBuffer",
    "RtlMoveMemory",
    # Anti-debug
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    # Timing-based anti-analysis
    "GetTickCount",
    "QueryPerformanceCounter",
    # Exception-based control flow
    "SetUnhandledExceptionFilter",
]
"""Win32 / NT APIs frequently used by packers for dynamic loading, unpacking, and anti-debug."""

SUSPICIOUS_API_SET: Final[frozenset[str]] = frozenset(SUSPICIOUS_APIS)
"""Frozen set variant for O(1) membership tests."""

# ---------------------------------------------------------------------------
# Entropy thresholds (Shannon entropy, 0.0 – 8.0 for byte data)
# ---------------------------------------------------------------------------

ENTROPY_THRESHOLDS: Final[dict[str, tuple[float, float]]] = {
    "LOW": (0.0, 3.5),
    "MEDIUM": (3.5, 5.5),
    "HIGH": (5.5, 7.0),
    "VERY_HIGH": (7.0, 8.0),
}
"""Section-level entropy classification ranges.

Packed / encrypted sections typically fall in the HIGH or VERY_HIGH bands.
"""

# ---------------------------------------------------------------------------
# Detection confidence thresholds
# ---------------------------------------------------------------------------

CONFIDENCE_THRESHOLDS: Final[dict[str, tuple[float, float]]] = {
    "NONE": (0.0, 0.20),
    "LOW": (0.20, 0.40),
    "MEDIUM": (0.40, 0.65),
    "HIGH": (0.65, 0.85),
    "VERY_HIGH": (0.85, 1.0),
}
"""Confidence-level classification for aggregate detection scores (0.0 – 1.0)."""

# ---------------------------------------------------------------------------
# Default heuristic feature weights
# ---------------------------------------------------------------------------

DEFAULT_HEURISTIC_WEIGHTS: Final[dict[str, float]] = {
    "section_name_match": 0.25,
    "high_entropy": 0.20,
    "suspicious_imports": 0.15,
    "ep_in_non_standard_section": 0.10,
    "low_import_count": 0.08,
    "writable_code_section": 0.07,
    "section_size_mismatch": 0.05,
    "no_debug_directory": 0.04,
    "few_resources": 0.03,
    "non_standard_image_base": 0.03,
}
"""Default weights applied when combining heuristic signals into an aggregate score.

Weights should sum to 1.0.  Adjustable via configuration.
"""

# ---------------------------------------------------------------------------
# File-processing limits
# ---------------------------------------------------------------------------

MAX_FILE_SIZE: Final[int] = 100 * 1024 * 1024  # 100 MiB
"""Maximum PE file size the framework will process (bytes)."""

DEFAULT_EP_BYTES: Final[int] = 256
"""Number of bytes to read starting at the entry point for signature matching."""

DEFAULT_MAX_WORKERS: Final[int] = 4
"""Default thread-/process-pool size for parallel file scanning."""

# ---------------------------------------------------------------------------
# Misc constants
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS: Final[frozenset[str]] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".drv", ".ocx", ".cpl", ".efi",
})
"""File extensions treated as potential PE files."""

PE_SIGNATURE: Final[bytes] = b"MZ"
"""DOS header magic bytes for quick pre-validation."""
