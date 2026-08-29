"""Enumeration types for the PackerScope framework.

Provides strongly-typed enumerations used throughout the framework for
packer classification, detection methods, confidence scoring, entropy
classification, unpacking strategies, report formats, and log levels.

All string-valued enums derive from :class:`~enum.StrEnum` (Python 3.11+)
so they serialise cleanly to JSON and can be compared directly against
plain strings when convenient.

Example:
    >>> from packerscope.core.enums import PackerType, ConfidenceLevel
    >>> packer = PackerType.UPX
    >>> packer == "upx"
    True
    >>> ConfidenceLevel.from_score(0.92)
    <ConfidenceLevel.VERY_HIGH: 'very_high'>
"""

from __future__ import annotations

try:
    from enum import StrEnum, auto
except ImportError:  # pragma: no cover (Python < 3.11 fallback)
    from enum import Enum, auto

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Python 3.10 compatibility fallback for StrEnum."""

        @staticmethod
        def _generate_next_value_(
            name: str, start: int, count: int, last_values: list[str]
        ) -> str:
            return name.lower()

        def __str__(self) -> str:
            return str(self.value)

__all__ = [
    "ConfidenceLevel",
    "DetectionMethod",
    "EntropyClass",
    "LogLevel",
    "PackerType",
    "ReportFormat",
    "UnpackStrategy",
]


# ---------------------------------------------------------------------------
# PackerType
# ---------------------------------------------------------------------------

class PackerType(StrEnum):
    """Known packer / protector families that PackerScope can identify.

    Members cover the most prevalent PE packers and protectors encountered
    in the wild, plus two meta-values:

    * ``GENERIC_PACKED`` — the file appears packed, but no specific family
      could be attributed.
    * ``UNKNOWN`` — analysis was inconclusive.
    * ``NONE`` — the file is *not* packed.
    """

    # --- Compressors ---
    UPX = auto()
    """Ultimate Packer for eXecutables — the most common open-source PE packer."""

    ASPACK = auto()
    """ASPack — a commercial Win32 executable compressor."""

    MPRESS = auto()
    """MPRESS — free PE/NET/MAC-OS-X compressor using LZMA / LZMAT."""

    FSG = auto()
    """Fast Small Good — legacy but still-seen PE compressor."""

    MEW = auto()
    """MEW — minimalist PE compressor by Northfox."""

    PECOMPACT = auto()
    """PECompact — commercial PE compressor by Bitsum Technologies."""

    NSPACK = auto()
    """NsPack / North Star PE packer."""

    PETITE = auto()
    """Petite — Win32 executable compressor by Ian Luck."""

    UPACK = auto()
    """UPack — PE compressor known for anti-analysis tricks."""

    WINUPACK = auto()
    """WinUPack — GUI front-end / variant of UPack."""

    MOLEBOX = auto()
    """MoleBox — virtualiser / packer that bundles files inside the PE."""

    # --- Protectors / Virtualisers ---
    THEMIDA = auto()
    """Themida / WinLicense — advanced code virtualiser by Oreans."""

    VMPROTECT = auto()
    """VMProtect — bytecode virtualiser with strong anti-debug."""

    ENIGMA = auto()
    """Enigma Protector — commercial software protection system."""

    ARMADILLO = auto()
    """Armadillo (Software Passport) — legacy commercial protector."""

    OBSIDIUM = auto()
    """Obsidium — code virtualiser and anti-tamper protector."""

    # --- Meta values ---
    GENERIC_PACKED = auto()
    """File appears packed but the specific family is undetermined."""

    UNKNOWN = auto()
    """Analysis was inconclusive — could not determine packing status."""

    NONE = auto()
    """File is not packed."""


# ---------------------------------------------------------------------------
# ConfidenceLevel
# ---------------------------------------------------------------------------

class ConfidenceLevel(StrEnum):
    """Qualitative confidence tiers derived from a ``[0.0, 1.0]`` score.

    Use :meth:`from_score` to convert a numeric confidence value into the
    appropriate tier.

    Mapping (inclusive boundaries):

    ==================  ==================
    Score range          Level
    ==================  ==================
    ``0.0``              NONE
    ``(0.0,  0.40]``     LOW
    ``(0.40, 0.65]``     MEDIUM
    ``(0.65, 0.85]``     HIGH
    ``(0.85, 1.00]``     VERY_HIGH
    ==================  ==================
    """

    NONE = auto()
    """No confidence — score is exactly 0.0."""

    LOW = auto()
    """Low confidence (score ≤ 0.40)."""

    MEDIUM = auto()
    """Medium confidence (0.40 < score ≤ 0.65)."""

    HIGH = auto()
    """High confidence (0.65 < score ≤ 0.85)."""

    VERY_HIGH = auto()
    """Very high confidence (score > 0.85)."""

    @classmethod
    def from_score(cls, score: float) -> ConfidenceLevel:
        """Map a numeric confidence score to a qualitative level.

        Args:
            score: A floating-point value in the range ``[0.0, 1.0]``.

        Returns:
            The :class:`ConfidenceLevel` corresponding to *score*.

        Raises:
            ValueError: If *score* is outside the ``[0.0, 1.0]`` range.

        Example:
            >>> ConfidenceLevel.from_score(0.72)
            <ConfidenceLevel.HIGH: 'high'>
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError(
                f"Confidence score must be in [0.0, 1.0], got {score!r}"
            )

        if score == 0.0:
            return cls.NONE
        if score <= 0.40:
            return cls.LOW
        if score <= 0.65:
            return cls.MEDIUM
        if score <= 0.85:
            return cls.HIGH
        return cls.VERY_HIGH


# ---------------------------------------------------------------------------
# DetectionMethod
# ---------------------------------------------------------------------------

class DetectionMethod(StrEnum):
    """Algorithmic families used by individual detector plug-ins.

    Each detector reports *which* detection method it applied so the
    aggregation engine can weight and de-duplicate overlapping evidence.
    """

    ENTROPY = auto()
    """Whole-file or per-section Shannon entropy analysis."""

    SECTION_ANALYSIS = auto()
    """Anomalous section attributes (name, size ratio, permissions)."""

    IAT_ANALYSIS = auto()
    """Import Address Table sparseness / suspicious API usage."""

    ENTRYPOINT_ANALYSIS = auto()
    """Entry-point location, stub patterns, and jump-chain detection."""

    SIGNATURE_SCAN = auto()
    """Byte-pattern / signature-database matching (PEiD-style)."""

    YARA_SCAN = auto()
    """YARA rule matching against file content."""

    PE_STRUCTURE = auto()
    """Structural anomalies in the PE optional/file headers."""

    HEURISTIC = auto()
    """Composite heuristics combining multiple lightweight signals."""


# ---------------------------------------------------------------------------
# EntropyClass
# ---------------------------------------------------------------------------

class EntropyClass(StrEnum):
    """Qualitative classification of Shannon entropy values.

    Shannon entropy for byte distributions ranges from 0.0 (perfectly
    uniform / all-zero) to 8.0 (maximally random).  Use :meth:`from_value`
    to convert a raw entropy float into one of these tiers.

    Mapping:

    ==================  ==================
    Entropy range        Class
    ==================  ==================
    ``[0.0, 3.5)``       LOW
    ``[3.5, 6.0)``       MEDIUM
    ``[6.0, 7.2)``       HIGH
    ``[7.2, 8.0]``       VERY_HIGH
    ==================  ==================
    """

    LOW = auto()
    """Low entropy (< 3.5) — likely plaintext, zero-padded, or sparse data."""

    MEDIUM = auto()
    """Medium entropy (3.5–6.0) — typical compiled code or structured data."""

    HIGH = auto()
    """High entropy (6.0–7.2) — possibly compressed or lightly encrypted."""

    VERY_HIGH = auto()
    """Very high entropy (≥ 7.2) — strongly suggests compression / encryption."""

    @classmethod
    def from_value(cls, entropy: float) -> EntropyClass:
        """Classify a raw Shannon-entropy measurement.

        Args:
            entropy: A floating-point Shannon entropy value in
                the range ``[0.0, 8.0]``.

        Returns:
            The :class:`EntropyClass` tier for *entropy*.

        Raises:
            ValueError: If *entropy* is outside ``[0.0, 8.0]``.

        Example:
            >>> EntropyClass.from_value(7.5)
            <EntropyClass.VERY_HIGH: 'very_high'>
        """
        if not 0.0 <= entropy <= 8.0:
            raise ValueError(
                f"Shannon entropy must be in [0.0, 8.0], got {entropy!r}"
            )

        if entropy < 3.5:
            return cls.LOW
        if entropy < 6.0:
            return cls.MEDIUM
        if entropy < 7.2:
            return cls.HIGH
        return cls.VERY_HIGH


# ---------------------------------------------------------------------------
# UnpackStrategy
# ---------------------------------------------------------------------------

class UnpackStrategy(StrEnum):
    """High-level strategies the unpacking pipeline can employ.

    Each concrete unpacker declares which strategy it implements so the
    orchestrator can select, prioritise, and fall back between them.
    """

    NATIVE_TOOL = auto()
    """Invoke the packer's own CLI tool (e.g. ``upx -d``)."""

    STATIC_DECOMPRESS = auto()
    """Statically decompress the payload using a known algorithm
    (e.g. aPLib, LZMA) without executing the PE."""

    DYNAMIC_DEBUG = auto()
    """Run the PE under a debugger, set breakpoints on OEP / VirtualAlloc,
    and dump the unpacked image from process memory."""

    DYNAMIC_EMULATE = auto()
    """Emulate the unpacking stub via a CPU emulator (e.g. Unicorn Engine)
    to recover the original payload without real execution."""

    PLUGIN = auto()
    """Delegate to an external / third-party unpacking plug-in."""


# ---------------------------------------------------------------------------
# ReportFormat
# ---------------------------------------------------------------------------

class ReportFormat(StrEnum):
    """Output formats supported by the reporting subsystem."""

    JSON = auto()
    """Structured JSON (default, machine-readable)."""

    CSV = auto()
    """Comma-separated values (batch / spreadsheet workflows)."""

    MARKDOWN = auto()
    """Markdown-formatted report (human-readable)."""

    HTML = auto()
    """Self-contained HTML report with styling."""


# ---------------------------------------------------------------------------
# LogLevel
# ---------------------------------------------------------------------------

class LogLevel(StrEnum):
    """Log severity levels aligned with Python's :mod:`logging` module.

    Provided as a convenience enum so configuration files and CLI flags
    can reference levels as plain strings.
    """

    DEBUG = auto()
    """Verbose diagnostic output."""

    INFO = auto()
    """Normal operational messages."""

    WARNING = auto()
    """Potential issues that do not prevent execution."""

    ERROR = auto()
    """Errors that affect individual operations but not the whole run."""

    CRITICAL = auto()
    """Fatal errors requiring immediate termination."""
