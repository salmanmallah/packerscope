"""Pydantic v2 data models for the PackerScope framework.

Every data structure exchanged between PackerScope subsystems is
represented as an immutable-by-default Pydantic ``BaseModel``.  This
guarantees runtime validation, clean JSON serialisation, and rich IDE
support via type annotations.

Design notes
------------
* All timestamps default to :func:`datetime.now` (local timezone).
* ``ConfigDict(frozen=False)`` is set on models that are mutated during
  the analysis pipeline; the rest default to Pydantic's standard
  (non-frozen) behaviour.
* Field descriptions are provided via ``Field(description=…)`` to
  power automatic JSON-Schema generation for API docs.

Example:
    >>> from packerscope.core.models import DetectionResult
    >>> from packerscope.core.enums import DetectionMethod
    >>> result = DetectionResult.empty("entropy_detector", DetectionMethod.ENTROPY)
    >>> result.is_packed
    False
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field

from packerscope.core.enums import (
    ConfidenceLevel,
    DetectionMethod,
    EntropyClass,
    PackerType,
)

__all__ = [
    "AnalysisReport",
    "DetectionResult",
    "EntryPointAnalysis",
    "EntropyResult",
    "FileMetadata",
    "ImportAnalysis",
    "ImportInfo",
    "PackerVerdict",
    "SectionEntropy",
    "SectionInfo",
    "SignatureMatch",
    "StructureAnalysis",
    "UnpackResult",
    "VerificationResult",
    "YARAMatch",
]


# ========================================================================
# Entropy Models
# ========================================================================


class SectionEntropy(BaseModel):
    """Shannon entropy measurement for a single PE section.

    Attributes:
        name: Section name (e.g. ``.text``, ``.rsrc``).
        entropy: Raw Shannon entropy value ``[0.0, 8.0]``.
        entropy_class: Qualitative tier derived from *entropy*.
        offset: File offset (bytes) to the start of the section.
        size: Raw size of the section on disk (bytes).
    """

    name: str = Field(
        ...,
        description="PE section name (e.g. '.text', '.rdata').",
    )
    entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Shannon entropy of section content [0.0, 8.0].",
    )
    entropy_class: EntropyClass = Field(
        ...,
        description="Qualitative entropy classification.",
    )
    offset: int = Field(
        ...,
        ge=0,
        description="File offset to the start of this section (bytes).",
    )
    size: int = Field(
        ...,
        ge=0,
        description="Raw (on-disk) size of this section (bytes).",
    )


class EntropyResult(BaseModel):
    """Aggregated entropy analysis spanning the entire PE file.

    Attributes:
        whole_file_entropy: Entropy computed over the raw file bytes.
        whole_file_class: Qualitative tier of the whole-file entropy.
        section_entropies: Per-section entropy breakdowns.
        max_section_entropy: Highest section entropy observed.
        min_section_entropy: Lowest section entropy observed.
        mean_section_entropy: Arithmetic mean of section entropies.
    """

    whole_file_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Shannon entropy of the entire file [0.0, 8.0].",
    )
    whole_file_class: EntropyClass = Field(
        ...,
        description="Qualitative entropy classification for the whole file.",
    )
    section_entropies: list[SectionEntropy] = Field(
        default_factory=list,
        description="Entropy measurements for each PE section.",
    )
    max_section_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Maximum entropy among all sections.",
    )
    min_section_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Minimum entropy among all sections.",
    )
    mean_section_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Arithmetic mean of section entropies.",
    )


# ========================================================================
# Section Models
# ========================================================================


class SectionInfo(BaseModel):
    """Detailed metadata for a single PE section header.

    Includes memory layout, permissions, entropy, and a computed
    ``is_rwx`` flag that fires when a section is simultaneously
    readable, writable, *and* executable — a strong packing indicator.

    Attributes:
        name: Section name string.
        virtual_address: RVA where the section is loaded in memory.
        virtual_size: Size of the section when loaded in memory (bytes).
        raw_size: Size of the section on disk (bytes).
        raw_offset: File offset to the raw section data (bytes).
        entropy: Shannon entropy of the section content.
        entropy_class: Qualitative entropy tier.
        is_executable: Section has the ``IMAGE_SCN_MEM_EXECUTE`` flag.
        is_writable: Section has the ``IMAGE_SCN_MEM_WRITE`` flag.
        is_readable: Section has the ``IMAGE_SCN_MEM_READ`` flag.
        is_rwx: ``True`` when the section is read + write + execute.
        flags: Human-readable list of section characteristic flags.
        size_ratio: Ratio of ``virtual_size`` to ``raw_size``.
    """

    name: str = Field(
        ...,
        description="Section name (e.g. '.text').",
    )
    virtual_address: int = Field(
        ...,
        ge=0,
        description="Relative Virtual Address where the section is mapped.",
    )
    virtual_size: int = Field(
        ...,
        ge=0,
        description="In-memory size of the section (bytes).",
    )
    raw_size: int = Field(
        ...,
        ge=0,
        description="On-disk size of the section (bytes).",
    )
    raw_offset: int = Field(
        ...,
        ge=0,
        description="File offset to the section data (bytes).",
    )
    entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Shannon entropy of the section content.",
    )
    entropy_class: EntropyClass = Field(
        ...,
        description="Qualitative entropy classification.",
    )
    is_executable: bool = Field(
        ...,
        description="True if the section has IMAGE_SCN_MEM_EXECUTE.",
    )
    is_writable: bool = Field(
        ...,
        description="True if the section has IMAGE_SCN_MEM_WRITE.",
    )
    is_readable: bool = Field(
        ...,
        description="True if the section has IMAGE_SCN_MEM_READ.",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Human-readable section characteristic flags.",
    )
    size_ratio: float = Field(
        ...,
        ge=0.0,
        description="Ratio of virtual_size to raw_size (inf when raw_size is 0).",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_rwx(self) -> bool:
        """``True`` when the section is simultaneously R + W + X.

        This combination is atypical for legitimate software and is a
        reliable packing indicator — packed stubs usually need to write
        decoded code into an executable region.
        """
        return self.is_readable and self.is_writable and self.is_executable


# ========================================================================
# Import Models
# ========================================================================


class ImportInfo(BaseModel):
    """Import descriptor for a single DLL.

    Attributes:
        dll_name: Name of the imported DLL (e.g. ``KERNEL32.dll``).
        functions: List of function names (or ordinals as strings)
            imported from this DLL.
    """

    dll_name: str = Field(
        ...,
        description="Imported DLL name (e.g. 'KERNEL32.dll').",
    )
    functions: list[str] = Field(
        default_factory=list,
        description="Function names imported from this DLL.",
    )


class ImportAnalysis(BaseModel):
    """Aggregate import-table analysis results.

    A sparse or suspicious IAT is a strong packing signal because
    packers typically resolve imports dynamically via
    ``GetProcAddress`` / ``LoadLibrary``.

    Attributes:
        total_imports: Total number of imported functions across all DLLs.
        dll_count: Number of distinct DLLs referenced.
        api_count: Alias for *total_imports* (for clarity in reports).
        dlls: Flat list of imported DLL names.
        suspicious_apis: APIs commonly associated with packing or
            runtime unpacking (e.g. ``VirtualAlloc``, ``VirtualProtect``).
        has_dynamic_loading: ``True`` when ``LoadLibrary`` /
            ``GetProcAddress`` are present.
        anomaly_score: Normalised score ``[0.0, 1.0]`` indicating how
            anomalous the import table is relative to legitimate software.
        imports: Per-DLL import descriptors.
    """

    total_imports: int = Field(
        ...,
        ge=0,
        description="Total number of imported functions.",
    )
    dll_count: int = Field(
        ...,
        ge=0,
        description="Number of distinct DLLs in the import table.",
    )
    api_count: int = Field(
        ...,
        ge=0,
        description="Total API functions imported (same as total_imports).",
    )
    dlls: list[str] = Field(
        default_factory=list,
        description="Flat list of imported DLL names.",
    )
    suspicious_apis: list[str] = Field(
        default_factory=list,
        description="APIs commonly used for runtime unpacking.",
    )
    has_dynamic_loading: bool = Field(
        ...,
        description="True if LoadLibrary/GetProcAddress are imported.",
    )
    anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="IAT anomaly score [0.0, 1.0].",
    )
    imports: list[ImportInfo] = Field(
        default_factory=list,
        description="Per-DLL import descriptors.",
    )


# ========================================================================
# Entry-Point Models
# ========================================================================


class EntryPointAnalysis(BaseModel):
    """Analysis of the PE entry-point and surrounding code.

    Packers typically redirect the entry point into a stub that
    decompresses / decrypts the original code section before jumping
    to the Original Entry Point (OEP).

    Attributes:
        entry_point_rva: RVA of the ``AddressOfEntryPoint``.
        entry_point_section: Name of the section containing the EP.
        is_in_code_section: ``True`` when the EP resides in ``.text``
            or the first executable section.
        first_bytes_hex: Hex string of the first ≈ 64 bytes at the EP.
        stub_detected: Whether a known unpacking stub was recognised.
        stub_type: Name of the detected stub (``None`` if not detected).
        jump_chain_detected: ``True`` when sequential ``JMP`` instructions
            redirect control flow through multiple trampolines.
        nop_sled_detected: ``True`` when an unusually long NOP run
            precedes or follows the EP.
        disassembly: Disassembled mnemonics for the first *n*
            instructions at the EP.
    """

    entry_point_rva: int = Field(
        ...,
        ge=0,
        description="Relative virtual address of the entry point.",
    )
    entry_point_section: str = Field(
        ...,
        description="Name of the section that contains the entry point.",
    )
    is_in_code_section: bool = Field(
        ...,
        description="True if the EP is in the primary code section.",
    )
    first_bytes_hex: str = Field(
        ...,
        description="Hex-encoded first bytes at the entry point.",
    )
    stub_detected: bool = Field(
        ...,
        description="True if a known unpacking stub was detected.",
    )
    stub_type: str | None = Field(
        default=None,
        description="Detected stub type name, if any.",
    )
    jump_chain_detected: bool = Field(
        ...,
        description="True if sequential JMP chain was detected.",
    )
    nop_sled_detected: bool = Field(
        ...,
        description="True if an abnormal NOP sled was detected.",
    )
    disassembly: list[str] = Field(
        default_factory=list,
        description="Disassembled mnemonics at the entry point.",
    )


# ========================================================================
# Structure Analysis
# ========================================================================


class StructureAnalysis(BaseModel):
    """Deep structural inspection of PE headers and optional data directories.

    Covers overlays, TLS callbacks, relocations, resources, debug info,
    Authenticode certificates, checksum validity, and assorted header
    fields that may reveal packing or tampering.

    Attributes:
        has_overlay: ``True`` when data exists beyond the last section.
        overlay_size: Byte count of the overlay region.
        overlay_entropy: Entropy of the overlay (``None`` if absent).
        has_tls: ``True`` when a TLS directory is present.
        tls_callback_count: Number of TLS callback entries.
        has_relocations: ``True`` when a relocation table is present.
        relocation_count: Number of base-relocation entries.
        has_resources: ``True`` when a resource directory is present.
        resource_count: Number of resource entries.
        has_debug_info: ``True`` when a debug directory is present.
        has_certificates: ``True`` when Authenticode data is present.
        checksum_valid: ``True`` when the PE checksum matches the
            calculated value.
        pe_checksum: Checksum stored in the PE optional header.
        calculated_checksum: Freshly computed checksum.
        compile_timestamp: ``TimeDateStamp`` from the COFF header.
        compile_timestamp_valid: ``True`` if the timestamp is plausible
            (not in the future, not before 1990).
        linker_version: ``"<major>.<minor>"`` linker version string.
        is_dll: ``True`` for DLL images.
        is_64bit: ``True`` for PE32+ (64-bit) images.
        machine_type: Machine architecture string (e.g. ``"I386"``,
            ``"AMD64"``).
        subsystem: Windows subsystem string (e.g. ``"WINDOWS_GUI"``).
        image_base: Preferred base address.
        section_alignment: In-memory section alignment.
        file_alignment: On-disk section alignment.
        number_of_sections: Count of section headers.
        size_of_image: Total in-memory image size.
        size_of_headers: Combined size of DOS + PE + section headers.
        anomalies: Free-text list of detected structural anomalies.
    """

    has_overlay: bool = Field(
        ...,
        description="True if data exists after the last PE section.",
    )
    overlay_size: int = Field(
        ...,
        ge=0,
        description="Size of the overlay region (bytes).",
    )
    overlay_entropy: float | None = Field(
        default=None,
        description="Shannon entropy of the overlay, if present.",
    )
    has_tls: bool = Field(
        ...,
        description="True if a TLS directory exists.",
    )
    tls_callback_count: int = Field(
        ...,
        ge=0,
        description="Number of TLS callback entries.",
    )
    has_relocations: bool = Field(
        ...,
        description="True if a relocation table is present.",
    )
    relocation_count: int = Field(
        ...,
        ge=0,
        description="Number of base relocation entries.",
    )
    has_resources: bool = Field(
        ...,
        description="True if a resource directory is present.",
    )
    resource_count: int = Field(
        ...,
        ge=0,
        description="Number of resource entries.",
    )
    has_debug_info: bool = Field(
        ...,
        description="True if debug directory data is present.",
    )
    has_certificates: bool = Field(
        ...,
        description="True if Authenticode certificate data is present.",
    )
    checksum_valid: bool = Field(
        ...,
        description="True if PE checksum matches the computed value.",
    )
    pe_checksum: int = Field(
        ...,
        ge=0,
        description="Checksum value stored in the PE optional header.",
    )
    calculated_checksum: int = Field(
        ...,
        ge=0,
        description="Freshly computed PE checksum.",
    )
    compile_timestamp: datetime | None = Field(
        default=None,
        description="TimeDateStamp from the COFF file header.",
    )
    compile_timestamp_valid: bool = Field(
        ...,
        description="True if the compile timestamp appears plausible.",
    )
    linker_version: str = Field(
        ...,
        description="Linker version string '<major>.<minor>'.",
    )
    is_dll: bool = Field(
        ...,
        description="True if the image is a DLL.",
    )
    is_64bit: bool = Field(
        ...,
        description="True for PE32+ (64-bit) images.",
    )
    machine_type: str = Field(
        ...,
        description="Machine architecture (e.g. 'I386', 'AMD64').",
    )
    subsystem: str = Field(
        ...,
        description="Windows subsystem (e.g. 'WINDOWS_GUI').",
    )
    image_base: int = Field(
        ...,
        ge=0,
        description="Preferred image base address.",
    )
    section_alignment: int = Field(
        ...,
        ge=1,
        description="In-memory section alignment (bytes).",
    )
    file_alignment: int = Field(
        ...,
        ge=1,
        description="On-disk file alignment (bytes).",
    )
    number_of_sections: int = Field(
        ...,
        ge=0,
        description="Number of section headers.",
    )
    size_of_image: int = Field(
        ...,
        ge=0,
        description="Total in-memory image size (bytes).",
    )
    size_of_headers: int = Field(
        ...,
        ge=0,
        description="Combined size of all headers (bytes).",
    )
    anomalies: list[str] = Field(
        default_factory=list,
        description="Free-text descriptions of detected structural anomalies.",
    )


# ========================================================================
# Signature & YARA Models
# ========================================================================


class SignatureMatch(BaseModel):
    """A byte-pattern signature match (PEiD-style database lookup).

    Attributes:
        signature_name: Human-readable name of the matched signature.
        packer_name: Canonical packer name derived from the signature.
        offset: File offset where the match was found.
        database: Name / path of the signature database used.
        confidence: Confidence weight assigned to this match ``[0, 1]``.
        ep_only: ``True`` if the signature was applied only at the EP.
    """

    signature_name: str = Field(
        ...,
        description="Human-readable signature name.",
    )
    packer_name: str = Field(
        ...,
        description="Canonical packer name associated with the signature.",
    )
    offset: int = Field(
        ...,
        ge=0,
        description="File offset of the signature match (bytes).",
    )
    database: str = Field(
        ...,
        description="Signature database name or path.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for this match [0.0, 1.0].",
    )
    ep_only: bool = Field(
        ...,
        description="True if the signature applies only at the entry point.",
    )


class YARAMatch(BaseModel):
    """A YARA rule match against the target PE file.

    Attributes:
        rule_name: Name of the matching YARA rule.
        namespace: YARA namespace the rule belongs to.
        author: Rule author (from rule metadata), empty if unspecified.
        description: Rule description (from rule metadata).
        tags: Tags attached to the YARA rule.
        strings_matched: Details of each string/pattern that matched.
        confidence: Confidence weight assigned to this rule ``[0, 1]``.
    """

    rule_name: str = Field(
        ...,
        description="Name of the matching YARA rule.",
    )
    namespace: str = Field(
        ...,
        description="YARA namespace of the rule.",
    )
    author: str = Field(
        default="",
        description="Author of the YARA rule.",
    )
    description: str = Field(
        default="",
        description="Human-readable description of the YARA rule.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags associated with the YARA rule.",
    )
    strings_matched: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Details of matched strings/patterns.",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence weight for this YARA match [0.0, 1.0].",
    )


# ========================================================================
# Detection Result & Verdict
# ========================================================================


class DetectionResult(BaseModel):
    """Output produced by a single detector plug-in.

    Every detector in the pipeline emits one ``DetectionResult`` which
    the aggregation engine combines into a :class:`PackerVerdict`.

    Attributes:
        detector_name: Unique identifier of the detector that produced
            this result.
        method: The :class:`~packerscope.core.enums.DetectionMethod`
            employed.
        is_packed: Whether this detector considers the file packed.
        packer_hint: If a specific packer was recognised, its type.
        confidence: Confidence in this detector's decision ``[0, 1]``.
        reasons: Human-readable explanations of why the decision was made.
        details: Arbitrary key-value metadata emitted by the detector.
        duration_seconds: Wall-clock time consumed by this detector.
    """

    detector_name: str = Field(
        ...,
        description="Unique identifier of the detector.",
    )
    method: DetectionMethod = Field(
        ...,
        description="Detection method used by this detector.",
    )
    is_packed: bool = Field(
        default=False,
        description="True if this detector considers the file packed.",
    )
    packer_hint: PackerType = Field(
        default=PackerType.NONE,
        description="Specific packer type detected, if any.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this detection [0.0, 1.0].",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the detection decision.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary detector-specific metadata.",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock time consumed by this detector (seconds).",
    )

    @classmethod
    def empty(
        cls,
        detector_name: str,
        method: DetectionMethod,
    ) -> DetectionResult:
        """Create a *negative* (not-packed) placeholder result.

        Useful when a detector wants to report that it ran successfully
        but found no evidence of packing.

        Args:
            detector_name: Identifier for the detector.
            method: Detection method that was applied.

        Returns:
            A :class:`DetectionResult` with ``is_packed=False`` and
            zero confidence.

        Example:
            >>> result = DetectionResult.empty("entropy", DetectionMethod.ENTROPY)
            >>> result.is_packed
            False
        """
        return cls(
            detector_name=detector_name,
            method=method,
            is_packed=False,
            packer_hint=PackerType.NONE,
            confidence=0.0,
        )


class PackerVerdict(BaseModel):
    """Aggregated packing verdict produced by the decision engine.

    Combines evidence from all detector plug-ins into a single,
    confidence-weighted conclusion.

    Attributes:
        is_packed: Final decision — is the file packed?
        packer: Most likely packer family.
        confidence: Aggregate confidence ``[0, 1]``.
        confidence_level: Qualitative tier derived from *confidence*.
        reasons: Consolidated list of reasons across detectors.
        contributing_detectors: Mapping of ``detector_name → weight``
            for detectors that contributed to the verdict.
    """

    is_packed: bool = Field(
        ...,
        description="Final aggregated decision: is the file packed?",
    )
    packer: PackerType = Field(
        default=PackerType.NONE,
        description="Most likely packer family.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregate confidence score [0.0, 1.0].",
    )
    confidence_level: ConfidenceLevel = Field(
        default=ConfidenceLevel.NONE,
        description="Qualitative confidence tier.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Consolidated reasons from contributing detectors.",
    )
    contributing_detectors: dict[str, float] = Field(
        default_factory=dict,
        description="Detector name → confidence weight mapping.",
    )


# ========================================================================
# File Metadata
# ========================================================================


class FileMetadata(BaseModel):
    """Cryptographic hashes and basic file-level metadata.

    Attributes:
        md5: MD5 hex digest.
        sha1: SHA-1 hex digest.
        sha256: SHA-256 hex digest.
        imphash: PE import hash (pefile-computed).
        ssdeep: Context-triggered piecewise hash (ssdeep).
        file_size: Size of the file on disk (bytes).
        file_name: Base name of the file (no directory component).
        file_path: Full filesystem path to the analysed file.
        compile_timestamp: ``TimeDateStamp`` from the COFF header.
        machine_type: Machine architecture string.
        subsystem: Windows subsystem string.
    """

    md5: str = Field(
        ...,
        min_length=32,
        max_length=32,
        description="MD5 hex digest (32 hex chars).",
    )
    sha1: str = Field(
        ...,
        min_length=40,
        max_length=40,
        description="SHA-1 hex digest (40 hex chars).",
    )
    sha256: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hex digest (64 hex chars).",
    )
    imphash: str = Field(
        default="",
        description="PE import hash.",
    )
    ssdeep: str = Field(
        default="",
        description="Context-triggered piecewise hash (ssdeep).",
    )
    file_size: int = Field(
        ...,
        ge=0,
        description="File size in bytes.",
    )
    file_name: str = Field(
        ...,
        description="Base filename (no directory component).",
    )
    file_path: str = Field(
        ...,
        description="Absolute filesystem path to the file.",
    )
    compile_timestamp: datetime | None = Field(
        default=None,
        description="Compile timestamp from the COFF header.",
    )
    machine_type: str = Field(
        default="",
        description="Machine architecture (e.g. 'I386', 'AMD64').",
    )
    subsystem: str = Field(
        default="",
        description="Windows subsystem (e.g. 'WINDOWS_GUI').",
    )


# ========================================================================
# Unpack & Verification Models
# ========================================================================


class UnpackResult(BaseModel):
    """Outcome of an unpacking attempt.

    Attributes:
        success: ``True`` if unpacking completed without error.
        strategy_used: The :class:`~packerscope.core.enums.UnpackStrategy`
            value that succeeded (as a string).
        unpacked_path: Filesystem path to the unpacked PE on disk.
        error_message: Descriptive error if unpacking failed.
        duration_seconds: Wall-clock time of the unpack operation.
        unpacker_name: Name of the concrete unpacker implementation.
    """

    success: bool = Field(
        ...,
        description="True if unpacking succeeded.",
    )
    strategy_used: str = Field(
        default="",
        description="Unpacking strategy that was applied.",
    )
    unpacked_path: str = Field(
        default="",
        description="Path to the unpacked PE file, if successful.",
    )
    error_message: str = Field(
        default="",
        description="Error message if unpacking failed.",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock time of the unpack operation (seconds).",
    )
    unpacker_name: str = Field(
        default="",
        description="Name of the concrete unpacker implementation used.",
    )


class VerificationResult(BaseModel):
    """Post-unpack verification comparing the packed vs. unpacked PE.

    Runs a battery of checks (entropy reduction, IAT restoration,
    section normalisation) to confirm that unpacking was effective.

    Attributes:
        is_valid_pe: ``True`` if the unpacked file is a valid PE.
        entropy_reduced: ``True`` if overall entropy decreased.
        iat_restored: ``True`` if the import table grew after unpacking.
        sections_normal: ``True`` if section entropies normalised.
        original_entropy: Whole-file entropy of the packed PE.
        unpacked_entropy: Whole-file entropy of the unpacked PE.
        original_imports: Import count in the packed PE.
        unpacked_imports: Import count in the unpacked PE.
        comparison: Arbitrary comparison key-value data.
        checks_passed: Number of verification checks that passed.
        total_checks: Total number of verification checks run.
    """

    is_valid_pe: bool = Field(
        ...,
        description="True if the unpacked file is a valid PE.",
    )
    entropy_reduced: bool = Field(
        ...,
        description="True if entropy decreased after unpacking.",
    )
    iat_restored: bool = Field(
        ...,
        description="True if the IAT grew after unpacking.",
    )
    sections_normal: bool = Field(
        ...,
        description="True if section entropies normalised.",
    )
    original_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Whole-file entropy of the packed PE.",
    )
    unpacked_entropy: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Whole-file entropy of the unpacked PE.",
    )
    original_imports: int = Field(
        ...,
        ge=0,
        description="Number of imports in the packed PE.",
    )
    unpacked_imports: int = Field(
        ...,
        ge=0,
        description="Number of imports in the unpacked PE.",
    )
    comparison: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary comparison key-value data.",
    )
    checks_passed: int = Field(
        default=0,
        ge=0,
        description="Number of verification checks that passed.",
    )
    total_checks: int = Field(
        default=0,
        ge=0,
        description="Total number of verification checks executed.",
    )


# ========================================================================
# Top-Level Analysis Report
# ========================================================================


class AnalysisReport(BaseModel):
    """Complete analysis report for a single PE file.

    This is the top-level data structure returned by the PackerScope
    pipeline.  It aggregates every sub-analysis (entropy, sections,
    imports, entry-point, structure, signatures, YARA, detection
    results, verdict, unpacking, and verification) into a single
    serialisable object.

    Attributes:
        file_name: Base name of the analysed file.
        file_path: Absolute path to the analysed file.
        metadata: Cryptographic hashes and basic file-level metadata.
        verdict: Aggregated packing verdict.
        detections: Individual detector results.
        signatures: Byte-signature matches.
        yara_matches: YARA rule matches.
        entropy: Whole-file and per-section entropy results.
        sections: Per-section metadata.
        imports: IAT analysis.
        entrypoint: Entry-point analysis.
        structure: PE structural analysis.
        unpack_result: Unpacking outcome, if attempted.
        verification: Post-unpack verification, if applicable.
        analysis_duration_seconds: Total wall-clock analysis time.
        errors: Errors encountered during analysis.
        warnings: Non-fatal warnings generated during analysis.
        timestamp: When the analysis was performed.
        framework_version: PackerScope version string.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_name: str = Field(
        ...,
        description="Base name of the analysed file.",
    )
    file_path: str = Field(
        ...,
        description="Absolute filesystem path to the analysed file.",
    )
    metadata: FileMetadata = Field(
        ...,
        description="Cryptographic hashes and file-level metadata.",
    )
    verdict: PackerVerdict = Field(
        ...,
        description="Aggregated packing verdict.",
    )
    detections: list[DetectionResult] = Field(
        default_factory=list,
        description="Individual detector results.",
    )
    signatures: list[SignatureMatch] = Field(
        default_factory=list,
        description="Byte-signature matches.",
    )
    yara_matches: list[YARAMatch] = Field(
        default_factory=list,
        description="YARA rule matches.",
    )
    entropy: EntropyResult | None = Field(
        default=None,
        description="Whole-file and per-section entropy results.",
    )
    sections: list[SectionInfo] = Field(
        default_factory=list,
        description="Per-section metadata.",
    )
    imports: ImportAnalysis | None = Field(
        default=None,
        description="Import Address Table analysis.",
    )
    entrypoint: EntryPointAnalysis | None = Field(
        default=None,
        description="Entry-point analysis.",
    )
    structure: StructureAnalysis | None = Field(
        default=None,
        description="PE structural analysis.",
    )
    unpack_result: UnpackResult | None = Field(
        default=None,
        description="Unpacking outcome, if attempted.",
    )
    verification: VerificationResult | None = Field(
        default=None,
        description="Post-unpack verification result.",
    )
    analysis_duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Total wall-clock analysis time (seconds).",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered during analysis.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings from analysis.",
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the analysis was performed.",
    )
    framework_version: str = Field(
        default="0.1.0",
        description="PackerScope version string.",
    )
