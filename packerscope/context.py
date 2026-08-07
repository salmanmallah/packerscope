"""PEContext — Shared analysis state object for the PackerScope pipeline.

The PEContext is the central data carrier flowing through the entire
detection pipeline. It holds:
    - The raw PE file data
    - The parsed PE object (via PEParser)
    - File metadata (hashes, size, timestamps)
    - Detection results from each detector
    - Aggregate verdict
    - Unpacking results
    - Verification results
    - Errors and warnings accumulated during analysis

Every detector reads from the context and writes its results back to it.
The orchestrator creates a PEContext at the start of analysis and passes
it through each stage.

Design Pattern: Blackboard
    The PEContext acts as a shared blackboard where independent knowledge
    sources (detectors) read and write information. This decouples
    detectors from each other — they communicate only through the context.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from packerscope.core.enums import (
    ConfidenceLevel,
    EntropyClass,
    PackerType,
)
from packerscope.core.models import (
    AnalysisReport,
    DetectionResult,
    EntryPointAnalysis,
    EntropyResult,
    FeatureVector,
    FileMetadata,
    ImportAnalysis,
    PackerVerdict,
    SectionInfo,
    SignatureMatch,
    StructureAnalysis,
    UnpackResult,
    VerificationResult,
    YARAMatch,
)
from packerscope.utils.hasher import FileHasher
from packerscope.utils.pe_parser import PEParser


class PEContext:
    """Shared analysis context for a single PE file.

    This object is created by the Orchestrator at the start of analysis
    and passed through every stage of the pipeline. Detectors read from
    it and write their results to it.

    Attributes:
        file_path: Path to the PE file being analyzed.
        raw_data: Raw bytes of the PE file.
        pe: PEParser wrapper for structured access.
        metadata: Computed file metadata (hashes, size, etc.).
        detection_results: Results from each detector, keyed by name.
        signature_matches: Byte-pattern signature matches.
        yara_matches: YARA rule matches.
        entropy: Entropy analysis results.
        sections: Parsed section information.
        imports: Import table analysis.
        entrypoint: Entry point analysis.
        structure: PE structure analysis.
        features: Extracted ML feature vector.
        verdict: Final packer verdict.
        unpack_result: Unpacking attempt results.
        verification: Post-unpack verification results.
        errors: Non-fatal errors encountered during analysis.
        warnings: Warnings generated during analysis.
        start_time: Timestamp when analysis began.

    Example:
        >>> ctx = PEContext(Path("sample.exe"))
        >>> ctx.initialize()
        >>> print(ctx.metadata.sha256)
        'a1b2c3...'
        >>> ctx.add_detection("entropy", result)
        >>> print(ctx.is_packed)
        True
    """

    def __init__(self, file_path: Path) -> None:
        """Initialize context with a file path.

        Args:
            file_path: Absolute path to the PE file to analyze.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        self.file_path: Path = file_path.resolve()
        if not self.file_path.exists():
            raise FileNotFoundError(f"PE file not found: {self.file_path}")

        self.raw_data: bytes = b""
        self.pe: PEParser | None = None
        self.metadata: FileMetadata | None = None

        # Detection results
        self.detection_results: dict[str, DetectionResult] = {}
        self.signature_matches: list[SignatureMatch] = []
        self.yara_matches: list[YARAMatch] = []

        # Analysis components
        self.entropy: EntropyResult | None = None
        self.sections: list[SectionInfo] = []
        self.imports: ImportAnalysis | None = None
        self.entrypoint: EntryPointAnalysis | None = None
        self.structure: StructureAnalysis | None = None
        self.features: FeatureVector | None = None

        # Verdict
        self.verdict: PackerVerdict | None = None

        # Unpacking
        self.unpack_result: UnpackResult | None = None
        self.verification: VerificationResult | None = None

        # Diagnostics
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.start_time: float = time.monotonic()

    def initialize(self) -> bool:
        """Load the PE file, compute hashes, and prepare for analysis.

        Reads the raw file data, parses the PE structure, and computes
        file hashes (MD5, SHA1, SHA256, imphash).

        Returns:
            True if initialization succeeded (valid PE), False otherwise.
            On failure, errors are recorded in ``self.errors``.
        """
        try:
            self.raw_data = self.file_path.read_bytes()
        except OSError as e:
            self.errors.append(f"Failed to read file: {e}")
            return False

        # Compute hashes
        hashes = FileHasher.compute_all(self.raw_data)

        # Parse PE
        self.pe = PEParser(self.file_path)
        try:
            self.pe.load()
        except Exception as e:
            self.errors.append(f"Failed to parse PE: {e}")
            # Still create metadata with hashes even if PE parsing fails
            self.metadata = FileMetadata(
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                file_size=len(self.raw_data),
                file_name=self.file_path.name,
                file_path=str(self.file_path),
            )
            return False

        # Compute imphash
        imphash = FileHasher.compute_imphash(self.pe.pe) if self.pe.is_valid else ""

        # Compute ssdeep
        ssdeep_hash = FileHasher.compute_ssdeep(self.raw_data)

        # Build metadata
        self.metadata = FileMetadata(
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            imphash=imphash,
            ssdeep=ssdeep_hash,
            file_size=len(self.raw_data),
            file_name=self.file_path.name,
            file_path=str(self.file_path),
            compile_timestamp=self.pe.compile_timestamp if self.pe.is_valid else None,
            machine_type=self.pe.machine_type if self.pe.is_valid else "",
            subsystem=self.pe.subsystem if self.pe.is_valid else "",
        )

        return self.pe.is_valid

    @property
    def is_valid_pe(self) -> bool:
        """Whether the file was successfully parsed as a valid PE."""
        return self.pe is not None and self.pe.is_valid

    @property
    def is_packed(self) -> bool:
        """Whether the current verdict indicates the file is packed.

        Returns False if no verdict has been determined yet.
        """
        if self.verdict is not None:
            return self.verdict.is_packed
        # Check if any detector flagged it as packed
        return any(r.is_packed for r in self.detection_results.values())

    @property
    def detected_packer(self) -> PackerType:
        """The identified packer type, or NONE if not determined."""
        if self.verdict is not None:
            return self.verdict.packer
        return PackerType.NONE

    @property
    def analysis_duration(self) -> float:
        """Elapsed time in seconds since analysis began."""
        return time.monotonic() - self.start_time

    def add_detection(self, name: str, result: DetectionResult) -> None:
        """Record a detection result from a detector.

        Args:
            name: The detector's unique name.
            result: The detection result to store.
        """
        self.detection_results[name] = result

    def get_detection(self, name: str) -> DetectionResult | None:
        """Retrieve a detection result by detector name.

        Args:
            name: The detector's unique name.

        Returns:
            The DetectionResult if found, None otherwise.
        """
        return self.detection_results.get(name)

    def add_signature_match(self, match: SignatureMatch) -> None:
        """Record a signature match.

        Args:
            match: The signature match to add.
        """
        self.signature_matches.append(match)

    def add_yara_match(self, match: YARAMatch) -> None:
        """Record a YARA rule match.

        Args:
            match: The YARA match to add.
        """
        self.yara_matches.append(match)

    def add_error(self, error: str) -> None:
        """Record a non-fatal error.

        Args:
            error: Human-readable error description.
        """
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Record a warning.

        Args:
            warning: Human-readable warning description.
        """
        self.warnings.append(warning)

    def build_report(self) -> AnalysisReport:
        """Compile all analysis data into a final AnalysisReport.

        Aggregates all detection results, metadata, and verification
        data into a single report model ready for serialization.

        Returns:
            Complete AnalysisReport with all accumulated data.
        """
        return AnalysisReport(
            file_name=self.file_path.name,
            file_path=str(self.file_path),
            metadata=self.metadata or FileMetadata(
                md5="",
                sha1="",
                sha256="",
                file_size=0,
                file_name=self.file_path.name,
                file_path=str(self.file_path),
            ),
            verdict=self.verdict or PackerVerdict(is_packed=False),
            detections=list(self.detection_results.values()),
            signatures=self.signature_matches,
            yara_matches=self.yara_matches,
            entropy=self.entropy,
            sections=self.sections,
            imports=self.imports,
            entrypoint=self.entrypoint,
            structure=self.structure,
            unpack_result=self.unpack_result,
            verification=self.verification,
            analysis_duration_seconds=self.analysis_duration,
            errors=self.errors,
            warnings=self.warnings,
            timestamp=datetime.now(),
        )

    def close(self) -> None:
        """Release resources held by the PE parser."""
        if self.pe is not None:
            self.pe.close()

    def __enter__(self) -> PEContext:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        packed_status = "packed" if self.is_packed else "not packed"
        packer = self.detected_packer.value
        return (
            f"<PEContext(file={self.file_path.name!r}, "
            f"status={packed_status}, packer={packer})>"
        )
