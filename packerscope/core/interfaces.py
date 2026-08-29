"""Core abstract interfaces for PackerScope plugin system.

This module defines the abstract base classes that all detectors, unpackers,
reporters, and verifiers must implement. These interfaces form the plugin
contract — any class implementing these ABCs can be registered with the
PluginManager and used in the analysis pipeline.

Design Pattern: Strategy + Template Method
    Each interface defines a contract (detect/unpack/generate/verify) that
    concrete implementations fulfill. The Orchestrator selects and invokes
    implementations at runtime based on analysis state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packerscope.context import PEContext
    from packerscope.core.enums import PackerType, ReportFormat
    from packerscope.core.models import (
        AnalysisReport,
        DetectionResult,
        UnpackResult,
        VerificationResult,
    )


class BaseDetector(ABC):
    """Abstract base class for all packer detection modules.

    Each detector analyzes one specific aspect of a PE file and produces
    a DetectionResult indicating whether packing indicators were found.

    Detectors are executed in priority order (lower number = higher priority).
    Each detector receives the shared PEContext and can read results from
    previously executed detectors.

    Attributes:
        name: Unique identifier for this detector.
        description: Human-readable description of what this detector does.
        version: Semantic version string for this detector.
        priority: Execution order — lower values run earlier. Range: 1–999.
        enabled: Whether this detector is active. Can be toggled via config.

    Example:
        >>> class MyDetector(BaseDetector):
        ...     name = "my_detector"
        ...     description = "Detects MyPacker via header anomaly"
        ...     priority = 50
        ...
        ...     def detect(self, ctx: PEContext) -> DetectionResult:
        ...         # ... detection logic ...
        ...         return DetectionResult(...)
    """

    name: str = "base"
    description: str = ""
    version: str = "1.0.0"
    priority: int = 100
    enabled: bool = True

    @abstractmethod
    def detect(self, ctx: PEContext) -> DetectionResult:
        """Execute detection logic against the PE file.

        This method performs a single, focused analysis technique on the
        PE file contained in the context. It should read any needed prior
        results from `ctx.detection_results` and store its own findings.

        Args:
            ctx: Shared analysis context containing the parsed PE file,
                raw data, metadata, and results from previously executed
                detectors.

        Returns:
            A DetectionResult containing:
                - Whether packing was detected
                - Confidence score (0.0–1.0)
                - Packer type hint (if identifiable)
                - Human-readable reasons for the detection
                - Additional details as a dict

        Raises:
            DetectionError: If detection fails in an unrecoverable way.
                The orchestrator catches this and records it as an error
                in the analysis report without stopping the pipeline.
        """
        ...

    def is_available(self) -> bool:
        """Check if this detector's dependencies are available.

        Override this method to verify that optional dependencies
        (e.g., YARA library, ML model files, capstone) are installed
        and accessible.

        Returns:
            True if the detector can run, False if it should be skipped.
            Default implementation always returns True.
        """
        return True

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}(name={self.name!r}, "
            f"priority={self.priority}, enabled={self.enabled})>"
        )


class BaseUnpacker(ABC):
    """Abstract base class for all unpacking strategies.

    Each unpacker handles one or more packer types. The orchestrator
    queries ``can_handle()`` to find the right unpacker for a detected
    packer, then invokes ``unpack()`` to attempt extraction.

    Unpackers are tried in priority order. If the primary unpacker fails,
    the orchestrator falls back to the next available unpacker that
    supports the detected packer type.

    Attributes:
        name: Unique identifier for this unpacker.
        supported_packers: List of PackerType values this unpacker can handle.
        priority: Selection order — lower values are preferred.

    Example:
        >>> class MyUnpacker(BaseUnpacker):
        ...     name = "my_unpacker"
        ...     supported_packers = [PackerType.UPX]
        ...     priority = 10
        ...
        ...     def unpack(self, ctx, output_path):
        ...         # ... unpacking logic ...
        ...         return UnpackResult(success=True, ...)
    """

    name: str = "base"
    supported_packers: list[PackerType] = []
    priority: int = 100

    @abstractmethod
    def unpack(self, ctx: PEContext, output_path: Path) -> UnpackResult:
        """Attempt to unpack the PE file.

        Args:
            ctx: Analysis context with detection results. Contains the
                original file path, raw data, and packer verdict.
            output_path: File path where the unpacked PE should be written.

        Returns:
            UnpackResult indicating success/failure, the output path,
            the strategy used, and any error messages.

        Raises:
            UnpackError: If unpacking fails in an unrecoverable way.
        """
        ...

    def can_handle(self, packer: PackerType) -> bool:
        """Check if this unpacker supports the given packer type.

        Args:
            packer: The identified packer type from detection.

        Returns:
            True if this unpacker can attempt to unpack the given packer.
        """
        return packer in self.supported_packers

    def is_available(self) -> bool:
        """Check if required external tools are available.

        Override to verify that external tools (e.g., ``upx`` binary,
        debugger connections) are accessible.

        Returns:
            True if the unpacker can operate, False otherwise.
        """
        return True

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}(name={self.name!r}, "
            f"packers={[p.value for p in self.supported_packers]})>"
        )


class BaseReporter(ABC):
    """Abstract base class for report generators.

    Each reporter produces output in a specific format (JSON, CSV,
    Markdown, HTML). The orchestrator invokes all requested reporters
    after analysis completes.

    Attributes:
        format: The ReportFormat this reporter generates.

    Example:
        >>> class MyReporter(BaseReporter):
        ...     format = ReportFormat.JSON
        ...
        ...     def generate(self, report, output_path):
        ...         # ... write JSON report ...
        ...         return output_path / "report.json"
    """

    format: ReportFormat

    @abstractmethod
    def generate(self, report: AnalysisReport, output_path: Path) -> Path:
        """Generate a report file from analysis results.

        Args:
            report: Complete analysis report data containing all
                detection results, metadata, and verification info.
            output_path: Directory where the report file should be written.

        Returns:
            Path to the generated report file.

        Raises:
            IOError: If the report file cannot be written.
        """
        ...

    def generate_batch(self, reports: list[AnalysisReport], output_path: Path) -> Path:
        """Generate a batch report from multiple analysis results.

        Default implementation generates individual reports. Override
        for formats that benefit from aggregation (e.g., CSV).

        Args:
            reports: List of analysis reports to aggregate.
            output_path: Directory for the batch report file.

        Returns:
            Path to the generated batch report file.
        """
        # Default: generate individual reports
        paths = []
        for report in reports:
            path = self.generate(report, output_path)
            paths.append(path)
        return paths[-1] if paths else output_path

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(format={self.format.value})>"


class BaseVerifier(ABC):
    """Abstract base class for unpack verification.

    Verifiers compare the original packed PE with the unpacked result
    to determine if unpacking was successful. They check entropy
    reduction, IAT restoration, section normalization, and structural
    validity.

    Example:
        >>> class MyVerifier(BaseVerifier):
        ...     def verify(self, original_ctx, unpacked_path):
        ...         # ... compare packed vs unpacked ...
        ...         return VerificationResult(...)
    """

    @abstractmethod
    def verify(
        self,
        original_ctx: PEContext,
        unpacked_path: Path,
    ) -> VerificationResult:
        """Compare original packed PE with unpacked result.

        Performs multiple checks to determine if unpacking produced
        a valid, usable PE file with restored functionality.

        Args:
            original_ctx: Context from the packed file analysis,
                containing original entropy, imports, and structure.
            unpacked_path: Path to the unpacked PE file on disk.

        Returns:
            VerificationResult with comparison metrics including:
                - Whether the unpacked file is a valid PE
                - Whether entropy was reduced
                - Whether the IAT was restored
                - Whether sections appear normal
                - Detailed comparison data

        Raises:
            PEParseError: If the unpacked file cannot be parsed.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
