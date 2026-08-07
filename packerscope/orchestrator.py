"""Pipeline orchestrator for PackerScope.

Controls the end-to-end analysis pipeline: PE loading → detection →
verdict → unpacking → verification → reporting. Also handles batch
processing with concurrent execution.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from packerscope.config import Config
from packerscope.context import PEContext
from packerscope.core.enums import ConfidenceLevel, PackerType, ReportFormat
from packerscope.core.models import AnalysisReport, PackerVerdict
from packerscope.exceptions import FileTooLargeError, PackerScopeError, PEParseError
from packerscope.plugin_manager import PluginManager
from packerscope.utils.concurrency import AnalysisPool
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class Orchestrator:
    """Pipeline controller for PackerScope analysis.

    Coordinates the complete analysis workflow for single files and
    batch processing. Manages detector execution order, unpacker
    selection, verification, and report generation.

    Example:
        >>> config = Config()
        >>> orch = Orchestrator(config)
        >>> report = orch.analyze(Path("sample.exe"))
        >>> print(report.verdict.packer)
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._plugin_manager = PluginManager(self._config)
        self._initialized = False

    def initialize(self) -> None:
        """Discover plugins and prepare for analysis."""
        if self._initialized:
            return
        self._config.ensure_directories()
        self._plugin_manager.discover_plugins()
        self._initialized = True
        logger.info("orchestrator_initialized")

    def analyze(self, file_path: Path) -> AnalysisReport:
        """Run the complete analysis pipeline on a single PE file.

        Args:
            file_path: Path to the PE file to analyze.

        Returns:
            Complete AnalysisReport with all findings.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            FileTooLargeError: If the file exceeds the configured size limit.
        """
        self.initialize()
        file_path = Path(file_path).resolve()

        logger.info("analysis_started", file=str(file_path))
        start = time.monotonic()

        # Validate file
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size
        if file_size > self._config.max_file_size:
            raise FileTooLargeError(file_size, self._config.max_file_size)

        # Create context
        with PEContext(file_path) as ctx:
            # Phase 1: Initialize — load PE, compute hashes
            pe_valid = ctx.initialize()

            if not pe_valid:
                logger.warning("invalid_pe", file=str(file_path), errors=ctx.errors)
                # Still generate a report with the errors
                report = ctx.build_report()
                report.analysis_duration_seconds = time.monotonic() - start
                return report

            # Phase 2: Detection pipeline
            self._run_detection_pipeline(ctx)

            # Phase 3: Determine verdict
            if ctx.verdict is None:
                ctx.verdict = self._build_fallback_verdict(ctx)

            # Phase 4: Unpacking (if enabled and packed)
            if self._config.enable_unpack and ctx.verdict.is_packed:
                self._run_unpacking(ctx)

            # Phase 5: Build and generate reports
            report = ctx.build_report()
            report.analysis_duration_seconds = time.monotonic() - start

            # Generate report files
            self._generate_reports(report)

            logger.info(
                "analysis_complete",
                file=file_path.name,
                is_packed=report.verdict.is_packed,
                packer=report.verdict.packer.value,
                confidence=round(report.verdict.confidence, 4),
                duration=round(report.analysis_duration_seconds, 3),
            )

            return report

    def analyze_batch(
        self,
        file_paths: list[Path],
        max_workers: int | None = None,
    ) -> list[AnalysisReport]:
        """Run analysis on multiple files concurrently.

        Args:
            file_paths: List of PE file paths.
            max_workers: Number of concurrent workers (default from config).

        Returns:
            List of AnalysisReport objects (one per file).
        """
        self.initialize()
        workers = max_workers or self._config.max_workers

        logger.info(
            "batch_analysis_started",
            file_count=len(file_paths),
            workers=workers,
        )

        pool = AnalysisPool(max_workers=workers)
        results = pool.map_analyze(file_paths, self.analyze)

        logger.info(
            "batch_analysis_complete",
            total=len(file_paths),
            successful=sum(1 for r in results if r is not None),
        )

        return [r for r in results if r is not None]

    def _run_detection_pipeline(self, ctx: PEContext) -> None:
        """Execute all detectors in priority order."""
        detectors = self._plugin_manager.get_detectors()

        for detector in detectors:
            try:
                logger.debug("running_detector", name=detector.name, priority=detector.priority)
                result = detector.detect(ctx)
                ctx.add_detection(detector.name, result)
            except Exception as e:
                error_msg = f"Detector '{detector.name}' failed: {e}"
                logger.error("detector_error", name=detector.name, error=str(e))
                ctx.add_error(error_msg)

    def _build_fallback_verdict(self, ctx: PEContext) -> PackerVerdict:
        """Build a verdict from detection results if HeuristicDetector didn't run."""
        is_packed = any(r.is_packed for r in ctx.detection_results.values())

        if not is_packed:
            return PackerVerdict(is_packed=False)

        # Aggregate packer hints
        packer_votes: dict[PackerType, float] = {}
        all_reasons: list[str] = []
        contributing: dict[str, float] = {}

        for name, result in ctx.detection_results.items():
            if result.is_packed:
                contributing[name] = result.confidence
                all_reasons.extend(result.reasons)
                if result.packer_hint not in (PackerType.NONE, PackerType.UNKNOWN):
                    p = result.packer_hint
                    packer_votes[p] = packer_votes.get(p, 0) + result.confidence

        packer = PackerType.GENERIC_PACKED
        if packer_votes:
            packer = max(packer_votes, key=packer_votes.get)  # type: ignore[arg-type]

        avg_confidence = (
            sum(contributing.values()) / len(contributing)
            if contributing
            else 0.0
        )

        return PackerVerdict(
            is_packed=True,
            packer=packer,
            confidence=round(min(avg_confidence, 1.0), 4),
            confidence_level=ConfidenceLevel.from_score(avg_confidence),
            reasons=all_reasons[:10],
            contributing_detectors=contributing,
        )

    def _run_unpacking(self, ctx: PEContext) -> None:
        """Attempt to unpack the PE file."""
        if ctx.verdict is None:
            return

        packer = ctx.verdict.packer
        unpackers = self._plugin_manager.get_unpackers_for(packer)

        if not unpackers:
            # Try generic unpackers
            unpackers = self._plugin_manager.get_unpackers_for(PackerType.GENERIC_PACKED)

        if not unpackers:
            ctx.add_warning(f"No unpacker available for {packer.value}")
            return

        output_dir = self._config.output_dir / "unpacked"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{ctx.file_path.stem}_unpacked{ctx.file_path.suffix}"

        for unpacker in unpackers:
            try:
                logger.info("unpacking_attempt", unpacker=unpacker.name, packer=packer.value)
                result = unpacker.unpack(ctx, output_path)
                ctx.unpack_result = result

                if result.success:
                    logger.info("unpack_success", unpacker=unpacker.name)

                    # Verify
                    if self._config.enable_verification:
                        verifier = self._plugin_manager.get_verifier()
                        if verifier:
                            ctx.verification = verifier.verify(ctx, Path(result.unpacked_path))
                    break
                else:
                    logger.warning(
                        "unpack_failed",
                        unpacker=unpacker.name,
                        error=result.error_message,
                    )
            except Exception as e:
                logger.error("unpack_error", unpacker=unpacker.name, error=str(e))
                ctx.add_error(f"Unpacker '{unpacker.name}' error: {e}")

    def _generate_reports(self, report: AnalysisReport) -> None:
        """Generate reports in all configured formats."""
        output_dir = self._config.output_dir / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in self._config.report_formats:
            reporter = self._plugin_manager.get_reporter(fmt)
            if reporter:
                try:
                    path = reporter.generate(report, output_dir)
                    logger.info("report_generated", format=fmt.value, path=str(path))
                except Exception as e:
                    logger.error("report_error", format=fmt.value, error=str(e))
