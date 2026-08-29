"""PackerScope — Automatic packer detection, classification, and unpacking framework.

Provides high-level programmatic entry points for binary analysis alongside
access to internal pipeline components.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packerscope.config import Config
from packerscope.core.enums import ConfidenceLevel, DetectionMethod, PackerType, ReportFormat
from packerscope.core.models import AnalysisReport, PackerVerdict
from packerscope.orchestrator import Orchestrator

try:
    __version__ = version("packerscope")
except PackageNotFoundError:
    __version__ = "0.2.0"
__author__ = "Salman Mallah"
__all__ = [
    "AnalysisReport",
    "ConfidenceLevel",
    "Config",
    "DetectionMethod",
    "Orchestrator",
    "PackerType",
    "PackerVerdict",
    "ReportFormat",
    "__author__",
    "__version__",
    "batch_scan",
    "detect",
    "scan",
]


def scan(
    target: str | Path,
    *,
    config: Config | None = None,
    unpack: bool = False,
    verbose: bool = False,
    output_dir: str | Path | None = None,
    formats: list[ReportFormat] | None = None,
) -> AnalysisReport:
    """Analyze a single Windows PE file for packer detection.

    Args:
        target: Path to the executable file to analyze.
        config: Optional pre-configured Config instance.
        unpack: If True, attempts unpacking when a supported packer is found.
        verbose: If True, enables detailed log output (INFO level).
        output_dir: Optional directory to store generated reports.
        formats: Optional list of report formats to generate.

    Returns:
        AnalysisReport instance containing verdict, detections, and metadata.

    Example:
        >>> import packerscope
        >>> result = packerscope.scan("sample.exe")
        >>> print(result.is_packed)
        >>> print(result.packer)
        >>> print(result.confidence)
    """
    from packerscope.utils.logger import setup_logging

    log_level = "INFO" if verbose else "WARNING"
    setup_logging(level=log_level)

    cfg = config.model_copy(deep=True) if config is not None else Config()
    if unpack:
        cfg.enable_unpack = True
    if output_dir:
        cfg.output_dir = Path(output_dir)
    if formats:
        cfg.report_formats = formats

    orchestrator = Orchestrator(config=cfg)
    return orchestrator.analyze(Path(target))


def detect(
    target: str | Path,
    *,
    config: Config | None = None,
    verbose: bool = False,
) -> AnalysisReport:
    """Convenience alias for :func:`scan` with unpacking disabled."""
    return scan(target, config=config, unpack=False, verbose=verbose)


def batch_scan(
    targets: list[str | Path] | str | Path,
    *,
    config: Config | None = None,
    workers: int | None = None,
    recursive: bool = True,
    unpack: bool = False,
    verbose: bool = False,
    output_dir: str | Path | None = None,
) -> list[AnalysisReport]:
    """Analyze multiple Windows PE files or a directory.

    Args:
        targets: Directory path, glob pattern, or list of file paths.
        config: Optional pre-configured Config instance.
        workers: Number of concurrent worker threads.
        recursive: If scanning a directory, search subdirectories recursively.
        unpack: If True, attempts unpacking for detected files.
        verbose: If True, enables detailed log output.
        output_dir: Optional directory to store generated reports.

    Returns:
        List of AnalysisReport instances.
    """
    from packerscope.utils.logger import setup_logging

    log_level = "INFO" if verbose else "WARNING"
    setup_logging(level=log_level)

    cfg = config.model_copy(deep=True) if config is not None else Config()
    if workers is not None:
        cfg.max_workers = workers
    if unpack:
        cfg.enable_unpack = True
    if output_dir:
        cfg.output_dir = Path(output_dir)

    # Resolve target paths
    file_paths: list[Path] = []
    if isinstance(targets, (str, Path)):
        p = Path(targets)
        if p.is_dir():
            pattern = "**/*" if recursive else "*"
            file_paths = [f for f in p.glob(pattern) if f.is_file()]
        elif p.is_file():
            file_paths = [p]
        else:
            parent = p.parent if p.parent.exists() else Path(".")
            file_paths = [f for f in parent.glob(p.name) if f.is_file()]
    else:
        file_paths = [Path(t) for t in targets]

    orchestrator = Orchestrator(config=cfg)
    return orchestrator.analyze_batch(file_paths, max_workers=workers)
