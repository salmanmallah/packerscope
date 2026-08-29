"""CSV report generator for PackerScope."""

from __future__ import annotations

import csv
from pathlib import Path

from packerscope.core.enums import ReportFormat
from packerscope.core.interfaces import BaseReporter
from packerscope.core.models import AnalysisReport
from packerscope.utils.logger import get_logger

logger = get_logger(__name__)

_CSV_HEADERS = [
    "file_name",
    "file_path",
    "md5",
    "sha256",
    "imphash",
    "is_packed",
    "packer",
    "confidence",
    "confidence_level",
    "whole_file_entropy",
    "section_count",
    "import_count",
    "has_overlay",
    "has_tls",
    "compile_timestamp",
    "unpack_success",
    "unpack_strategy",
    "analysis_duration_seconds",
]


class CSVReporter(BaseReporter):
    """Generate analysis reports in CSV format (one row per file).

    Useful for batch analysis results and spreadsheet import.
    """

    name: str = "csv"
    format: ReportFormat = ReportFormat.CSV

    def generate(self, report: AnalysisReport, output_dir: Path) -> Path:
        """Append the analysis result as a row to the CSV file.

        If the CSV file already exists, appends without a header row.
        If it doesn't exist, creates it with headers.

        Args:
            report: The complete analysis report.
            output_dir: Directory to write the report into.

        Returns:
            Path to the CSV file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "packerscope_results.csv"
        write_header = not output_path.exists()

        row = {
            "file_name": report.file_name,
            "file_path": report.file_path,
            "md5": report.metadata.md5,
            "sha256": report.metadata.sha256,
            "imphash": report.metadata.imphash,
            "is_packed": report.verdict.is_packed,
            "packer": report.verdict.packer.value,
            "confidence": round(report.verdict.confidence, 4),
            "confidence_level": report.verdict.confidence_level.value,
            "whole_file_entropy": (report.entropy.whole_file_entropy if report.entropy else ""),
            "section_count": len(report.sections),
            "import_count": report.imports.total_imports if report.imports else "",
            "has_overlay": (report.structure.has_overlay if report.structure else ""),
            "has_tls": report.structure.has_tls if report.structure else "",
            "compile_timestamp": (
                str(report.structure.compile_timestamp) if report.structure else ""
            ),
            "unpack_success": (report.unpack_result.success if report.unpack_result else ""),
            "unpack_strategy": (report.unpack_result.strategy_used if report.unpack_result else ""),
            "analysis_duration_seconds": round(report.analysis_duration_seconds, 3),
        }

        with open(output_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_HEADERS)
            if write_header:
                writer.writeheader()
            writer.writerow(row)

        logger.info("csv_report_updated", path=str(output_path))
        return output_path
