"""JSON report generator for PackerScope."""

from __future__ import annotations

import json
from pathlib import Path

from packerscope.core.enums import ReportFormat
from packerscope.core.interfaces import BaseReporter
from packerscope.core.models import AnalysisReport
from packerscope.utils.logger import get_logger

logger = get_logger(__name__)


class JSONReporter(BaseReporter):
    """Generate analysis reports in JSON format."""

    name: str = "json"
    format: ReportFormat = ReportFormat.JSON

    def generate(self, report: AnalysisReport, output_dir: Path) -> Path:
        """Write the analysis report as a JSON file.

        Args:
            report: The complete analysis report.
            output_dir: Directory to write the report into.

        Returns:
            Path to the generated JSON file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{report.file_name}_{report.metadata.sha256[:12]}.json"
        output_path = output_dir / filename

        data = report.model_dump(mode="json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("json_report_generated", path=str(output_path))
        return output_path
