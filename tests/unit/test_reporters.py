"""Unit tests for PackerScope report generators."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packerscope.core.models import AnalysisReport
from packerscope.reporters.csv_reporter import CSVReporter
from packerscope.reporters.html_reporter import HTMLReporter
from packerscope.reporters.json_reporter import JSONReporter
from packerscope.reporters.markdown_reporter import MarkdownReporter


class TestReporters:
    """Test suite for JSON, CSV, Markdown, and HTML reporters."""

    def test_json_reporter_generates_valid_json(
        self, sample_analysis_report: AnalysisReport, tmp_path: Path
    ):
        """Verify JSONReporter outputs well-formed JSON."""
        reporter = JSONReporter()
        out_path = reporter.generate(sample_analysis_report, tmp_path)

        assert out_path.exists()
        assert out_path.suffix == ".json"

        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["file_name"] == "sample.exe"
        assert data["verdict"]["is_packed"] is True
        assert data["verdict"]["packer"] == "upx"

    def test_json_reporter_sanitizes_path_traversal(
        self, sample_analysis_report: AnalysisReport, tmp_path: Path
    ):
        """Verify JSONReporter sanitizes path traversal tokens in filename."""
        sample_analysis_report.file_name = "../../traversal_test.exe"
        reporter = JSONReporter()
        out_path = reporter.generate(sample_analysis_report, tmp_path)

        assert out_path.exists()
        # Must be contained directly inside tmp_path, not two directories up
        assert out_path.parent.resolve() == tmp_path.resolve()

    def test_csv_reporter_creates_and_appends(
        self, sample_analysis_report: AnalysisReport, tmp_path: Path
    ):
        """Verify CSVReporter creates header on first write and appends on subsequent writes."""
        reporter = CSVReporter()

        # First write
        out_path = reporter.generate(sample_analysis_report, tmp_path)
        assert out_path.exists()
        lines_1 = out_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines_1) == 2  # Header + 1 data row
        assert "file_name" in lines_1[0]
        assert "sample.exe" in lines_1[1]

        # Second write (append)
        reporter.generate(sample_analysis_report, tmp_path)
        lines_2 = out_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines_2) == 3  # Header + 2 data rows

    def test_markdown_reporter_generates_formatted_doc(
        self, sample_analysis_report: AnalysisReport, tmp_path: Path
    ):
        """Verify MarkdownReporter outputs structured markdown."""
        reporter = MarkdownReporter()
        out_path = reporter.generate(sample_analysis_report, tmp_path)

        assert out_path.exists()
        assert out_path.suffix == ".md"

        content = out_path.read_text(encoding="utf-8")
        assert "# PackerScope Analysis Report" in content
        assert "Verdict" in content
        assert "UPX" in content or "upx" in content

    def test_html_reporter_generates_styled_html(
        self, sample_analysis_report: AnalysisReport, tmp_path: Path
    ):
        """Verify HTMLReporter produces a valid HTML document."""
        reporter = HTMLReporter()
        out_path = reporter.generate(sample_analysis_report, tmp_path)

        assert out_path.exists()
        assert out_path.suffix == ".html"

        content = out_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "PACKED" in content
        assert "UPX" in content or "upx" in content
