"""Unit tests for PEContext shared blackboard."""

from __future__ import annotations

from pathlib import Path

import pytest

from packerscope.context import PEContext
from packerscope.core.enums import ConfidenceLevel, DetectionMethod, PackerType
from packerscope.core.models import AnalysisReport, DetectionResult, PackerVerdict


class TestPEContext:
    """Test suite for PEContext state management and reporting."""

    def test_context_missing_file_raises(self, tmp_path: Path):
        """Verify PEContext initialization raises FileNotFoundError if file is missing."""
        missing = tmp_path / "missing.exe"
        with pytest.raises(FileNotFoundError):
            PEContext(missing)

    def test_context_lifecycle_and_initialization(self, tmp_path: Path):
        """Verify context manager lifecycle and initialize() logic."""
        sample = tmp_path / "sample.exe"
        content = b"MZ" + b"\x00" * 200
        sample.write_bytes(content)

        with PEContext(sample) as ctx:
            assert ctx.file_path == sample.resolve()
            ctx.initialize()
            assert ctx.metadata is not None
            assert len(ctx.metadata.sha256) == 64
            assert ctx.raw_data == content

    def test_context_add_detection_and_build_report(self, tmp_path: Path):
        """Verify adding detections, errors, warnings, and building final report."""
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)

        with PEContext(sample) as ctx:
            ctx.initialize()
            det_result = DetectionResult(
                detector_name="test_detector",
                method=DetectionMethod.HEURISTIC,
                is_packed=True,
                confidence=0.85,
                packer_hint=PackerType.UPX,
                reasons=["Suspicious section names"],
            )
            ctx.add_detection("test_detector", det_result)
            ctx.add_error("Non-fatal test error")
            ctx.add_warning("Test warning")

            ctx.verdict = PackerVerdict(
                is_packed=True,
                packer=PackerType.UPX,
                confidence=0.85,
                confidence_level=ConfidenceLevel.HIGH,
                reasons=["Suspicious section names"],
            )

            report = ctx.build_report()
            assert isinstance(report, AnalysisReport)
            assert report.verdict.is_packed is True
            assert report.verdict.packer == PackerType.UPX
            assert "Non-fatal test error" in report.errors
            assert "Test warning" in report.warnings
