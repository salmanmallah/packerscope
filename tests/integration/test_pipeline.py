"""Integration tests for PackerScope orchestrator and CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from packerscope.cli import main
from packerscope.config import Config
from packerscope.orchestrator import Orchestrator


@pytest.fixture
def mock_pe_file(tmp_path):
    """Create a dummy file that passes pefile's very basic structure checks."""
    # This is a tiny, valid-enough DOS header to satisfy pefile
    # MZ... \x00\x00\x00\x00\x00\x00\x00\x00... PE\0\0
    pe_data = (
        b"MZ"
        + b"\x00" * 58
        + b"\x40\x00\x00\x00"  # offset to PE
        + b"\x00" * 4
        + b"PE\x00\x00"  # PE signature
        + b"\x4c\x01"  # Machine (x86)
        + b"\x01\x00"  # Number of sections
        + b"\x00" * 12
        + b"\xe0\x00"  # Size of optional header
        + b"\x02\x01"  # Characteristics
        + b"\x0b\x01"  # Magic (PE32)
        + b"\x00" * 224  # Rest of optional header
        + b".text\x00\x00\x00"  # Section name
        + b"\x00\x10\x00\x00"  # Virtual Size
        + b"\x00\x10\x00\x00"  # Virtual Address
        + b"\x00\x10\x00\x00"  # Size of raw data
        + b"\x00\x02\x00\x00"  # Pointer to raw data
        + b"\x00" * 12
        + b"\x20\x00\x00\x60"  # Characteristics (RX)
        + b"\x00" * 4096  # Section data (empty/0-entropy)
    )
    test_file = tmp_path / "dummy.exe"
    test_file.write_bytes(pe_data)
    return test_file


class TestCLI:
    """Integration tests for the CLI."""

    def test_info_command(self, mock_pe_file):
        runner = CliRunner()
        result = runner.invoke(main, ["info", str(mock_pe_file)])
        assert result.exit_code == 0
        assert "dummy.exe" in result.output
        assert "MD5" in result.output
        assert "Size" in result.output

    def test_scan_command(self, mock_pe_file, tmp_path):
        runner = CliRunner()
        out_dir = tmp_path / "reports"
        out_dir.mkdir()
        result = runner.invoke(main, ["scan", str(mock_pe_file), "--output", str(out_dir)])
        assert result.exit_code == 0
        assert "NOT PACKED" in result.output

    def test_batch_command(self, mock_pe_file, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["batch", str(mock_pe_file.parent)])
        assert result.exit_code == 0
        assert "Batch Analysis Results" in result.output
        assert "dummy.exe" in result.output


class TestOrchestrator:
    """Integration tests for the Orchestrator."""

    def test_pipeline_execution(self, mock_pe_file, tmp_path):
        config = Config(output_dir=tmp_path)
        config.report_formats = []  # Don't generate reports for tests
        orch = Orchestrator(config)
        orch.initialize()

        report = orch.analyze(mock_pe_file)
        assert report.file_name == "dummy.exe"
        assert not report.verdict.is_packed
        assert report.analysis_duration_seconds >= 0.0
