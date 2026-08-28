"""Unit tests for top-level PackerScope convenience API."""

from __future__ import annotations

from pathlib import Path

import pytest

import packerscope
from packerscope.core.models import AnalysisReport


@pytest.fixture
def sample_pe_file(tmp_path: Path) -> Path:
    """Create a minimal PE file fixture."""
    pe_data = (
        b"MZ" + b"\x00" * 58 +
        b"\x40\x00\x00\x00" +
        b"\x00" * 4 +
        b"PE\x00\x00" +
        b"\x4C\x01" +
        b"\x01\x00" +
        b"\x00" * 12 +
        b"\xE0\x00" +
        b"\x02\x01" +
        b"\x0B\x01" +
        b"\x00" * 224 +
        b".text\x00\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00" * 12 +
        b"\x20\x00\x00\x60" +
        b"\x00" * 4096
    )
    test_file = tmp_path / "sample.exe"
    test_file.write_bytes(pe_data)
    return test_file


class TestTopLevelAPI:
    """Tests for packerscope.scan, detect, and batch_scan."""

    def test_scan_function(self, sample_pe_file: Path) -> None:
        result = packerscope.scan(sample_pe_file)
        assert isinstance(result, AnalysisReport)
        assert result.file_name == "sample.exe"
        assert isinstance(result.is_packed, bool)
        assert isinstance(result.packer, str)
        assert isinstance(result.confidence, float)
        assert isinstance(result.reasons, list)

    def test_detect_alias(self, sample_pe_file: Path) -> None:
        result = packerscope.detect(sample_pe_file)
        assert isinstance(result, AnalysisReport)
        assert result.file_name == "sample.exe"

    def test_batch_scan_function(self, sample_pe_file: Path, tmp_path: Path) -> None:
        results = packerscope.batch_scan(tmp_path)
        assert len(results) >= 1
        assert results[0].file_name == "sample.exe"
