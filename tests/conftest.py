"""Shared pytest fixtures for PackerScope tests."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from packerscope.config import Config
from packerscope.context import PEContext
from packerscope.core.enums import ConfidenceLevel, EntropyClass, PackerType
from packerscope.core.models import (
    AnalysisReport,
    EntropyResult,
    EntryPointAnalysis,
    FileMetadata,
    ImportAnalysis,
    PackerVerdict,
    SectionInfo,
    StructureAnalysis,
)


@pytest.fixture
def temp_pe_file(tmp_path: Path) -> Path:
    """Create a minimal mock PE file on disk."""
    file_path = tmp_path / "sample.exe"
    # Write a dummy binary file
    content = (
        b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 200
    )
    file_path.write_bytes(content)
    return file_path


@pytest.fixture
def mock_config() -> Config:
    """Provide default Config for testing."""
    return Config()


@pytest.fixture
def sample_analysis_report() -> AnalysisReport:
    """Provide a full sample AnalysisReport instance."""
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    return AnalysisReport(
        file_name="sample.exe",
        file_path="C:/samples/sample.exe",
        metadata=FileMetadata(
            file_name="sample.exe",
            file_path="C:/samples/sample.exe",
            file_size=1024,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            imphash="1234567890abcdef1234567890abcdef",
        ),
        verdict=PackerVerdict(
            is_packed=True,
            packer=PackerType.UPX,
            confidence=0.95,
            confidence_level=ConfidenceLevel.VERY_HIGH,
            reasons=["High section entropy", "UPX signature match"],
            contributing_detectors={"entropy": 0.8, "signature": 1.0},
        ),
        entropy=EntropyResult(
            whole_file_entropy=7.8,
            whole_file_class=EntropyClass.VERY_HIGH,
            section_entropies=[],
            max_section_entropy=7.9,
            min_section_entropy=0.0,
            mean_section_entropy=3.95,
        ),
        sections=[
            SectionInfo(
                name="UPX0",
                virtual_address=0x1000,
                virtual_size=0x10000,
                raw_size=0,
                raw_offset=0x400,
                entropy=0.0,
                entropy_class=EntropyClass.LOW,
                is_executable=True,
                is_writable=True,
                is_readable=True,
                size_ratio=0.0,
            ),
            SectionInfo(
                name="UPX1",
                virtual_address=0x11000,
                virtual_size=0x8000,
                raw_size=0x8000,
                raw_offset=0x400,
                entropy=7.9,
                entropy_class=EntropyClass.VERY_HIGH,
                is_executable=True,
                is_writable=True,
                is_readable=True,
                size_ratio=1.0,
            ),
        ],
        analysis_duration_seconds=0.123,
    )
