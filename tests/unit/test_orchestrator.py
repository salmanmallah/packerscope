"""Unit tests for the Orchestrator pipeline."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packerscope.config import Config
from packerscope.core.enums import ConfidenceLevel, PackerType, ReportFormat
from packerscope.core.models import AnalysisReport, PackerVerdict, UnpackResult
from packerscope.exceptions import FileTooLargeError
from packerscope.orchestrator import Orchestrator


class TestOrchestrator:
    """Test suite for Orchestrator initialization and analysis flow."""

    def test_orchestrator_initialization_idempotent(self):
        """Verify initialize() can be called multiple times safely."""
        config = Config()
        orch = Orchestrator(config)
        assert not orch._initialized

        orch.initialize()
        assert orch._initialized

        # Calling again should be a no-op
        orch.initialize()
        assert orch._initialized

    def test_orchestrator_initialization_thread_safe(self):
        """Verify initialize() is thread-safe under concurrent execution."""
        config = Config()
        orch = Orchestrator(config)

        def init_worker():
            orch.initialize()
            return orch._initialized

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(init_worker) for _ in range(16)]
            results = [f.result() for f in futures]

        assert all(results)
        assert orch._initialized

    def test_analyze_nonexistent_file(self, tmp_path: Path):
        """Verify analyze() raises FileNotFoundError for missing file."""
        orch = Orchestrator()
        missing_path = tmp_path / "does_not_exist.exe"

        with pytest.raises(FileNotFoundError):
            orch.analyze(missing_path)

    def test_analyze_oversized_file(self, tmp_path: Path):
        """Verify analyze() raises FileTooLargeError when file size exceeds limit."""
        config = Config(max_file_size=50)
        orch = Orchestrator(config)

        sample = tmp_path / "big_sample.exe"
        sample.write_bytes(b"A" * 100)

        with pytest.raises(FileTooLargeError) as exc_info:
            orch.analyze(sample)

        assert exc_info.value.file_size == 100
        assert exc_info.value.max_size == 50

    def test_analyze_invalid_pe(self, tmp_path: Path):
        """Verify analyze() handles invalid PE files without crashing."""
        config = Config()
        orch = Orchestrator(config)

        corrupt = tmp_path / "corrupt.exe"
        corrupt.write_bytes(b"NOT_A_PE_HEADER")

        report = orch.analyze(corrupt)
        assert isinstance(report, AnalysisReport)
        assert len(report.errors) > 0 or not report.verdict.is_packed

    def test_analyze_with_unpacking_disabled(self, temp_pe_file: Path):
        """Verify analyze() skips unpacking when enable_unpack is False."""
        config = Config(enable_unpack=False)
        orch = Orchestrator(config)

        report = orch.analyze(temp_pe_file)
        assert isinstance(report, AnalysisReport)
        assert report.unpack_result is None

    def test_batch_analyze(self, tmp_path: Path):
        """Verify analyze_batch processes multiple files concurrently."""
        config = Config()
        orch = Orchestrator(config)

        file1 = tmp_path / "f1.exe"
        file2 = tmp_path / "f2.exe"
        content = b"MZ" + b"\x00" * 200
        file1.write_bytes(content)
        file2.write_bytes(content)

        reports = orch.analyze_batch([file1, file2], max_workers=2)
        assert len(reports) == 2
        assert all(isinstance(r, AnalysisReport) for r in reports)
