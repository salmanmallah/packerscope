"""Tests for PackerScope configuration and context."""

from __future__ import annotations

from pathlib import Path

import pytest

from packerscope.config import Config, HeuristicWeights, DetectorConfig, EntropyThresholds
from packerscope.core.enums import ReportFormat


class TestConfig:
    """Tests for Config class."""

    def test_default_values(self):
        config = Config()
        assert config.max_file_size == 100 * 1024 * 1024
        assert config.max_workers == 4
        assert config.enable_unpack is False
        assert config.enable_verification is True

    def test_max_workers_validation(self):
        config = Config(max_workers=0)
        assert config.max_workers == 1

        config = Config(max_workers=100)
        assert config.max_workers == 32

    def test_report_formats_default(self):
        config = Config()
        assert ReportFormat.JSON in config.report_formats

    def test_ensure_directories(self, tmp_path):
        config = Config(output_dir=tmp_path / "test_output")
        config.ensure_directories()
        assert (tmp_path / "test_output").exists()
        assert (tmp_path / "test_output" / "reports").exists()
        assert (tmp_path / "test_output" / "unpacked").exists()


class TestHeuristicWeights:
    """Tests for HeuristicWeights configuration."""

    def test_default_weights(self):
        w = HeuristicWeights()
        assert w.high_entropy == 25
        assert w.signature_match == 30

    def test_max_score_sum(self):
        w = HeuristicWeights()
        assert w.max_score > 0
        assert w.max_score == sum(
            getattr(w, f) for f in HeuristicWeights.model_fields
        )


class TestDetectorConfig:
    """Tests for DetectorConfig."""

    def test_all_enabled_by_default(self):
        dc = DetectorConfig()
        assert dc.entropy is True
        assert dc.sections is True
        assert dc.iat is True
        assert dc.entrypoint is True
        assert dc.pe_structure is True
        assert dc.signatures is True
        assert dc.yara is True
        assert dc.heuristic is True
