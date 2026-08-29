"""Unit tests for PackerScope core enums and models."""

from __future__ import annotations

import pytest

from packerscope.core.enums import (
    ConfidenceLevel,
    DetectionMethod,
    EntropyClass,
    PackerType,
    ReportFormat,
    UnpackStrategy,
)
from packerscope.core.models import (
    AnalysisReport,
    DetectionResult,
    EntropyResult,
    FileMetadata,
    ImportAnalysis,
    ImportInfo,
    PackerVerdict,
    SectionEntropy,
    SectionInfo,
    SignatureMatch,
    UnpackResult,
    VerificationResult,
    YARAMatch,
)

# ── Enum Tests ─────────────────────────────────────────────────────────────

class TestPackerType:
    """Tests for PackerType enum."""

    def test_upx_is_str(self):
        assert isinstance(PackerType.UPX.value, str)

    def test_none_is_str(self):
        assert isinstance(PackerType.NONE.value, str)

    def test_all_variants_are_strings(self):
        for ptype in PackerType:
            assert isinstance(ptype.value, str)

    def test_comparison_with_string(self):
        # StrEnum auto() generates lowercase member names
        assert PackerType.UPX.value == PackerType.UPX


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum and from_score classmethod."""

    def test_from_score_zero_is_none(self):
        assert ConfidenceLevel.from_score(0.0) is ConfidenceLevel.NONE

    def test_from_score_low(self):
        assert ConfidenceLevel.from_score(0.30) is ConfidenceLevel.LOW

    def test_from_score_medium(self):
        assert ConfidenceLevel.from_score(0.55) is ConfidenceLevel.MEDIUM

    def test_from_score_high(self):
        assert ConfidenceLevel.from_score(0.75) is ConfidenceLevel.HIGH

    def test_from_score_very_high(self):
        assert ConfidenceLevel.from_score(0.95) is ConfidenceLevel.VERY_HIGH

    def test_from_score_one(self):
        assert ConfidenceLevel.from_score(1.0) is ConfidenceLevel.VERY_HIGH

    def test_from_score_invalid_raises(self):
        with pytest.raises(ValueError):
            ConfidenceLevel.from_score(1.5)


class TestEntropyClass:
    """Tests for EntropyClass enum."""

    def test_from_value_low(self):
        assert EntropyClass.from_value(2.0) is EntropyClass.LOW

    def test_from_value_very_high(self):
        assert EntropyClass.from_value(7.5) is EntropyClass.VERY_HIGH


# ── Model Tests ────────────────────────────────────────────────────────────

# Helper: valid hash strings for FileMetadata validation
_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestDetectionResult:
    """Tests for DetectionResult model."""

    def test_creation(self):
        result = DetectionResult(
            detector_name="test",
            method=DetectionMethod.ENTROPY,
            is_packed=True,
            confidence=0.85,
            reasons=["High entropy"],
        )
        assert result.is_packed
        assert result.confidence == 0.85
        assert result.detector_name == "test"

    def test_empty_factory(self):
        result = DetectionResult.empty("test", DetectionMethod.ENTROPY)
        assert not result.is_packed
        assert result.confidence == 0.0

    def test_default_packer_hint_is_none(self):
        result = DetectionResult(
            detector_name="test",
            method=DetectionMethod.ENTROPY,
            is_packed=False,
        )
        assert result.packer_hint == PackerType.NONE


class TestPackerVerdict:
    """Tests for PackerVerdict model."""

    def test_not_packed(self):
        v = PackerVerdict(is_packed=False)
        assert not v.is_packed
        assert v.packer == PackerType.NONE

    def test_packed_with_packer(self):
        v = PackerVerdict(
            is_packed=True,
            packer=PackerType.UPX,
            confidence=0.90,
            confidence_level=ConfidenceLevel.VERY_HIGH,
        )
        assert v.is_packed
        assert v.packer == PackerType.UPX


class TestFileMetadata:
    """Tests for FileMetadata model."""

    def test_creation(self):
        m = FileMetadata(
            md5=_MD5,
            sha1=_SHA1,
            sha256=_SHA256,
            file_size=1024,
            file_name="test.exe",
            file_path="/tmp/test.exe",
        )
        assert m.file_size == 1024
        assert m.file_name == "test.exe"

    def test_short_hash_rejected(self):
        with pytest.raises(ValueError):
            FileMetadata(
                md5="abc", sha1="def", sha256="ghi",
                file_size=100, file_name="test.exe", file_path="/tmp/test.exe",
            )


class TestAnalysisReport:
    """Tests for AnalysisReport model."""

    def test_minimal_report(self):
        report = AnalysisReport(
            file_name="test.exe",
            file_path="/tmp/test.exe",
            metadata=FileMetadata(
                md5=_MD5, sha1=_SHA1, sha256=_SHA256,
                file_size=100, file_name="test.exe", file_path="/tmp/test.exe",
            ),
            verdict=PackerVerdict(is_packed=False),
        )
        assert report.file_name == "test.exe"
        assert not report.verdict.is_packed
        assert not report.is_packed
        assert report.packer == "none"
        assert report.confidence == 0.0
        assert report.reasons == []
        summary = report.summary()
        assert summary["is_packed"] is False
        assert summary["packer"] == "none"
        assert summary["file_name"] == "test.exe"
        assert report.framework_version == "0.2.0"
