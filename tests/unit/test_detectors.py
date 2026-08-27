"""Unit tests for PackerScope detectors."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

import pytest

from packerscope.core.enums import DetectionMethod, EntropyClass, PackerType
from packerscope.core.models import DetectionResult, EntropyResult, SectionEntropy, SectionInfo
from packerscope.detectors.entropy_detector import EntropyDetector
from packerscope.detectors.section_detector import SectionDetector
from packerscope.detectors.iat_detector import IATDetector
from packerscope.detectors.heuristic_detector import HeuristicDetector
from packerscope.signatures.peid_parser import PEiDParser


# ── Fixtures ───────────────────────────────────────────────────────────────

class MockSection:
    """Mock PE section for testing."""
    def __init__(self, name, vsize, rsize, entropy=5.0, chars=0x60000020):
        self.name = name
        self.virtual_address = 0x1000
        self.virtual_size = vsize
        self.raw_size = rsize
        self.raw_offset = 0x200
        self.characteristics = chars
        self.data = b"\x00" * min(rsize, 256)


class MockImport:
    """Mock import entry."""
    def __init__(self, dll_name, functions):
        self.dll_name = dll_name
        self.functions = functions


class MockPE:
    """Mock PEParser for testing detectors."""
    def __init__(self):
        self.is_valid = True
        self.is_64bit = False
        self.entry_point_rva = 0x1000
        self.entry_point_offset = 0x400
        self._sections = []
        self._imports = []

    @property
    def sections(self):
        return self._sections

    @property
    def imports(self):
        return self._imports

    def entry_point_data(self, size=256):
        return b"\x60\xE8\x00\x00\x00\x00" + b"\x00" * (size - 6)


def make_ctx(sections=None, imports=None, raw_data=None):
    """Create a mock PEContext for testing."""
    ctx = MagicMock()
    ctx.pe = MockPE()
    if sections:
        ctx.pe._sections = sections
    if imports:
        ctx.pe._imports = imports
    ctx.raw_data = raw_data or b"\x00" * 4096
    ctx.sections = []
    ctx.entropy = None
    ctx.imports = None
    ctx.entrypoint = None
    ctx.structure = None
    ctx.detection_results = {}
    ctx.signature_matches = []
    ctx.yara_matches = []
    ctx.verdict = None
    ctx.features = None
    ctx.file_path = Path("test.exe")
    ctx.get_detection = lambda name: ctx.detection_results.get(name)
    ctx.add_signature_match = lambda m: ctx.signature_matches.append(m)
    ctx.add_yara_match = lambda m: ctx.yara_matches.append(m)
    return ctx


# ── Entropy Detector Tests ────────────────────────────────────────────────

class TestEntropyDetector:
    """Tests for EntropyDetector."""

    def test_low_entropy_not_packed(self):
        # Uniform data = 0 entropy
        ctx = make_ctx(
            sections=[MockSection(".text", 4096, 4096)],
            raw_data=b"\x00" * 4096,
        )
        detector = EntropyDetector()
        result = detector.detect(ctx)
        assert not result.is_packed
        assert result.method == DetectionMethod.ENTROPY

    def test_high_entropy_packed(self):
        import os
        high_entropy_data = os.urandom(4096)
        ctx = make_ctx(
            sections=[MockSection(".text", 4096, 4096)],
            raw_data=high_entropy_data,
        )
        # Override section data
        ctx.pe._sections[0].data = high_entropy_data
        detector = EntropyDetector()
        result = detector.detect(ctx)
        assert result.is_packed
        assert result.confidence > 0.5

    def test_entropy_result_stored_in_context(self):
        ctx = make_ctx(
            sections=[MockSection(".text", 4096, 4096)],
            raw_data=b"\x00" * 4096,
        )
        detector = EntropyDetector()
        detector.detect(ctx)
        assert ctx.entropy is not None


# ── Section Detector Tests ─────────────────────────────────────────────────

class TestSectionDetector:
    """Tests for SectionDetector."""

    def test_normal_sections_not_packed(self):
        ctx = make_ctx()
        ctx.sections = [
            SectionInfo(
                name=".text", virtual_address=0x1000, virtual_size=4096,
                raw_size=4096, raw_offset=0x200, entropy=5.0,
                entropy_class=EntropyClass.MEDIUM,
                is_executable=True, is_writable=False, is_readable=True,
                is_rwx=False, flags=[], size_ratio=1.0,
            ),
        ]
        detector = SectionDetector()
        result = detector.detect(ctx)
        assert not result.is_packed

    def test_upx_section_names_detected(self):
        ctx = make_ctx()
        ctx.sections = [
            SectionInfo(
                name="UPX0", virtual_address=0x1000, virtual_size=65536,
                raw_size=0, raw_offset=0x200, entropy=0.0,
                entropy_class=EntropyClass.LOW,
                is_executable=True, is_writable=True, is_readable=True,
                is_rwx=True, flags=[], size_ratio=0.0,
            ),
            SectionInfo(
                name="UPX1", virtual_address=0x11000, virtual_size=4096,
                raw_size=4096, raw_offset=0x400, entropy=7.5,
                entropy_class=EntropyClass.VERY_HIGH,
                is_executable=True, is_writable=False, is_readable=True,
                is_rwx=False, flags=[], size_ratio=1.0,
            ),
        ]
        detector = SectionDetector()
        result = detector.detect(ctx)
        assert result.is_packed
        assert result.packer_hint == PackerType.UPX


# ── IAT Detector Tests ────────────────────────────────────────────────────

class TestIATDetector:
    """Tests for IATDetector."""

    def test_no_imports_is_packed(self):
        ctx = make_ctx(imports=[])
        detector = IATDetector()
        result = detector.detect(ctx)
        assert result.is_packed
        assert result.confidence >= 0.75

    def test_normal_imports_not_packed(self):
        funcs = [f"func_{i}" for i in range(100)]
        ctx = make_ctx(imports=[
            MockImport("kernel32.dll", funcs[:30]),
            MockImport("user32.dll", funcs[30:60]),
            MockImport("advapi32.dll", funcs[60:]),
        ])
        detector = IATDetector()
        result = detector.detect(ctx)
        assert not result.is_packed

    def test_tiny_iat_suspicious(self):
        ctx = make_ctx(imports=[
            MockImport("kernel32.dll", ["LoadLibraryA", "GetProcAddress"]),
        ])
        detector = IATDetector()
        result = detector.detect(ctx)
        assert result.is_packed


# ── PEiD Parser Tests ─────────────────────────────────────────────────────

class TestPEiDParser:
    """Tests for PEiD signature database parser."""

    def test_load_existing_database(self):
        db_path = Path(__file__).parent.parent.parent / "packerscope" / "signatures" / "peid_userdb.txt"
        if not db_path.exists():
            pytest.skip("PEiD database not found")
        parser = PEiDParser(db_path)
        sigs = parser.load()
        assert len(sigs) > 30  # We created 45+ signatures

    def test_load_nonexistent_returns_empty(self):
        parser = PEiDParser(Path("/nonexistent/file.txt"))
        sigs = parser.load()
        assert sigs == []

    def test_parse_pattern_basic(self):
        pattern = PEiDParser._parse_pattern("60 E8 00 00 00 00")
        assert pattern == [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00]

    def test_parse_pattern_wildcards(self):
        pattern = PEiDParser._parse_pattern("60 BE ?? ?? ?? ?? 8D")
        assert pattern == [0x60, 0xBE, None, None, None, None, 0x8D]

    def test_parse_pattern_invalid(self):
        pattern = PEiDParser._parse_pattern("ZZ XX")
        assert pattern == []


# ── Heuristic Detector Tests ──────────────────────────────────────────────

class TestHeuristicDetector:
    """Tests for HeuristicDetector."""

    def test_empty_context_not_packed(self):
        ctx = make_ctx()
        ctx.entropy = None
        ctx.imports = None
        ctx.structure = None
        ctx.entrypoint = None
        detector = HeuristicDetector()
        result = detector.detect(ctx)
        # With no data, should have very low confidence
        assert result.confidence < 0.5

    def test_multiple_signals_increase_confidence(self):
        ctx = make_ctx()
        ctx.entropy = EntropyResult(
            whole_file_entropy=7.5,
            whole_file_class=EntropyClass.VERY_HIGH,
            section_entropies=[
                SectionEntropy(name=".text", entropy=7.5, entropy_class=EntropyClass.VERY_HIGH, offset=0, size=4096),
                SectionEntropy(name=".data", entropy=7.6, entropy_class=EntropyClass.VERY_HIGH, offset=4096, size=4096),
            ],
            max_section_entropy=7.6,
            min_section_entropy=7.5,
            mean_section_entropy=7.55,
        )
        ctx.sections = []
        ctx.imports = None
        ctx.structure = None
        ctx.entrypoint = None
        ctx.detection_results = {
            "sections": DetectionResult(
                detector_name="sections",
                method=DetectionMethod.SECTION_ANALYSIS,
                is_packed=True,
                packer_hint=PackerType.UPX,
                confidence=0.9,
                reasons=["Known packer section UPX0"],
            ),
            "iat": DetectionResult(
                detector_name="iat",
                method=DetectionMethod.IAT_ANALYSIS,
                is_packed=True,
                confidence=0.8,
                reasons=["Tiny IAT"],
            ),
        }

        detector = HeuristicDetector()
        result = detector.detect(ctx)
        assert result.is_packed
        assert result.confidence > 0
