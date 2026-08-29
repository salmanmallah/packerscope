"""Unit tests for UnpackVerifier."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packerscope.context import PEContext
from packerscope.core.models import EntropyResult, ImportAnalysis, VerificationResult
from packerscope.verification.verifier import UnpackVerifier


class TestUnpackVerifier:
    """Test suite for post-unpack verification checks."""

    def test_verify_invalid_pe_unpacked(self, tmp_path: Path):
        """Verify handling of invalid unpacked PE output."""
        sample = tmp_path / "original.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)

        unpacked = tmp_path / "corrupt_unpacked.exe"
        unpacked.write_bytes(b"CORRUPT_BYTES")

        verifier = UnpackVerifier()
        with PEContext(sample) as ctx:
            res = verifier.verify(ctx, unpacked)
            assert isinstance(res, VerificationResult)
            assert not res.is_valid_pe
            assert res.checks_passed == 0

    @patch("pefile.PE")
    @patch("packerscope.verification.verifier.calculate_entropy")
    def test_verify_valid_unpacked_success(self, mock_calc_entropy, mock_pe_class, tmp_path: Path):
        """Verify successful check evaluation when entropy is reduced and PE is valid."""
        mock_pe = MagicMock()
        mock_pe_class.return_value = mock_pe

        # Unpacked entropy lower than original
        mock_calc_entropy.return_value = 4.0

        sample = tmp_path / "original.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)

        unpacked = tmp_path / "unpacked.exe"
        unpacked.write_bytes(b"MZ" + b"\x00" * 200)

        verifier = UnpackVerifier()
        with PEContext(sample) as ctx:
            ctx.entropy = MagicMock(whole_file_entropy=7.5)
            ctx.imports = MagicMock(total_imports=2)

            res = verifier.verify(ctx, unpacked)
            assert res.is_valid_pe
            assert res.entropy_reduced
            assert res.checks_passed >= 2
