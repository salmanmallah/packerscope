"""Unit tests for PackerScope unpackers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packerscope.context import PEContext
from packerscope.core.enums import PackerType, UnpackStrategy
from packerscope.core.models import UnpackResult
from packerscope.unpackers.dynamic_unpacker import DynamicUnpacker
from packerscope.unpackers.generic_unpacker import GenericStaticUnpacker
from packerscope.unpackers.upx_unpacker import UPXUnpacker


class TestUnpackers:
    """Test suite for unpacking engines."""

    def test_upx_unpacker_unavailable_handling(self, tmp_path: Path):
        """Verify UPXUnpacker gracefully fails when UPX is not installed."""
        unpacker = UPXUnpacker()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        output = tmp_path / "unpacked.exe"

        with patch.object(unpacker, "is_available", return_value=False):
            with PEContext(sample) as ctx:
                result = unpacker.unpack(ctx, output)
                assert not result.success
                assert "not found" in result.error_message.lower()

    @patch("subprocess.run")
    def test_upx_unpacker_success(self, mock_run, tmp_path: Path):
        """Verify UPXUnpacker handles successful UPX process return."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Unpacked 1 file."
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        unpacker = UPXUnpacker()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        output = tmp_path / "unpacked.exe"

        with patch.object(unpacker, "is_available", return_value=True):
            with PEContext(sample) as ctx:
                result = unpacker.unpack(ctx, output)
                assert result.success
                assert result.strategy_used == UnpackStrategy.NATIVE_TOOL.value
                assert result.unpacked_path == str(output)

    @patch("subprocess.run")
    def test_upx_unpacker_failure(self, mock_run, tmp_path: Path):
        """Verify UPXUnpacker handles subprocess failure properly."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "CantUnpackException: not packed by UPX"
        mock_run.return_value = mock_proc

        unpacker = UPXUnpacker()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        output = tmp_path / "unpacked.exe"

        with patch.object(unpacker, "is_available", return_value=True):
            with PEContext(sample) as ctx:
                result = unpacker.unpack(ctx, output)
                assert not result.success
                assert "CantUnpackException" in result.error_message

    def test_generic_static_unpacker_invalid_pe(self, tmp_path: Path):
        """Verify GenericStaticUnpacker rejects unparsed / invalid PE."""
        unpacker = GenericStaticUnpacker()
        sample = tmp_path / "invalid.exe"
        sample.write_bytes(b"NON_PE")
        output = tmp_path / "unpacked.exe"

        with PEContext(sample) as ctx:
            result = unpacker.unpack(ctx, output)
            assert not result.success
            assert "Invalid PE" in result.error_message

    def test_generic_static_unpacker_no_extractable_payload(self, tmp_path: Path):
        """Verify GenericStaticUnpacker returns false when no valid overlay/decompression exists."""
        unpacker = GenericStaticUnpacker()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        output = tmp_path / "unpacked.exe"

        with PEContext(sample) as ctx:
            ctx.pe = MagicMock()
            ctx.pe.is_valid = True
            ctx.pe.has_overlay = False

            result = unpacker.unpack(ctx, output)
            assert not result.success
            assert "no extractable payload" in result.error_message.lower()

    def test_dynamic_unpacker_not_implemented(self, tmp_path: Path):
        """Verify DynamicUnpacker returns appropriate status for placeholder."""
        unpacker = DynamicUnpacker()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        output = tmp_path / "unpacked.exe"

        with PEContext(sample) as ctx:
            result = unpacker.unpack(ctx, output)
            assert not result.success
            assert "backend" in result.error_message.lower() or "not" in result.error_message.lower()
