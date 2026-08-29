"""Unit tests for PackerScope PluginManager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packerscope.config import Config
from packerscope.core.enums import PackerType, ReportFormat
from packerscope.plugin_manager import PluginManager


class TestPluginManager:
    """Test suite for plugin discovery and registration."""

    def test_builtin_plugins_discovery(self):
        """Verify built-in detectors, unpackers, and reporters are registered."""
        config = Config()
        pm = PluginManager(config)
        pm.discover_plugins()

        detectors = pm.get_detectors()
        assert len(detectors) >= 6  # Entropy, Section, IAT, EntryPoint, Structure, Heuristic, etc.

        # Verify priority sorting (lower numerical priority runs first)
        priorities = [d.priority for d in detectors]
        assert priorities == sorted(priorities)

    def test_get_unpackers_for_packer(self):
        """Verify unpacker lookup by PackerType."""
        config = Config()
        pm = PluginManager(config)
        pm.discover_plugins()

        generic_unpackers = pm.get_unpackers_for(PackerType.GENERIC_PACKED)
        assert len(generic_unpackers) >= 1
        assert any(u.name == "generic_static" for u in generic_unpackers)

        # Mock UPX binary availability
        with patch("shutil.which", return_value="/usr/bin/upx"):
            upx_unpackers = pm.get_unpackers_for(PackerType.UPX)
            assert len(upx_unpackers) >= 1
            assert any(u.name == "upx_native" for u in upx_unpackers)

    def test_get_reporters(self):
        """Verify reporters for all supported formats are available."""
        config = Config()
        pm = PluginManager(config)
        pm.discover_plugins()

        for fmt in [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.MARKDOWN, ReportFormat.HTML]:
            reporter = pm.get_reporter(fmt)
            assert reporter is not None
            assert reporter.format == fmt

    def test_get_verifier(self):
        """Verify unpack verification engine is registered."""
        config = Config()
        pm = PluginManager(config)
        pm.discover_plugins()

        verifier = pm.get_verifier()
        assert verifier is not None
