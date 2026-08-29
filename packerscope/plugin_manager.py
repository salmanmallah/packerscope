"""Plugin discovery and registration for PackerScope.

Discovers and registers detector, unpacker, and reporter plugins from:
1. Built-in modules (packerscope/detectors/, unpackers/, reporters/)
2. External plugin directories (plugins/)
3. Python entry points (pip-installed packages)
"""

from __future__ import annotations

import importlib
import importlib.metadata
from pathlib import Path
from typing import TYPE_CHECKING

from packerscope.core.enums import PackerType, ReportFormat
from packerscope.core.interfaces import BaseDetector, BaseReporter, BaseUnpacker, BaseVerifier
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.config import Config

logger = get_logger(__name__)


class PluginManager:
    """Discovers and manages detector, unpacker, and reporter plugins.

    Plugins are registered into typed registries and retrieved by the
    Orchestrator for pipeline execution.

    Example:
        >>> pm = PluginManager(config)
        >>> pm.discover_plugins()
        >>> detectors = pm.get_detectors()
        >>> unpackers = pm.get_unpackers_for(PackerType.UPX)
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config
        self._detectors: list[BaseDetector] = []
        self._unpackers: list[BaseUnpacker] = []
        self._reporters: list[BaseReporter] = []
        self._verifiers: list[BaseVerifier] = []

    def discover_plugins(self, extra_dirs: list[Path] | None = None) -> None:
        """Discover and register all available plugins.

        Args:
            extra_dirs: Additional directories to scan for plugin modules.
        """
        self._register_builtin_detectors()
        self._register_builtin_unpackers()
        self._register_builtin_reporters()
        self._register_builtin_verifiers()

        # Scan external plugin directories
        dirs = list(extra_dirs or [])
        if self._config and self._config.plugins_dir.exists():
            dirs.append(self._config.plugins_dir)
        for d in dirs:
            self._scan_plugin_dir(d)

        # Scan Python entry points
        self._scan_entry_points()

        logger.info(
            "plugins_discovered",
            detectors=len(self._detectors),
            unpackers=len(self._unpackers),
            reporters=len(self._reporters),
        )

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a detector plugin."""
        if not detector.is_available():
            logger.info("detector_unavailable", name=detector.name)
            return
        self._detectors.append(detector)
        logger.debug("detector_registered", name=detector.name, priority=detector.priority)

    def register_unpacker(self, unpacker: BaseUnpacker) -> None:
        """Register an unpacker plugin."""
        self._unpackers.append(unpacker)
        logger.debug("unpacker_registered", name=unpacker.name)

    def register_reporter(self, reporter: BaseReporter) -> None:
        """Register a reporter plugin."""
        self._reporters.append(reporter)
        logger.debug("reporter_registered", format=reporter.format.value)

    def register_verifier(self, verifier: BaseVerifier) -> None:
        """Register a verifier plugin."""
        self._verifiers.append(verifier)

    def get_detectors(self) -> list[BaseDetector]:
        """Get all registered detectors sorted by priority (ascending)."""
        return sorted(
            [d for d in self._detectors if d.enabled],
            key=lambda d: d.priority,
        )

    def get_unpackers_for(self, packer: PackerType) -> list[BaseUnpacker]:
        """Get unpackers that can handle the given packer type, sorted by priority."""
        return sorted(
            [u for u in self._unpackers if u.can_handle(packer) and u.is_available()],
            key=lambda u: u.priority,
        )

    def get_reporter(self, fmt: ReportFormat) -> BaseReporter | None:
        """Get the reporter for a specific format."""
        for r in self._reporters:
            if r.format == fmt:
                return r
        return None

    def get_verifier(self) -> BaseVerifier | None:
        """Get the first registered verifier."""
        return self._verifiers[0] if self._verifiers else None

    def _register_builtin_detectors(self) -> None:
        """Register all built-in detector modules."""
        from packerscope.detectors import ALL_DETECTORS

        det_config = self._config.detectors if self._config else None

        for detector_cls in ALL_DETECTORS:
            try:
                # Check config enable/disable
                if det_config:
                    attr_name = detector_cls.name if hasattr(detector_cls, "name") else ""
                    # Map detector names to config attributes
                    config_map = {
                        "entropy": "entropy",
                        "sections": "sections",
                        "iat": "iat",
                        "entrypoint": "entrypoint",
                        "pe_structure": "pe_structure",
                        "signatures": "signatures",
                        "yara": "yara",
                        "heuristic": "heuristic",
                    }
                    config_key = config_map.get(attr_name, "")
                    if (
                        config_key
                        and hasattr(det_config, config_key)
                        and not getattr(det_config, config_key)
                    ):
                        continue

                # Instantiate with appropriate arguments
                if detector_cls.__name__ == "SignatureDetector":
                    sig_dir = self._config.signatures_dir if self._config else None
                    instance = detector_cls(signatures_dir=sig_dir)
                elif detector_cls.__name__ == "YARADetector":
                    rules_dir = self._config.yara_rules_dir if self._config else None
                    instance = detector_cls(rules_dirs=[rules_dir] if rules_dir else [])
                elif detector_cls.__name__ == "HeuristicDetector":
                    weights = self._config.heuristic_weights if self._config else None
                    instance = detector_cls(weights=weights)
                else:
                    instance = detector_cls()

                self.register_detector(instance)
            except Exception as e:
                logger.error("detector_init_error", detector=detector_cls.__name__, error=str(e))

    def _register_builtin_unpackers(self) -> None:
        """Register all built-in unpacker modules."""
        try:
            from packerscope.unpackers.dynamic_unpacker import DynamicUnpacker
            from packerscope.unpackers.generic_unpacker import GenericStaticUnpacker
            from packerscope.unpackers.upx_unpacker import UPXUnpacker

            self.register_unpacker(UPXUnpacker())
            self.register_unpacker(GenericStaticUnpacker())
            self.register_unpacker(DynamicUnpacker())
        except Exception as e:
            logger.error("unpacker_init_error", error=str(e))

    def _register_builtin_reporters(self) -> None:
        """Register all built-in reporter modules."""
        try:
            from packerscope.reporters.csv_reporter import CSVReporter
            from packerscope.reporters.html_reporter import HTMLReporter
            from packerscope.reporters.json_reporter import JSONReporter
            from packerscope.reporters.markdown_reporter import MarkdownReporter

            self.register_reporter(JSONReporter())
            self.register_reporter(CSVReporter())
            self.register_reporter(MarkdownReporter())
            self.register_reporter(HTMLReporter())
        except Exception as e:
            logger.error("reporter_init_error", error=str(e))

    def _register_builtin_verifiers(self) -> None:
        """Register built-in verifier."""
        try:
            from packerscope.verification.verifier import UnpackVerifier
            self.register_verifier(UnpackVerifier())
        except Exception as e:
            logger.error("verifier_init_error", error=str(e))

    def _scan_plugin_dir(self, plugin_dir: Path) -> None:
        """Scan a directory for plugin Python files with register() functions."""
        if not plugin_dir.exists():
            return

        for subdir in ("detectors", "unpackers", "reporters"):
            d = plugin_dir / subdir
            if not d.exists():
                continue
            for py_file in d.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                try:
                    spec = importlib.util.spec_from_file_location(
                        f"plugin_{py_file.stem}", py_file
                    )
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        if hasattr(module, "register"):
                            module.register(self)
                            logger.info("plugin_loaded", file=str(py_file))
                except Exception as e:
                    logger.error("plugin_load_error", file=str(py_file), error=str(e))

    def _scan_entry_points(self) -> None:
        """Discover plugins registered via Python entry points."""
        for group in ("packerscope.detectors", "packerscope.unpackers", "packerscope.reporters"):
            try:
                eps = importlib.metadata.entry_points()
                # Python 3.12+ returns a SelectableGroups-like object
                if hasattr(eps, "select"):
                    group_eps = eps.select(group=group)
                else:
                    group_eps = eps.get(group, [])

                for ep in group_eps:
                    try:
                        register_fn = ep.load()
                        register_fn(self)
                        logger.info("entrypoint_plugin_loaded", name=ep.name, group=group)
                    except Exception as e:
                        logger.error("entrypoint_plugin_error", name=ep.name, error=str(e))
            except Exception:
                pass
