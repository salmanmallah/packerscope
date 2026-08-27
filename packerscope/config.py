"""Configuration management for PackerScope.

Loads and validates configuration from multiple sources with the following
priority (highest to lowest):
    1. CLI arguments (passed at runtime)
    2. Environment variables (PACKERSCOPE_ prefix)
    3. Configuration file (config.yaml)
    4. Default values

Uses pydantic-settings for type-safe configuration with automatic
environment variable binding and validation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from packerscope.core.enums import LogLevel, ReportFormat


class EntropyThresholds(BaseModel):
    """Entropy classification thresholds."""

    low_max: float = Field(default=3.5, description="Upper bound for LOW entropy")
    medium_max: float = Field(default=5.5, description="Upper bound for MEDIUM entropy")
    high_max: float = Field(default=7.0, description="Upper bound for HIGH entropy")
    very_high_max: float = Field(default=8.0, description="Upper bound for VERY_HIGH entropy")


class HeuristicWeights(BaseModel):
    """Configurable weights for the heuristic detection engine.

    Each weight determines how much a specific feature contributes to the
    overall packing confidence score. Higher weights indicate stronger
    indicators of packing.
    """

    high_entropy: int = Field(default=25, description="Weight for high entropy detection")
    suspicious_section_names: int = Field(
        default=20, description="Weight for suspicious section names"
    )
    known_packer_sections: int = Field(
        default=20, description="Weight for known packer section names"
    )
    tiny_iat: int = Field(default=15, description="Weight for very small IAT")
    rwx_sections: int = Field(default=10, description="Weight for RWX sections")
    signature_match: int = Field(default=30, description="Weight for signature match")
    yara_match: int = Field(default=25, description="Weight for YARA rule match")
    entry_point_stub: int = Field(default=15, description="Weight for EP stub detection")
    ep_outside_text: int = Field(
        default=10, description="Weight for EP outside .text section"
    )
    large_overlay: int = Field(default=5, description="Weight for large overlay data")
    no_relocations: int = Field(default=5, description="Weight for missing relocations")
    abnormal_alignment: int = Field(
        default=5, description="Weight for abnormal section alignment"
    )
    compressed_resources: int = Field(
        default=5, description="Weight for compressed resources"
    )
    missing_debug_info: int = Field(
        default=3, description="Weight for missing debug information"
    )
    suspicious_timestamp: int = Field(
        default=3, description="Weight for suspicious compile timestamp"
    )

    @property
    def max_score(self) -> int:
        """Sum of all weights — used for score normalization."""
        return sum(
            getattr(self, field_name)
            for field_name in self.__class__.model_fields
        )


class DetectorConfig(BaseModel):
    """Per-detector enable/disable configuration."""

    entropy: bool = Field(default=True, description="Enable entropy analysis")
    sections: bool = Field(default=True, description="Enable section analysis")
    iat: bool = Field(default=True, description="Enable IAT analysis")
    entrypoint: bool = Field(default=True, description="Enable entry point analysis")
    pe_structure: bool = Field(default=True, description="Enable PE structure analysis")
    signatures: bool = Field(default=True, description="Enable signature scanning")
    yara: bool = Field(default=True, description="Enable YARA scanning")
    heuristic: bool = Field(default=True, description="Enable heuristic engine")


class Config(BaseSettings):
    """PackerScope main configuration.

    Configuration is loaded from environment variables with the
    ``PACKERSCOPE_`` prefix, and can be overridden via CLI arguments
    or a YAML configuration file.

    Example:
        >>> config = Config()  # Loads from env + defaults
        >>> config = Config.from_yaml(Path("config.yaml"))
        >>> config.output_dir
        PosixPath('output')
    """

    model_config = SettingsConfigDict(
        env_prefix="PACKERSCOPE_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # --- Directory Paths ---
    signatures_dir: Path = Field(
        default=Path("packerscope/signatures"),
        description="Directory containing signature databases",
    )
    yara_rules_dir: Path = Field(
        default=Path("packerscope/signatures/yara_rules"),
        description="Directory containing YARA rule files",
    )
    output_dir: Path = Field(
        default=Path("output"),
        description="Default output directory for reports and unpacked files",
    )
    plugins_dir: Path = Field(
        default=Path("plugins"),
        description="Directory for external plugins",
    )

    # --- Analysis Settings ---
    max_file_size: int = Field(
        default=100 * 1024 * 1024,
        description="Maximum file size in bytes (default: 100MB)",
    )
    entry_point_bytes: int = Field(
        default=256,
        description="Number of bytes to read from entry point for analysis",
    )
    max_workers: int = Field(
        default=4,
        description="Maximum concurrent workers for batch processing",
    )

    # --- Feature Toggles ---
    enable_yara: bool = Field(
        default=True,
        description="Enable YARA rule scanning",
    )
    enable_unpack: bool = Field(
        default=False,
        description="Attempt unpacking after detection",
    )
    enable_verification: bool = Field(
        default=True,
        description="Verify unpacking results",
    )

    # --- Report Settings ---
    report_formats: list[ReportFormat] = Field(
        default=[ReportFormat.JSON],
        description="Report formats to generate",
    )

    # --- Logging ---
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging verbosity level",
    )
    log_file: Path | None = Field(
        default=None,
        description="Path to log file (None for console only)",
    )
    log_json: bool = Field(
        default=False,
        description="Output logs in JSON format",
    )

    # --- Nested Configs ---
    entropy_thresholds: EntropyThresholds = Field(
        default_factory=EntropyThresholds,
        description="Entropy classification thresholds",
    )
    heuristic_weights: HeuristicWeights = Field(
        default_factory=HeuristicWeights,
        description="Heuristic detection weights",
    )
    detectors: DetectorConfig = Field(
        default_factory=DetectorConfig,
        description="Per-detector enable/disable toggles",
    )

    # --- Section Name Overrides ---
    extra_section_signatures: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Additional packer section name signatures (packer_name -> [section_names])",
    )

    @field_validator("max_workers")
    @classmethod
    def validate_max_workers(cls, v: int) -> int:
        """Ensure max_workers is at least 1 and at most 32."""
        if v < 1:
            return 1
        if v > 32:
            return 32
        return v

    @field_validator("max_file_size")
    @classmethod
    def validate_max_file_size(cls, v: int) -> int:
        """Ensure max_file_size is positive."""
        if v <= 0:
            return 100 * 1024 * 1024  # Default 100MB
        return v

    @classmethod
    def from_yaml(cls, yaml_path: Path, **overrides: Any) -> Config:
        """Load configuration from a YAML file with optional overrides.

        Args:
            yaml_path: Path to the YAML configuration file.
            **overrides: Additional keyword arguments that override
                values from the YAML file and environment.

        Returns:
            A validated Config instance.

        Raises:
            FileNotFoundError: If the YAML file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        if not yaml_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {yaml_path}")

        with open(yaml_path, "r", encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f) or {}

        # Merge: overrides take precedence over YAML
        yaml_data.update(overrides)
        return cls(**yaml_data)

    @classmethod
    def from_cli(cls, **cli_args: Any) -> Config:
        """Create configuration from CLI arguments.

        Filters out None values (unset CLI flags) so that defaults
        and environment variables are preserved.

        Args:
            **cli_args: Keyword arguments from the CLI parser.

        Returns:
            A validated Config instance.
        """
        # Remove None values (unset CLI args)
        filtered = {k: v for k, v in cli_args.items() if v is not None}
        return cls(**filtered)

    def ensure_directories(self) -> None:
        """Create all required output directories if they don't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "unpacked").mkdir(parents=True, exist_ok=True)

    def to_yaml(self, output_path: Path) -> None:
        """Save current configuration to a YAML file.

        Args:
            output_path: Path where the YAML file should be written.
        """
        data = self.model_dump(mode="json")
        # Convert Path objects to strings for YAML serialization
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
