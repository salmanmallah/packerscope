"""PackerScope exception hierarchy.

Every domain-specific error inherits from :class:`PackerScopeError` so that
callers can catch the base class for blanket handling while still being able
to inspect structured context attributes on each subclass.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class PackerScopeError(Exception):
    """Root exception for all PackerScope errors.

    Args:
        message: Human-readable description of the error.
    """

    def __init__(self, message: str = "An unspecified PackerScope error occurred.") -> None:
        self.message: str = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


# ---------------------------------------------------------------------------
# PE parsing
# ---------------------------------------------------------------------------


class PEParseError(PackerScopeError):
    """Raised when a PE file cannot be parsed or is structurally invalid.

    Args:
        message: Description of the parsing failure.
        file_path: Path to the PE file that failed to parse.
    """

    def __init__(self, message: str, file_path: Path) -> None:
        self.file_path: Path = file_path
        super().__init__(message)

    def __str__(self) -> str:
        return f"PE parse error for '{self.file_path}': {self.message}"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class DetectionError(PackerScopeError):
    """Raised when a detection engine encounters an unrecoverable error.

    Args:
        message: Description of the detection failure.
        detector_name: Identifier of the detector that failed.
    """

    def __init__(self, message: str, detector_name: str) -> None:
        self.detector_name: str = detector_name
        super().__init__(message)

    def __str__(self) -> str:
        return f"Detection error in '{self.detector_name}': {self.message}"


# ---------------------------------------------------------------------------
# Unpacking
# ---------------------------------------------------------------------------


class UnpackError(PackerScopeError):
    """Raised when an unpacker fails to produce a valid unpacked PE.

    Args:
        message: Description of the unpacking failure.
        unpacker_name: Identifier of the unpacker that failed.
    """

    def __init__(self, message: str, unpacker_name: str) -> None:
        self.unpacker_name: str = unpacker_name
        super().__init__(message)

    def __str__(self) -> str:
        return f"Unpack error in '{self.unpacker_name}': {self.message}"


# ---------------------------------------------------------------------------
# Signatures / YARA
# ---------------------------------------------------------------------------


class SignatureLoadError(PackerScopeError):
    """Raised when a signature database file cannot be loaded.

    Args:
        message: Description of the loading failure.
        database_path: Path to the signature database that failed to load.
    """

    def __init__(self, message: str, database_path: Path) -> None:
        self.database_path: Path = database_path
        super().__init__(message)

    def __str__(self) -> str:
        return f"Signature load error for '{self.database_path}': {self.message}"


class YARAError(PackerScopeError):
    """Raised when a YARA rule fails to compile or match.

    Args:
        message: Description of the YARA failure.
        rule_file: Path or name of the YARA rule source.
        compile_error: Raw error string from the YARA compiler.
    """

    def __init__(self, message: str, rule_file: str, compile_error: str) -> None:
        self.rule_file: str = rule_file
        self.compile_error: str = compile_error
        super().__init__(message)

    def __str__(self) -> str:
        return (
            f"YARA error in rule '{self.rule_file}': {self.message} "
            f"(compile error: {self.compile_error})"
        )


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------


class PluginError(PackerScopeError):
    """Raised when a plugin fails to load, register, or execute.

    Args:
        message: Description of the plugin failure.
        plugin_name: Identifier of the offending plugin.
    """

    def __init__(self, message: str, plugin_name: str) -> None:
        self.plugin_name: str = plugin_name
        super().__init__(message)

    def __str__(self) -> str:
        return f"Plugin error in '{self.plugin_name}': {self.message}"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigError(PackerScopeError):
    """Raised when configuration is missing, malformed, or invalid.

    Args:
        message: Description of the configuration problem.
    """

    def __init__(self, message: str = "Invalid or missing configuration.") -> None:
        super().__init__(message)

    def __str__(self) -> str:
        return f"Configuration error: {self.message}"


# ---------------------------------------------------------------------------
# File-size guard
# ---------------------------------------------------------------------------


class FileTooLargeError(PackerScopeError):
    """Raised when a file exceeds the configured maximum size.

    Args:
        message: Description of the size violation.
        file_size: Actual size of the file in bytes.
        max_size: Maximum allowed size in bytes.
    """

    def __init__(
        self,
        message: str = "File size exceeds configured maximum limit.",
        file_size: int = 0,
        max_size: int = 0,
    ) -> None:
        self.file_size: int = file_size
        self.max_size: int = max_size
        super().__init__(message)

    def __str__(self) -> str:
        file_mb = self.file_size / (1024 * 1024)
        max_mb = self.max_size / (1024 * 1024)
        return (
            f"File too large: {file_mb:.2f} MiB exceeds limit of {max_mb:.2f} MiB. "
            f"{self.message}"
        )
