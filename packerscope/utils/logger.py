"""Structured logging configuration for PackerScope.

Wraps :mod:`structlog` with sensible defaults: coloured console output via
`Rich <https://rich.readthedocs.io>`_ for interactive use, optional JSON
output for machine consumption, and an optional rotating file handler.

Typical usage::

    from packerscope.utils.logger import setup_logging, get_logger

    setup_logging(level="DEBUG", log_file=Path("packerscope.log"))
    log = get_logger("my_module")
    log.info("analysis_started", file="sample.exe")
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import structlog

__all__ = [
    "get_logger",
    "setup_logging",
]

# ---------------------------------------------------------------------------
# Module-level sentinel to prevent double-init
# ---------------------------------------------------------------------------
_LOGGING_CONFIGURED: bool = False

# Rotation defaults
_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT: int = 5


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    json_output: bool = False,
) -> None:
    """Initialise structured logging for the entire application.

    This function is idempotent — calling it more than once replaces the
    previous configuration.

    Args:
        level: Minimum log level name (``DEBUG``, ``INFO``, ``WARNING``,
            ``ERROR``, ``CRITICAL``).
        log_file: Optional path to a rotating log file.  Parent directories
            are created automatically.
        json_output: When ``True``, emit newline-delimited JSON to *stdout*
            instead of coloured console output.

    Raises:
        ValueError: If *level* is not a recognised logging level name.
    """
    global _LOGGING_CONFIGURED  # noqa: PLW0603

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level!r}")

    # ----- stdlib root logger -----
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Clear existing handlers to make re-configuration safe.
    root.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    root.addHandler(console_handler)

    # Rotating file handler
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        root.addHandler(file_handler)

    # ----- structlog pipeline -----
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        try:
            from rich.console import Console  # noqa: F811
            from rich.traceback import install as _install_rich_tb

            _install_rich_tb(show_locals=False, width=120)

            use_colors = True
            if sys.platform == "win32":
                try:
                    import colorama  # noqa: F401
                except ImportError:
                    use_colors = False

            renderer = structlog.dev.ConsoleRenderer(
                colors=use_colors,
                exception_formatter=structlog.dev.plain_traceback,
            )
        except (ImportError, SystemError):
            # Fallback when rich/colorama is not available or raises SystemError on Windows.
            renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[
            *shared_processors,
            # Prepare event dict for stdlib or the final renderer.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Apply the structlog formatter to all stdlib handlers so that log
    # records produced via ``structlog.get_logger()`` are rendered
    # consistently regardless of which handler emits them.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    for handler in root.handlers:
        handler.setFormatter(formatter)

    _LOGGING_CONFIGURED = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a :class:`structlog.stdlib.BoundLogger` bound to *name*.

    If :func:`setup_logging` has not been called yet, a minimal default
    configuration is applied automatically to avoid un-configured log
    output.

    Args:
        name: Logger name — typically ``__name__`` of the calling module.

    Returns:
        A bound structured logger instance.
    """
    if not _LOGGING_CONFIGURED:
        setup_logging()

    return structlog.get_logger(name)
