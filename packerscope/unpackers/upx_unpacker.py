"""UPX unpacker for PackerScope.

Invokes the native ``upx -d`` command to decompress UPX-packed executables.
Falls back to manual section decompression if the UPX binary is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

from packerscope.core.enums import PackerType, UnpackStrategy
from packerscope.core.interfaces import BaseUnpacker
from packerscope.core.models import UnpackResult
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


class UPXUnpacker(BaseUnpacker):
    """Unpack UPX-compressed executables using the native UPX tool.

    Attempts to invoke ``upx -d`` on the target file. Copies the file
    to the output path before decompression to preserve the original.
    """

    name: str = "upx_native"
    supported_packers: list[PackerType] = [PackerType.UPX]
    priority: int = 10

    def is_available(self) -> bool:
        """Check if the ``upx`` binary is on PATH."""
        return shutil.which("upx") is not None

    def unpack(self, ctx: PEContext, output_path: Path, timeout: int = 60) -> UnpackResult:
        """Unpack using ``upx -d``.

        Args:
            ctx: Analysis context.
            output_path: Where to write the unpacked file.
            timeout: Subprocess timeout in seconds.

        Returns:
            UnpackResult indicating success or failure.
        """
        start = time.monotonic()

        if not self.is_available():
            return UnpackResult(
                success=False,
                strategy_used=UnpackStrategy.NATIVE_TOOL.value,
                error_message="UPX binary not found on PATH",
                duration_seconds=time.monotonic() - start,
                unpacker_name=self.name,
            )

        # Run UPX decompression directly to output_path
        try:
            result = subprocess.run(
                ["upx", "-d", "-o", str(output_path), "--force", str(ctx.file_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                logger.info("upx_unpack_success", output=str(output_path))
                return UnpackResult(
                    success=True,
                    strategy_used=UnpackStrategy.NATIVE_TOOL.value,
                    unpacked_path=str(output_path),
                    duration_seconds=time.monotonic() - start,
                    unpacker_name=self.name,
                )
            else:
                error = result.stderr.strip() or result.stdout.strip()
                logger.warning("upx_unpack_failed", error=error)
                # Clean up failed output
                if output_path.exists():
                    output_path.unlink()
                return UnpackResult(
                    success=False,
                    strategy_used=UnpackStrategy.NATIVE_TOOL.value,
                    error_message=f"UPX returned error: {error}",
                    duration_seconds=time.monotonic() - start,
                    unpacker_name=self.name,
                )

        except subprocess.TimeoutExpired:
            if output_path.exists():
                output_path.unlink()
            return UnpackResult(
                success=False,
                strategy_used=UnpackStrategy.NATIVE_TOOL.value,
                error_message=f"UPX process timed out ({timeout}s)",
                duration_seconds=time.monotonic() - start,
                unpacker_name=self.name,
            )
        except Exception as e:
            if output_path.exists():
                output_path.unlink()
            return UnpackResult(
                success=False,
                strategy_used=UnpackStrategy.NATIVE_TOOL.value,
                error_message=str(e),
                duration_seconds=time.monotonic() - start,
                unpacker_name=self.name,
            )
