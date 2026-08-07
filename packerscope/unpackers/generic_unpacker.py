"""Generic static unpacker for PackerScope.

Provides basic static unpacking by extracting and decompressing
sections from packed PE files. Supports simple packers that use
standard compression (zlib, LZMA) on sections.
"""

from __future__ import annotations

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


class GenericStaticUnpacker(BaseUnpacker):
    """Generic static unpacking via section decompression.

    Attempts to identify compressed sections and decompress them
    using standard algorithms (zlib, LZMA). This works for simpler
    packers but will fail for packers with custom compression or
    encryption.
    """

    name: str = "generic_static"
    supported_packers: list[PackerType] = [
        PackerType.GENERIC_PACKED,
        PackerType.ASPACK,
        PackerType.MPRESS,
        PackerType.FSG,
        PackerType.PECOMPACT,
        PackerType.NSPACK,
        PackerType.PETITE,
        PackerType.MEW,
        PackerType.UPACK,
        PackerType.WINUPACK,
    ]
    priority: int = 50

    def unpack(self, ctx: PEContext, output_path: Path) -> UnpackResult:
        """Attempt generic static unpacking.

        This is a best-effort unpacker. For many packers, dynamic
        unpacking is required for reliable results.

        Args:
            ctx: Analysis context.
            output_path: Where to write the unpacked file.

        Returns:
            UnpackResult indicating success or failure.
        """
        start = time.monotonic()

        if not ctx.pe or not ctx.pe.is_valid:
            return UnpackResult(
                success=False,
                strategy_used=UnpackStrategy.STATIC_DECOMPRESS.value,
                error_message="Invalid PE — cannot attempt static unpacking",
                duration_seconds=time.monotonic() - start,
                unpacker_name=self.name,
            )

        # Attempt overlay extraction (some packers store original PE in overlay)
        if ctx.pe.has_overlay:
            overlay_data = ctx.pe.overlay_data
            if overlay_data and len(overlay_data) > 64:
                # Check if overlay starts with MZ header
                if overlay_data[:2] == b"MZ":
                    try:
                        output_path.write_bytes(overlay_data)
                        logger.info("overlay_extraction_success", size=len(overlay_data))
                        return UnpackResult(
                            success=True,
                            strategy_used=UnpackStrategy.STATIC_DECOMPRESS.value,
                            unpacked_path=str(output_path),
                            duration_seconds=time.monotonic() - start,
                            unpacker_name=self.name,
                        )
                    except OSError as e:
                        logger.warning("overlay_write_failed", error=str(e))

                # Try decompressing overlay with common algorithms
                for algo_name, decompress_fn in self._decompressors():
                    try:
                        decompressed = decompress_fn(overlay_data)
                        if decompressed and decompressed[:2] == b"MZ":
                            output_path.write_bytes(decompressed)
                            logger.info(
                                "overlay_decompress_success",
                                algorithm=algo_name,
                                size=len(decompressed),
                            )
                            return UnpackResult(
                                success=True,
                                strategy_used=UnpackStrategy.STATIC_DECOMPRESS.value,
                                unpacked_path=str(output_path),
                                duration_seconds=time.monotonic() - start,
                                unpacker_name=self.name,
                            )
                    except Exception:
                        continue

        # If no overlay or overlay extraction failed
        logger.info("generic_static_unpack_failed", reason="No extractable payload found")
        return UnpackResult(
            success=False,
            strategy_used=UnpackStrategy.STATIC_DECOMPRESS.value,
            error_message=(
                "Static unpacking failed — no extractable payload found. "
                "Dynamic unpacking may be required."
            ),
            duration_seconds=time.monotonic() - start,
            unpacker_name=self.name,
        )

    @staticmethod
    def _decompressors():
        """Yield (name, function) pairs for common decompression algorithms."""
        import zlib
        yield "zlib", zlib.decompress

        try:
            import lzma
            yield "lzma", lzma.decompress
        except ImportError:
            pass

        # Try zlib with different wbits
        yield "zlib_raw", lambda data: zlib.decompress(data, -15)
        yield "zlib_gzip", lambda data: zlib.decompress(data, 31)
