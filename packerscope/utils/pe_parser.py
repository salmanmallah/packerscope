"""Unified PE file access layer for PackerScope.

Wraps :mod:`pefile` behind a higher-level, fully-typed API that exposes
section data, imports, overlay detection, and header metadata as plain Python
objects.  Every ``pefile`` call is guarded so that malformed or truncated
binaries never crash the analysis pipeline.

Typical usage::

    from packerscope.utils.pe_parser import PEParser

    with PEParser(Path("sample.exe")) as pe:
        pe.load()
        for sec in pe.sections:
            print(sec.name, hex(sec.virtual_address), sec.raw_size)
"""

from __future__ import annotations

import contextlib
import datetime
from pathlib import Path
from typing import NamedTuple

import pefile
import structlog

__all__ = [
    "ImportData",
    "PEParser",
    "SectionData",
]

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Machine type constants (IMAGE_FILE_MACHINE_*)
# ---------------------------------------------------------------------------
_MACHINE_NAMES: dict[int, str] = {
    0x0: "UNKNOWN",
    0x14C: "I386",
    0x166: "R4000",
    0x1A2: "SH3",
    0x1A3: "SH3DSP",
    0x1A6: "SH4",
    0x1A8: "SH5",
    0x1C0: "ARM",
    0x1C2: "THUMB",
    0x1C4: "ARMNT",
    0x1D3: "AM33",
    0x200: "IA64",
    0x266: "MIPS16",
    0x366: "MIPSFPU",
    0x466: "MIPSFPU16",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
    0x5128: "RISCV128",
    0x8664: "AMD64",
    0xAA64: "ARM64",
    0x9041: "M32R",
    0xC0EE: "CEE",
}

# Subsystem constants
_SUBSYSTEM_NAMES: dict[int, str] = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class SectionData(NamedTuple):
    """Parsed PE section descriptor.

    Attributes:
        name: Section name (decoded, stripped of null bytes).
        virtual_address: RVA where the section is mapped in memory.
        virtual_size: Size of the section in memory.
        raw_size: Size of the section on disk (``SizeOfRawData``).
        raw_offset: File offset of the section's raw data.
        characteristics: Section characteristic flags.
        data: Raw bytes of the section (may be truncated for large sections).
    """

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    data: bytes


class ImportData(NamedTuple):
    """A single import descriptor (DLL + imported function names).

    Attributes:
        dll_name: Name of the imported DLL.
        functions: List of imported function names (ordinals are formatted
            as ``"ord:<n>"``).
    """

    dll_name: str
    functions: list[str]


# ---------------------------------------------------------------------------
# PEParser
# ---------------------------------------------------------------------------


class PEParser:
    """High-level, context-managed wrapper around :mod:`pefile`.

    Args:
        file_path: Path to the PE file on disk.
    """

    def __init__(self, file_path: Path) -> None:
        self._file_path = file_path
        self._pe: pefile.PE | None = None
        self._raw_data: bytes = b""
        self._valid: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Parse the PE file.

        Sets :attr:`is_valid` to ``False`` on any ``pefile`` exception and
        logs a warning rather than propagating the error.
        """
        try:
            self._raw_data = self._file_path.read_bytes()
            self._pe = pefile.PE(data=self._raw_data, fast_load=False)
            self._valid = True
            logger.debug(
                "pe_loaded",
                path=str(self._file_path),
                size=len(self._raw_data),
            )
        except pefile.PEFormatError as exc:
            logger.warning(
                "pe_format_error",
                path=str(self._file_path),
                error=str(exc),
            )
            self._valid = False
        except OSError as exc:
            logger.warning(
                "pe_io_error",
                path=str(self._file_path),
                error=str(exc),
            )
            self._valid = False

    def close(self) -> None:
        """Release the underlying ``pefile.PE`` object."""
        if self._pe is not None:
            with contextlib.suppress(Exception):
                self._pe.close()
            self._pe = None
        self._valid = False

    # Context-manager support
    def __enter__(self) -> PEParser:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Validity
    # ------------------------------------------------------------------

    @property
    def is_valid(self) -> bool:
        """Return ``True`` when the PE was parsed without errors."""
        return self._valid

    # ------------------------------------------------------------------
    # Raw pefile access
    # ------------------------------------------------------------------

    @property
    def pe(self) -> pefile.PE:
        """Return the underlying :class:`pefile.PE` object.

        Raises:
            RuntimeError: If the PE has not been loaded or is invalid.
        """
        if self._pe is None:
            raise RuntimeError("PE not loaded — call .load() first")
        return self._pe

    # ------------------------------------------------------------------
    # Architecture
    # ------------------------------------------------------------------

    @property
    def is_64bit(self) -> bool:
        """``True`` for PE32+ (x86-64) images."""
        try:
            return self.pe.FILE_HEADER.Machine == 0x8664
        except Exception:
            return False

    @property
    def machine_type(self) -> str:
        """Human-readable machine type name (e.g. ``"AMD64"``)."""
        try:
            return _MACHINE_NAMES.get(self.pe.FILE_HEADER.Machine, "UNKNOWN")
        except Exception:
            return "UNKNOWN"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    @property
    def entry_point_rva(self) -> int:
        """Relative virtual address of the entry point."""
        try:
            return int(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except Exception:
            return 0

    @property
    def entry_point_offset(self) -> int:
        """File (physical) offset of the entry point."""
        try:
            offset = self.pe.get_offset_from_rva(self.entry_point_rva)
            return int(offset) if offset is not None else 0
        except Exception:
            logger.debug("ep_offset_resolution_failed", rva=hex(self.entry_point_rva))
            return 0

    def entry_point_data(self, size: int = 256) -> bytes:
        """Read *size* bytes starting at the entry point file offset.

        Args:
            size: Number of bytes to read (default ``256``).

        Returns:
            A bytes object, possibly shorter than *size* if the file is
            truncated.
        """
        offset = self.entry_point_offset
        if offset <= 0 or offset >= len(self._raw_data):
            return b""
        return self._raw_data[offset: offset + size]

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    @property
    def sections(self) -> list[SectionData]:
        """List of parsed section descriptors."""
        result: list[SectionData] = []
        try:
            for section in self.pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                data = section.get_data() if section.SizeOfRawData > 0 else b""
                result.append(
                    SectionData(
                        name=name,
                        virtual_address=section.VirtualAddress,
                        virtual_size=section.Misc_VirtualSize,
                        raw_size=section.SizeOfRawData,
                        raw_offset=section.PointerToRawData,
                        characteristics=section.Characteristics,
                        data=data,
                    )
                )
        except Exception:
            logger.warning("section_parse_error", exc_info=True)
        return result

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    @property
    def imports(self) -> list[ImportData]:
        """Parsed import directory entries."""
        result: list[ImportData] = []
        try:
            if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
                return result
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                functions: list[str] = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="replace"))
                    elif imp.ordinal is not None:
                        functions.append(f"ord:{imp.ordinal}")
                result.append(ImportData(dll_name=dll_name, functions=functions))
        except Exception:
            logger.warning("import_parse_error", exc_info=True)
        return result

    # ------------------------------------------------------------------
    # Optional header helpers
    # ------------------------------------------------------------------

    @property
    def image_base(self) -> int:
        """Preferred image base address."""
        try:
            return int(self.pe.OPTIONAL_HEADER.ImageBase)
        except Exception:
            return 0

    @property
    def subsystem(self) -> str:
        """Subsystem name (e.g. ``"WINDOWS_GUI"``)."""
        try:
            return _SUBSYSTEM_NAMES.get(self.pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN")
        except Exception:
            return "UNKNOWN"

    @property
    def linker_version(self) -> str:
        """Linker major.minor version string."""
        try:
            major = self.pe.OPTIONAL_HEADER.MajorLinkerVersion
            minor = self.pe.OPTIONAL_HEADER.MinorLinkerVersion
            return f"{major}.{minor}"
        except Exception:
            return "0.0"

    @property
    def compile_timestamp(self) -> datetime.datetime | None:
        """UTC datetime derived from ``TimeDateStamp``, or ``None``."""
        try:
            ts = self.pe.FILE_HEADER.TimeDateStamp
            if ts == 0:
                return None
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        except (OSError, OverflowError, ValueError):
            logger.debug("invalid_timestamp", raw=ts)
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------

    @property
    def overlay_offset(self) -> int:
        """File offset where the overlay begins (``0`` if none)."""
        try:
            off = self.pe.get_overlay_data_start_offset()
            return int(off) if off is not None else 0
        except Exception:
            return 0

    @property
    def has_overlay(self) -> bool:
        """``True`` when the file contains an overlay."""
        return self.overlay_offset > 0

    @property
    def overlay_data(self) -> bytes | None:
        """Raw overlay bytes, or ``None`` when no overlay is present."""
        off = self.overlay_offset
        if off <= 0 or off >= len(self._raw_data):
            return None
        return self._raw_data[off:]

    # ------------------------------------------------------------------
    # Directory presence checks
    # ------------------------------------------------------------------

    def _has_directory(self, index: int) -> bool:
        """Check whether the PE contains the data-directory at *index*."""
        try:
            return (
                len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > index
                and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress != 0
                and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size != 0
            )
        except Exception:
            return False

    @property
    def has_tls(self) -> bool:
        """``True`` when a TLS directory is present."""
        return self._has_directory(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"])

    @property
    def has_relocations(self) -> bool:
        """``True`` when a base-relocation directory is present."""
        return self._has_directory(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"])

    @property
    def has_resources(self) -> bool:
        """``True`` when a resource directory is present."""
        return self._has_directory(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"])

    @property
    def has_debug(self) -> bool:
        """``True`` when a debug directory is present."""
        return self._has_directory(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"])

    @property
    def has_certificates(self) -> bool:
        """``True`` when a certificate (Authenticode) table is present."""
        return self._has_directory(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"])

    # ------------------------------------------------------------------
    # Checksum
    # ------------------------------------------------------------------

    @property
    def checksum(self) -> int:
        """Stored PE checksum from the optional header."""
        try:
            return int(self.pe.OPTIONAL_HEADER.CheckSum)
        except Exception:
            return 0

    @property
    def calculated_checksum(self) -> int:
        """Freshly calculated PE checksum (expensive on large files)."""
        try:
            return int(self.pe.generate_checksum())
        except Exception:
            logger.debug("checksum_calculation_failed", exc_info=True)
            return 0
