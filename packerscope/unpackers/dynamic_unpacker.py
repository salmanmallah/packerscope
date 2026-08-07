"""Dynamic unpacker interface for PackerScope.

Defines the abstract interface for debugger/emulator-based unpacking.
Concrete backends (Frida, Qiling, x64dbg) will implement this interface
in future versions. Currently serves as the extension point.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from packerscope.core.enums import PackerType, UnpackStrategy
from packerscope.core.interfaces import BaseUnpacker
from packerscope.core.models import UnpackResult
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


class DebuggerBackend(ABC):
    """Abstract interface for debugger/emulator backends.

    Concrete implementations will wrap Frida, Qiling, x64dbg, or
    other dynamic analysis tools. This interface defines the
    operations needed for dynamic unpacking:
    1. Attach to or emulate the process
    2. Set breakpoints on key APIs
    3. Monitor execution for OEP detection
    4. Dump the process memory
    5. Reconstruct imports

    Example (future Frida backend):
        >>> backend = FridaBackend()
        >>> backend.attach(pid=1234)
        >>> backend.set_breakpoint(0x401000)
        >>> backend.continue_execution()
        >>> data = backend.read_memory(0x400000, 0x10000)
        >>> backend.dump_process(1234, Path("dumped.exe"))
    """

    name: str = "base"

    @abstractmethod
    def attach(self, target: str | int) -> bool:
        """Attach to a running process or load a file for emulation.

        Args:
            target: PID (int) or file path (str).

        Returns:
            True if attachment succeeded.
        """
        ...

    @abstractmethod
    def set_breakpoint(self, address: int) -> bool:
        """Set an execution breakpoint at the given address."""
        ...

    @abstractmethod
    def continue_execution(self) -> bool:
        """Resume execution until a breakpoint is hit."""
        ...

    @abstractmethod
    def read_memory(self, address: int, size: int) -> bytes:
        """Read bytes from the target's memory space."""
        ...

    @abstractmethod
    def dump_process(self, target: str | int, output_path: Path) -> bool:
        """Dump the process memory to a file."""
        ...

    @abstractmethod
    def detach(self) -> None:
        """Detach from the process / stop emulation."""
        ...


class DynamicUnpacker(BaseUnpacker):
    """Dynamic unpacking via debugger/emulator backends.

    This unpacker serves as the orchestrator for dynamic unpacking
    strategies. It selects and invokes the appropriate backend.

    Currently returns a "not implemented" result — backends will be
    added in future milestones (Frida, Qiling, x64dbg).
    """

    name: str = "dynamic"
    supported_packers: list[PackerType] = [
        PackerType.THEMIDA,
        PackerType.VMPROTECT,
        PackerType.ENIGMA,
        PackerType.ARMADILLO,
        PackerType.OBSIDIUM,
        PackerType.MOLEBOX,
    ]
    priority: int = 100  # Last resort

    def __init__(self, backend: DebuggerBackend | None = None) -> None:
        self._backend = backend

    def is_available(self) -> bool:
        """Check if a backend is configured and available."""
        return self._backend is not None

    def unpack(self, ctx: PEContext, output_path: Path) -> UnpackResult:
        """Attempt dynamic unpacking.

        Args:
            ctx: Analysis context.
            output_path: Where to write the unpacked file.

        Returns:
            UnpackResult — currently always fails with a descriptive
            message since no backend is implemented yet.
        """
        start = time.monotonic()

        if not self.is_available():
            packer = ctx.verdict.packer.value if ctx.verdict else "unknown"
            return UnpackResult(
                success=False,
                strategy_used=UnpackStrategy.DYNAMIC_DEBUG.value,
                error_message=(
                    f"Dynamic unpacking for {packer} requires a debugger/emulator backend "
                    "(Frida, Qiling, or x64dbg). No backend is currently configured. "
                    "See docs/adding_unpackers.md for integration instructions."
                ),
                duration_seconds=time.monotonic() - start,
                unpacker_name=self.name,
            )

        # Future: use self._backend to perform dynamic unpacking
        return UnpackResult(
            success=False,
            strategy_used=UnpackStrategy.DYNAMIC_DEBUG.value,
            error_message="Dynamic unpacking not yet implemented",
            duration_seconds=time.monotonic() - start,
            unpacker_name=self.name,
        )
