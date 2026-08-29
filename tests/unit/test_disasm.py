"""Unit tests for Disassembler and disassembly heuristics."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from packerscope.utils.disasm import Disassembler, is_available


class TestDisassembler:
    """Test suite for x86/x86-64 disassembly heuristics."""

    def test_disassemble_empty_data(self):
        """Verify disassemble returns empty list for empty bytes."""
        dis = Disassembler(is_64bit=False)
        assert dis.disassemble(b"") == []

    def test_detect_nop_sled(self):
        """Verify NOP sled detection with NOP sequence."""
        dis = Disassembler(is_64bit=False)
        nop_sled = b"\x90" * 30 + b"\xC3"
        assert dis.detect_nop_sled(nop_sled) is True

        # Normal code should not be a nop sled
        normal_code = b"\x55\x8B\xEC\x5D\xC3"  # push ebp; mov ebp, esp; pop ebp; ret
        assert dis.detect_nop_sled(normal_code) is False

    def test_detect_jump_chain(self):
        """Verify jump chain heuristic with consecutive jump instructions."""
        dis = Disassembler(is_64bit=False)
        # JMP short +0 (EB 00) repeated
        jump_data = b"\xEB\x00" * 5 + b"\xC3"

        if dis.is_available():
            assert dis.detect_jump_chain(jump_data) is True
        else:
            assert dis.detect_jump_chain(jump_data) is False

    def test_detect_push_ret(self):
        """Verify push/ret trampoline detection."""
        dis = Disassembler(is_64bit=False)
        # push 0x401000 (68 00 10 40 00) ; ret (C3)
        push_ret_data = b"\x68\x00\x10\x40\x00\xC3"

        if dis.is_available():
            assert dis.detect_push_ret(push_ret_data) is True
        else:
            assert dis.detect_push_ret(push_ret_data) is False
