"""Unit tests for PackerScope utility modules."""

from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from packerscope.core.enums import EntropyClass
from packerscope.utils.entropy import calculate_entropy, classify_entropy
from packerscope.utils.hasher import FileHasher


# ── Entropy Tests ──────────────────────────────────────────────────────────

class TestCalculateEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_data_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_single_byte_returns_zero(self):
        assert calculate_entropy(b"\x00") == 0.0

    def test_uniform_distribution_is_eight(self):
        data = bytes(range(256))
        ent = calculate_entropy(data)
        assert abs(ent - 8.0) < 0.01

    def test_repeated_byte_is_zero(self):
        data = b"\xAA" * 1024
        assert calculate_entropy(data) == 0.0

    def test_two_values_equally_distributed(self):
        data = b"\x00\xFF" * 512
        ent = calculate_entropy(data)
        assert abs(ent - 1.0) < 0.01

    def test_high_entropy_random_like_data(self):
        data = os.urandom(4096)
        ent = calculate_entropy(data)
        assert ent > 7.5


class TestClassifyEntropy:
    """Tests for entropy classification using core EntropyClass."""

    def test_low_entropy(self):
        result = classify_entropy(2.0)
        assert result is EntropyClass.LOW

    def test_medium_entropy(self):
        result = classify_entropy(4.5)
        assert result is EntropyClass.MEDIUM

    def test_high_entropy(self):
        result = classify_entropy(6.5)
        assert result is EntropyClass.HIGH

    def test_very_high_entropy(self):
        result = classify_entropy(7.5)
        assert result is EntropyClass.VERY_HIGH

    def test_boundary_low_medium(self):
        # 3.5 is at the boundary — from_value uses < 3.5 for LOW
        result = classify_entropy(3.5)
        assert result in (EntropyClass.LOW, EntropyClass.MEDIUM)

    def test_zero_is_low(self):
        result = classify_entropy(0.0)
        assert result is EntropyClass.LOW


# ── Hasher Tests ───────────────────────────────────────────────────────────

class TestFileHasher:
    """Tests for hash computation."""

    def test_compute_all_returns_three_hashes(self):
        result = FileHasher.compute_all(b"hello world")
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result

    def test_md5_is_correct(self):
        md5 = FileHasher.compute_md5(b"hello world")
        assert md5 == "5eb63bbbe01eeed093cb22bb8f5acdc3"

    def test_sha256_is_correct(self):
        sha256 = FileHasher.compute_sha256(b"hello world")
        assert sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_sha1_is_correct(self):
        sha1 = FileHasher.compute_sha1(b"hello world")
        assert sha1 == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

    def test_empty_data_hashes(self):
        result = FileHasher.compute_all(b"")
        assert len(result["md5"]) == 32
        assert len(result["sha256"]) == 64

    def test_ssdeep_returns_string(self):
        result = FileHasher.compute_ssdeep(b"test data" * 100)
        assert isinstance(result, str)
