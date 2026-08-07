"""Shannon entropy calculation utilities for PE binary analysis.

Provides functions to compute Shannon entropy over raw byte data, individual PE
sections, and sliding windows.  High entropy (≥ 7.0) is a strong indicator of
packed or encrypted content and serves as a first-pass heuristic in the
PackerScope detection pipeline.

Typical usage::

    from packerscope.utils.entropy import calculate_entropy, classify_entropy

    raw = Path("sample.exe").read_bytes()
    ent = calculate_entropy(raw)
    cls = classify_entropy(ent)
    print(f"Entropy: {ent:.4f} ({cls.name})")
"""

from __future__ import annotations

import math
from collections import Counter

import structlog

# Re-export the canonical EntropyClass from core.enums so existing
# ``from packerscope.utils.entropy import EntropyClass`` imports keep working.
from packerscope.core.enums import EntropyClass

__all__ = [
    "EntropyClass",
    "calculate_entropy",
    "calculate_section_entropy",
    "calculate_sliding_window_entropy",
    "classify_entropy",
]

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants — kept in sync with EntropyClass.from_value()
# ---------------------------------------------------------------------------
ENTROPY_LOW_THRESHOLD: float = 3.5
ENTROPY_MEDIUM_THRESHOLD: float = 6.0
ENTROPY_HIGH_THRESHOLD: float = 7.2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def calculate_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of *data* in bits per byte.

    The result ranges from ``0.0`` (all identical bytes) to ``8.0`` (uniformly
    distributed).

    Args:
        data: Raw bytes to analyse.

    Returns:
        Shannon entropy as a ``float`` in the range ``[0.0, 8.0]``.

    Examples:
        >>> calculate_entropy(b"\\x00" * 1024)
        0.0
        >>> round(calculate_entropy(bytes(range(256)) * 4), 4)
        8.0
    """
    length = len(data)
    if length <= 1:
        return 0.0

    counts = Counter(data)
    entropy: float = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_section_entropy(
    data: bytes,
    section_offset: int,
    section_size: int,
) -> float:
    """Compute Shannon entropy for a PE section slice.

    The function clamps the requested range to the available *data* length so
    it never raises on truncated files.

    Args:
        data: Full file bytes.
        section_offset: Byte offset where the section begins (``PointerToRawData``).
        section_size: Size of the section in bytes (``SizeOfRawData``).

    Returns:
        Shannon entropy of the section slice.  Returns ``0.0`` when the
        slice is empty or *section_offset* falls outside *data*.
    """
    if section_offset < 0 or section_size <= 0:
        logger.warning(
            "invalid_section_range",
            offset=section_offset,
            size=section_size,
        )
        return 0.0

    end = min(section_offset + section_size, len(data))
    section_bytes = data[section_offset:end]

    if not section_bytes:
        logger.debug(
            "empty_section_data",
            offset=section_offset,
            size=section_size,
            file_length=len(data),
        )
        return 0.0

    return calculate_entropy(section_bytes)


def calculate_sliding_window_entropy(
    data: bytes,
    window_size: int = 256,
) -> list[float]:
    """Compute Shannon entropy at each position using a sliding window.

    Useful for visualising entropy distribution across a file and locating
    packed regions surrounded by normal code.

    If *data* is shorter than *window_size*, a single entropy value covering
    the entire buffer is returned.

    Args:
        data: Raw bytes to analyse.
        window_size: Number of bytes in each window.  Must be ≥ 1.

    Returns:
        A list of entropy values, one per window position.

    Raises:
        ValueError: If *window_size* < 1.
    """
    if window_size < 1:
        raise ValueError(f"window_size must be >= 1, got {window_size}")

    length = len(data)
    if length == 0:
        return []

    # If the data is shorter than the window, return a single measurement.
    if length <= window_size:
        return [calculate_entropy(data)]

    results: list[float] = []

    # Initialise the frequency counter for the first window.
    counter = Counter(data[:window_size])
    results.append(_entropy_from_counter(counter, window_size))

    # Slide one byte at a time, updating the counter incrementally.
    for i in range(1, length - window_size + 1):
        outgoing = data[i - 1]
        incoming = data[i + window_size - 1]

        counter[outgoing] -= 1
        if counter[outgoing] == 0:
            del counter[outgoing]

        counter[incoming] += 1

        results.append(_entropy_from_counter(counter, window_size))

    return results


def classify_entropy(entropy_value: float) -> EntropyClass:
    """Map a Shannon entropy value to a discrete classification.

    Delegates to :meth:`EntropyClass.from_value` so thresholds are
    defined in a single canonical location.

    Args:
        entropy_value: Entropy in bits-per-byte (``0.0 … 8.0``).

    Returns:
        The corresponding :class:`EntropyClass` member.

    Examples:
        >>> classify_entropy(2.5)
        <EntropyClass.LOW: 'low'>
        >>> classify_entropy(7.5)
        <EntropyClass.VERY_HIGH: 'very_high'>
    """
    # Clamp to valid range rather than raising on edge-case floats
    clamped = max(0.0, min(entropy_value, 8.0))
    return EntropyClass.from_value(clamped)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _entropy_from_counter(counter: Counter[int], total: int) -> float:
    """Fast entropy computation from a pre-built counter.

    Args:
        counter: Byte-value → occurrence-count mapping.
        total: Sum of all counts (== window size).

    Returns:
        Shannon entropy in bits-per-byte.
    """
    if total <= 1:
        return 0.0

    entropy: float = 0.0
    log2_total = math.log2(total)
    for count in counter.values():
        # H = -Σ (c/n) * log2(c/n) = log2(n) - (1/n) * Σ c * log2(c)
        entropy += count * math.log2(count)

    return log2_total - entropy / total
