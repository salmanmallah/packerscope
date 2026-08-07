"""Utilities module — shared helpers, hashing, entropy, and file I/O.

Re-exports the most commonly used symbols so that downstream code can write::

    from packerscope.utils import calculate_entropy, classify_entropy, FileHasher
"""

from packerscope.utils.entropy import calculate_entropy, classify_entropy
from packerscope.utils.hasher import FileHasher
from packerscope.utils.logger import get_logger, setup_logging

__all__ = [
    "FileHasher",
    "calculate_entropy",
    "classify_entropy",
    "get_logger",
    "setup_logging",
]
