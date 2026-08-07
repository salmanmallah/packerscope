"""Detection plugins for PackerScope.

Auto-exports all built-in detector classes for registration with
the PluginManager.
"""

from packerscope.detectors.entropy_detector import EntropyDetector
from packerscope.detectors.entrypoint_detector import EntryPointDetector
from packerscope.detectors.heuristic_detector import HeuristicDetector
from packerscope.detectors.iat_detector import IATDetector
from packerscope.detectors.ml_detector import MLDetector
from packerscope.detectors.pe_structure_detector import PEStructureDetector
from packerscope.detectors.section_detector import SectionDetector
from packerscope.detectors.signature_detector import SignatureDetector
from packerscope.detectors.yara_detector import YARADetector

ALL_DETECTORS = [
    EntropyDetector,
    SectionDetector,
    IATDetector,
    EntryPointDetector,
    PEStructureDetector,
    SignatureDetector,
    YARADetector,
    MLDetector,
    HeuristicDetector,
]

__all__ = [
    "EntropyDetector",
    "SectionDetector",
    "IATDetector",
    "EntryPointDetector",
    "PEStructureDetector",
    "SignatureDetector",
    "YARADetector",
    "MLDetector",
    "HeuristicDetector",
    "ALL_DETECTORS",
]
