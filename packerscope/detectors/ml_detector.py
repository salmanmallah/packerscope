"""Machine learning-based packer detection for PackerScope.

Loads a pre-trained ML model and runs inference on the feature vector
extracted from the PEContext. Gracefully degrades when no model is
available or ML dependencies are missing.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from packerscope.core.enums import DetectionMethod, PackerType
from packerscope.core.interfaces import BaseDetector
from packerscope.core.models import DetectionResult
from packerscope.utils.logger import get_logger

if TYPE_CHECKING:
    from packerscope.context import PEContext

logger = get_logger(__name__)


def _ml_available() -> bool:
    """Check if scikit-learn is importable."""
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


class MLDetector(BaseDetector):
    """ML-based packer classifier.

    Loads a pre-trained model (joblib serialized) and runs inference on
    the feature vector. Returns empty results if no model is loaded or
    ML libraries are unavailable.

    Supported models: RandomForest, XGBoost, LightGBM, CatBoost
    (all via scikit-learn compatible API).
    """

    name: str = "ml_classifier"
    description: str = "Machine learning-based packer classification"
    version: str = "1.0.0"
    priority: int = 90  # Runs late — after feature-contributing detectors
    enabled: bool = False  # Disabled by default until model is trained

    def __init__(self, model_path: Path | None = None) -> None:
        self._model: Any | None = None
        self._model_path = model_path
        self._label_map: dict[int, PackerType] = {}

        if model_path and model_path.exists():
            self._load_model(model_path)

    def is_available(self) -> bool:
        """Check if ML dependencies and a trained model are available."""
        return _ml_available() and self._model is not None

    def detect(self, ctx: PEContext) -> DetectionResult:
        """Run ML inference on the extracted feature vector.

        Args:
            ctx: Shared analysis context.

        Returns:
            DetectionResult with ML classification findings.
        """
        start = time.monotonic()

        if not self.is_available():
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.MACHINE_LEARNING,
                is_packed=False,
                reasons=["ML model not available — skipping"],
                duration_seconds=time.monotonic() - start,
            )

        if ctx.features is None:
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.MACHINE_LEARNING,
                is_packed=False,
                reasons=["No feature vector extracted — skipping ML"],
                duration_seconds=time.monotonic() - start,
            )

        try:
            import numpy as np

            feature_array = np.array([ctx.features.to_array()])
            prediction = self._model.predict(feature_array)[0]
            probabilities = {}

            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(feature_array)[0]
                classes = self._model.classes_
                probabilities = {
                    str(cls): round(float(p), 4)
                    for cls, p in zip(classes, proba)
                }

            is_packed = bool(prediction != 0)  # 0 = not packed
            confidence = max(probabilities.values()) if probabilities else 0.5
            packer_hint = self._label_map.get(int(prediction), PackerType.GENERIC_PACKED)

            reasons = [
                f"ML prediction: {packer_hint.value} (confidence: {confidence:.2%})"
            ]

            duration = time.monotonic() - start
            logger.info(
                "ml_inference_complete",
                prediction=packer_hint.value,
                confidence=round(confidence, 4),
            )

            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.MACHINE_LEARNING,
                is_packed=is_packed,
                packer_hint=packer_hint,
                confidence=round(confidence, 4),
                reasons=reasons,
                details={
                    "probabilities": probabilities,
                    "raw_prediction": int(prediction),
                },
                duration_seconds=round(duration, 6),
            )

        except Exception as e:
            logger.error("ml_inference_error", error=str(e))
            return DetectionResult(
                detector_name=self.name,
                method=DetectionMethod.MACHINE_LEARNING,
                is_packed=False,
                reasons=[f"ML inference error: {e}"],
                duration_seconds=time.monotonic() - start,
            )

    def _load_model(self, model_path: Path) -> None:
        """Load a serialized ML model from disk."""
        try:
            import joblib
            self._model = joblib.load(model_path)
            logger.info("ml_model_loaded", path=str(model_path))
        except Exception as e:
            logger.error("ml_model_load_error", error=str(e), path=str(model_path))
            self._model = None
