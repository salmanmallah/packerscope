"""ML model trainer for PackerScope.

Provides utilities to train, evaluate, and save ML models for
packer classification using extracted features.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packerscope.utils.logger import get_logger

logger = get_logger(__name__)


class ModelTrainer:
    """Train and evaluate ML models for packer classification.

    Supports RandomForest, XGBoost, LightGBM, and CatBoost via
    scikit-learn compatible API.

    Example:
        >>> trainer = ModelTrainer()
        >>> trainer.load_dataset(Path("training_data.csv"))
        >>> results = trainer.train(model_type="random_forest")
        >>> trainer.save_model(Path("models/packer_model.joblib"))
    """

    def __init__(self) -> None:
        self._model: Any | None = None
        self._X: Any | None = None
        self._y: Any | None = None
        self._feature_names: list[str] = []
        self._results: dict[str, Any] = {}

    def load_dataset(self, csv_path: Path) -> None:
        """Load a training dataset from CSV.

        Expected format: CSV with feature columns and a 'label' column.
        Label 0 = not packed, 1+ = packer type index.

        Args:
            csv_path: Path to the training CSV file.
        """
        try:
            import pandas as pd
            df = pd.read_csv(csv_path)

            if "label" not in df.columns:
                raise ValueError("Dataset must have a 'label' column")

            self._y = df["label"].values
            self._X = df.drop(columns=["label"]).select_dtypes(include=["number"]).values
            self._feature_names = [
                c for c in df.columns
                if c != "label" and df[c].dtype in ("int64", "float64")
            ]

            logger.info(
                "dataset_loaded",
                samples=len(df),
                features=len(self._feature_names),
            )
        except ImportError:
            raise ImportError("pandas is required for training: pip install pandas")

    def train(
        self,
        model_type: str = "random_forest",
        test_size: float = 0.2,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Train a classifier on the loaded dataset.

        Args:
            model_type: One of 'random_forest', 'xgboost', 'lightgbm', 'catboost'.
            test_size: Fraction of data to use for testing.
            **kwargs: Additional arguments passed to the model constructor.

        Returns:
            Dictionary with evaluation metrics.
        """
        if self._X is None or self._y is None:
            raise RuntimeError("No dataset loaded. Call load_dataset() first.")

        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report

        X_train, X_test, y_train, y_test = train_test_split(
            self._X, self._y, test_size=test_size, random_state=42, stratify=self._y
        )

        model = self._create_model(model_type, **kwargs)
        model.fit(X_train, y_train)
        self._model = model

        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)

        self._results = {
            "model_type": model_type,
            "accuracy": round(accuracy, 4),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "features": len(self._feature_names),
            "classification_report": report,
        }

        logger.info(
            "model_trained",
            model_type=model_type,
            accuracy=round(accuracy, 4),
        )

        return self._results

    def save_model(self, output_path: Path) -> None:
        """Save the trained model to disk.

        Args:
            output_path: Path for the serialized model file.
        """
        if self._model is None:
            raise RuntimeError("No model trained. Call train() first.")

        import joblib
        output_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, output_path)

        # Save metadata alongside
        meta_path = output_path.with_suffix(".json")
        meta = {
            "feature_names": self._feature_names,
            "results": self._results,
        }
        meta_path.write_text(json.dumps(meta, indent=2, default=str))
        logger.info("model_saved", path=str(output_path))

    @staticmethod
    def _create_model(model_type: str, **kwargs: Any) -> Any:
        """Factory to create the appropriate ML model."""
        if model_type == "random_forest":
            from sklearn.ensemble import RandomForestClassifier
            return RandomForestClassifier(
                n_estimators=kwargs.get("n_estimators", 200),
                max_depth=kwargs.get("max_depth", None),
                random_state=42,
                n_jobs=-1,
            )
        elif model_type == "xgboost":
            from xgboost import XGBClassifier
            return XGBClassifier(
                n_estimators=kwargs.get("n_estimators", 200),
                max_depth=kwargs.get("max_depth", 6),
                random_state=42,
                use_label_encoder=False,
                eval_metric="mlogloss",
            )
        elif model_type == "lightgbm":
            from lightgbm import LGBMClassifier
            return LGBMClassifier(
                n_estimators=kwargs.get("n_estimators", 200),
                max_depth=kwargs.get("max_depth", -1),
                random_state=42,
                verbose=-1,
            )
        elif model_type == "catboost":
            from catboost import CatBoostClassifier
            return CatBoostClassifier(
                iterations=kwargs.get("n_estimators", 200),
                depth=kwargs.get("max_depth", 6),
                random_seed=42,
                verbose=0,
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
