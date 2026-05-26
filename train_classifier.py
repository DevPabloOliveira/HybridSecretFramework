import argparse
import json
import os
from pathlib import Path
from typing import Any

import pandas as pd

from modules.layer4_classification.feature_encoding import DEFAULT_FEATURE_ORDER, FeatureEncoder


POSITIVE_LABELS = {"1", "true", "yes", "y", "real", "real_secret", "secret"}
NEGATIVE_LABELS = {"0", "false", "no", "n", "false_positive", "negative", "fp"}


def normalize_label(value: Any) -> int:
    """Normalize CSV labels to 0/1 for supervised training."""

    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        if pd.isna(value):
            return 0
        return 1 if int(value) == 1 else 0
    return 1 if str(value).strip().lower() in POSITIVE_LABELS else 0


def extract_labeled_rows(data: pd.DataFrame, label_column: str) -> tuple[pd.DataFrame, list[int]]:
    """Resolve labeled rows from either a text label column or one-hot columns.

    Supported layouts:
    - `label` column with values like `real_secret` / `false_positive`
    - boolean-ish `real_secret` and/or `false_positive` columns

    Rows marked as `review` or left blank are excluded so active-learning queues
    do not pollute supervised training/evaluation metrics.
    """

    if label_column in data.columns:
        labels: list[int] = []
        indices: list[int] = []
        for idx, value in data[label_column].items():
            normalized = str(value).strip().lower()
            if not normalized or normalized == "nan" or normalized == "review":
                continue
            if normalized in POSITIVE_LABELS:
                labels.append(1)
                indices.append(idx)
            elif normalized in NEGATIVE_LABELS:
                labels.append(0)
                indices.append(idx)
        return data.loc[indices].reset_index(drop=True), labels

    has_real_secret = "real_secret" in data.columns
    has_false_positive = "false_positive" in data.columns
    if has_real_secret or has_false_positive:
        kept_rows: list[int] = []
        labels: list[int] = []
        for idx, row in data.iterrows():
            real_secret = normalize_label(row.get("real_secret", 0))
            false_positive = normalize_label(row.get("false_positive", 0))

            if real_secret == 1 and false_positive == 0:
                labels.append(1)
                kept_rows.append(idx)
            elif false_positive == 1 and real_secret == 0:
                labels.append(0)
                kept_rows.append(idx)
            elif real_secret == 1 and false_positive == 1:
                raise ValueError(
                    "A row in the labeled CSV marks both 'real_secret' and "
                    "'false_positive' as positive. Please keep only one truthy label per row."
                )
        return data.loc[kept_rows].reset_index(drop=True), labels

    available = ", ".join(data.columns.tolist())
    raise ValueError(
        f"Label column '{label_column}' was not found, and no one-hot label columns "
        f"('real_secret'/'false_positive') were present. Available columns: {available}"
    )


def resolve_labels(data: pd.DataFrame, label_column: str) -> list[int]:
    """Backward-compatible helper used by tests and evaluation."""

    if label_column in data.columns:
        return [normalize_label(value) for value in data[label_column]]

    has_real_secret = "real_secret" in data.columns
    has_false_positive = "false_positive" in data.columns
    if has_real_secret or has_false_positive:
        labels: list[int] = []
        for _, row in data.iterrows():
            real_secret = normalize_label(row.get("real_secret", 0))
            false_positive = normalize_label(row.get("false_positive", 0))

            if real_secret == 1 and false_positive == 0:
                labels.append(1)
            elif false_positive == 1 and real_secret == 0:
                labels.append(0)
            elif real_secret == 1 and false_positive == 1:
                raise ValueError(
                    "A row in the labeled CSV marks both 'real_secret' and "
                    "'false_positive' as positive. Please keep only one truthy label per row."
                )
            else:
                labels.append(0)
        return labels

    _, labels = extract_labeled_rows(data, label_column)
    return labels


def load_feature_order(path: str | None) -> list[str]:
    """Load a feature schema from JSON or use the default stabilized schema."""

    if not path:
        return list(DEFAULT_FEATURE_ORDER)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = data.get("feature_order")
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise ValueError("Feature order file must be a JSON list or an object with feature_order.")
    return data


def train_model(
    input_csv: str,
    output_path: str,
    label_column: str,
    feature_order: list[str],
    test_size: float,
) -> dict[str, Any]:
    """Train and persist a supervised Scikit-Learn model bundle."""

    try:
        import joblib
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except Exception as exc:
        raise RuntimeError("scikit-learn and joblib are required for model training.") from exc

    data = pd.read_csv(input_csv)

    labeled_data, y = extract_labeled_rows(data, label_column)
    encoder = FeatureEncoder(feature_order)
    x = [encoder.encode(row.to_dict()) for _, row in labeled_data.iterrows()]
    if len(set(y)) < 2:
        raise ValueError("Training data must contain at least one positive and one negative example.")

    model = Pipeline(
        steps=[
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )

    metrics: dict[str, Any] = {
        "input_rows": len(data),
        "training_rows": len(y),
        "positive_rows": sum(y),
        "negative_rows": len(y) - sum(y),
        "ignored_review_rows": len(data) - len(y),
    }
    if len(y) >= 6 and min(y.count(0), y.count(1)) >= 2:
        x_train, x_test, y_train, y_test = train_test_split(
            x,
            y,
            test_size=test_size,
            random_state=42,
            stratify=y,
        )
        model.fit(x_train, y_train)
        y_pred = model.predict(x_test)
        metrics["classification_report"] = classification_report(y_test, y_pred, output_dict=True)
    else:
        model.fit(x, y)
        metrics["classification_report"] = "Not generated: dataset too small for stratified split."

    artifact = {
        "model": model,
        "feature_order": feature_order,
        "model_name": "sklearn-logistic-regression-v1",
        "metrics": metrics,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a supervised HybridSecretFramework secret classifier."
    )
    parser.add_argument("--input", required=True, help="CSV containing feature columns and a label column")
    parser.add_argument("--output", required=True, help="Output .joblib model bundle path")
    parser.add_argument("--label-column", default="label", help="Label column; positive labels mean real secret")
    parser.add_argument("--feature-order-file", help="Optional JSON feature schema")
    parser.add_argument("--test-size", type=float, default=0.25, help="Evaluation split size")
    args = parser.parse_args()

    feature_order = load_feature_order(args.feature_order_file)
    metrics = train_model(args.input, args.output, args.label_column, feature_order, args.test_size)
    print(f"Saved trained classifier to {os.path.abspath(args.output)}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
