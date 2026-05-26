import argparse
import json
from typing import Any

import pandas as pd

from modules.core.models import AstContext, FeatureVector, SecretCandidate
from modules.layer4_classification.heuristic_baseline import HeuristicBaselineClassifier
from modules.layer4_classification.sklearn_classifier import SklearnSecretClassifier
from train_classifier import extract_labeled_rows


def build_feature_vector(row: dict[str, Any]) -> FeatureVector:
    """Build a minimal FeatureVector from an exported/labeled feature row."""

    candidate = SecretCandidate(
        repository=str(row.get("Repository", "")),
        file_path=str(row.get("File", row.get("file_path", ""))),
        url=str(row.get("URL", "")),
        raw_url=str(row.get("Raw URL", "")),
        value=str(row.get("Raw Value", row.get("Masked Value", ""))),
        provider=str(row.get("provider", row.get("Secret Type", ""))),
        signature_confidence=str(row.get("signature_confidence", "LOW")),
        start_index=0,
        end_index=0,
        line_number=int(float(row.get("Line", 0) or 0)),
        column_number=0,
        entropy=float(row.get("entropy", 0) or 0),
    )
    context = AstContext(
        language=str(row.get("language", "")),
        parser_name=str(row.get("parser_name", "evaluation-row")),
        ast_node_type=str(row.get("AST Node", "")) or None,
        variable_name=str(row.get("Associated Variable", "")) or None,
    )
    return FeatureVector(candidate=candidate, ast_context=context, features=row, evidence=[])


def evaluate(input_csv: str, label_column: str, model_path: str | None) -> dict[str, Any]:
    """Evaluate baseline or supervised classifier on a labeled feature CSV."""

    try:
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    except Exception as exc:
        raise RuntimeError("scikit-learn is required for evaluation metrics.") from exc

    data = pd.read_csv(input_csv).fillna("")
    labeled_data, y_true = extract_labeled_rows(data, label_column)

    classifier = SklearnSecretClassifier(model_path) if model_path else HeuristicBaselineClassifier()
    y_pred: list[int] = []
    confidences: list[float] = []

    for _, row in labeled_data.iterrows():
        decision = classifier.classify(build_feature_vector(row.to_dict()))
        y_pred.append(1 if decision.approved else 0)
        confidences.append(decision.confidence)

    report = classification_report(y_true, y_pred, labels=[0, 1], output_dict=True, zero_division=0)
    return {
        "model": getattr(classifier, "model_name", classifier.__class__.__name__),
        "input_rows": len(data),
        "rows": len(y_true),
        "ignored_review_rows": len(data) - len(y_true),
        "accuracy": accuracy_score(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "classification_report": report,
        "average_confidence": sum(confidences) / len(confidences) if confidences else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate HybridSecretFramework classifiers on labeled feature CSVs."
    )
    parser.add_argument("--input", required=True, help="CSV exported by --export-features and manually labeled")
    parser.add_argument("--label-column", default="label", help="Ground-truth label column")
    parser.add_argument("--classifier-model", help="Optional supervised .joblib model; baseline is used when omitted")
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()

    metrics = evaluate(args.input, args.label_column, args.classifier_model)
    rendered = json.dumps(metrics, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")


if __name__ == "__main__":
    main()
