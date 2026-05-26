# HybridSecretFramework Architecture Alignment

This document maps the current implementation to the systematic mapping on
Machine Learning and AST-based static analysis for reducing false positives in
secret detection.

## Alignment Summary

The repository implements the complete five-layer architecture described by the
review:

| Paper Layer | Implementation | Status |
| --- | --- | --- |
| Layer 1: Regex and entropy recovery | `modules/layer1_retrieval/` | Implemented |
| Layer 2: AST and structural parsing | `modules/layer2_parsing/` | Implemented for Python/config; Tree-sitter adapter available for other languages |
| Layer 3: syntactic, contextual, and statistical features | `modules/layer3_features/` | Implemented |
| Layer 4: ML-ready classification | `modules/layer4_classification/`, `train_classifier.py` | Implemented with baseline and Scikit-Learn bundle support |
| Layer 5: prioritization and explainability | `modules/layer5_reporting/` | Implemented |

## Research Question Mapping

| Research Question | Repository Evidence | Remaining Scientific Dependency |
| --- | --- | --- |
| QP1: supervised models for secret classification | `SklearnSecretClassifier`, `FeatureEncoder`, `train_classifier.py` | A labeled dataset is required to train and compare final models |
| QP2: AST/context for semantic features | `PythonAstParser`, `ConfigParser`, `TreeSitterParser`, `PythonDataFlowAnalyzer` | Whole-program and interprocedural data flow are still future extensions |
| QP3: precision, recall, F1, false positives | `evaluate_classifier.py` reports accuracy, confusion matrix, precision, recall, and F1 | Metrics become meaningful only after manual labels or benchmark labels are provided |
| QP4: Regex limitations | Regex is restricted to candidate recovery; classifier decides final approval | Ongoing signature tuning should be benchmark-driven |

## Implemented Scientific Capabilities

- Regex and entropy are used as a high-recall recovery layer, not as final truth.
- Python AST extraction identifies literal nodes, assignment targets, enclosing functions, and call context.
- Configuration parsing extracts key/value semantics from `.env`, YAML-like, JSON-like, and properties-style files.
- Data-flow slicing links assigned candidates to later call sites inside the same Python file.
- Secret-asset association detects nearby URLs, hosts, and database connection strings.
- Feature extraction includes syntactic, contextual, statistical, placeholder, asset, and path-based signals.
- The classification layer supports both a transparent baseline and persisted Scikit-Learn model bundles.
- Active API validation is gated by classifier confidence and remains implemented through the Strategy pattern.
- Reports include masked value, type, file, line, AST node, associated variable, usage calls, assets, confidence, risk, and evidence.
- The evaluation workflow can export candidate features, train a model, and compute precision/recall/F1 on labeled CSVs.

## Reproducible Workflow

1. Recover and analyze candidates while exporting all features:

```powershell
python main.py --token YOUR_TOKEN --input config/shodan_patterns.csv --export-features results/features.csv
```

2. Label the exported CSV with a `label` column using values such as `real_secret` or `false_positive`.

3. Train a supervised classifier:

```powershell
python train_classifier.py --input results/features_labeled.csv --output models/secret_classifier.joblib --label-column label
```

4. Evaluate baseline or supervised classifier:

```powershell
python evaluate_classifier.py --input results/features_labeled.csv --label-column label
python evaluate_classifier.py --input results/features_labeled.csv --label-column label --classifier-model models/secret_classifier.joblib
```

5. Run the production scan with the trained classifier:

```powershell
python main.py --token YOUR_TOKEN --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib
```

## Honest Completion Criteria

The codebase is aligned with the paper at the implementation-architecture level.
The remaining work for full academic validation is empirical rather than
structural: label a representative dataset, run `evaluate_classifier.py`, compare
baseline vs supervised model, and report precision, recall, F1, false-positive
rate, and false-negative rate.
