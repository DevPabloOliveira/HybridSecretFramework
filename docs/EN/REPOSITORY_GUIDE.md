# Repository Guide

## Purpose

HybridSecretFramework scans GitHub-recovered source artifacts for exposed secrets while
trying to avoid the classic failure mode of Regex-only scanners: confusing real
credentials with examples, identifiers, hashes, screenshots, placeholders, and
code symbols.

The repository uses a five-layer hybrid pipeline:

1. Recovery
2. Parsing
3. Feature Extraction
4. Classification
5. Reporting and Validation

## High-Level Flow

```text
GitHub pattern search
  -> raw file recovery
  -> Regex and entropy candidate extraction
  -> parser selection by language/path
  -> AST/context extraction
  -> feature extraction
  -> baseline or supervised classifier
  -> explainable findings
  -> optional provider-aware validation
```

## Directory Structure

```text
config/
docs/
models/
modules/
results/
tests/
main.py
label_features.py
train_classifier.py
evaluate_classifier.py
```

## Main Entry Points

- `main.py`: end-to-end scan, analysis, reporting, and optional validation
- `train_classifier.py`: supervised model training
- `evaluate_classifier.py`: baseline or supervised model evaluation
- `label_features.py`: bootstrap labeling and review queue generation

## Module Map

### `modules/core/`

- `models.py`: pipeline dataclasses and report models
- `pipeline.py`: five-layer orchestration
- `masking.py`: masking helpers
- `language.py`: language/path heuristics

### `modules/layer1_retrieval/`

- `signatures.py`
- `entropy.py`
- `candidate_retriever.py`
- `content_fetcher.py`

### `modules/layer2_parsing/`

- `parser_registry.py`
- `python_parser.py`
- `python_data_flow.py`
- `config_parser.py`
- `tree_sitter_parser.py`

### `modules/layer3_features/`

- `feature_extractor.py`
- `syntactic_features.py`
- `contextual_features.py`
- `statistical_features.py`
- `placeholder_detection.py`
- `asset_features.py`

### `modules/layer4_classification/`

- `classifier.py`
- `heuristic_baseline.py`
- `feature_encoding.py`
- `sklearn_classifier.py`
- `threshold_policy.py`

### `modules/layer5_reporting/`

- `risk.py`
- `explanation.py`
- `reporter.py`

### `modules/validators/`

- `shodan.py`
- `google.py`
- `scrapingbee.py`
- `generic.py`
- `passive.py`

## Operational Workflow

### Export features

```powershell
python main.py --token YOUR_GITHUB_TOKEN --input config/shodan_patterns.csv --export-features results/features.csv
```

### Bootstrap and review labels

```powershell
python label_features.py --input results/features_labeled.csv --output results/features_labeled_bootstrapped.csv --target-positive-count 10 --review-queue-limit 80
```

### Train

```powershell
python train_classifier.py --input results/features_labeled_bootstrapped.csv --output models/secret_classifier.joblib --label-column label
```

### Evaluate

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label --classifier-model models/secret_classifier.joblib
```

### Production-like scan

```powershell
python main.py --token YOUR_GITHUB_TOKEN --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate --export-features results/features_next.csv
```

## Result Files

- `*_1_SCAN_RAW.csv`: raw recovered files
- `*_2_HYBRID_FINDINGS.csv`: explainable approved findings
- `*_3_VALID_KEYS_CONFIRMED.csv`: active validation successes
- `features*.csv`: exported feature sets, labels, and review queues

## Safe Validation Policy

- Sensitive providers such as GitHub and AWS are routed to passive review
- Google, Shodan, and ScrapingBee can use provider-aware validators
- Generic candidates are never treated as verified simply because they match a format
