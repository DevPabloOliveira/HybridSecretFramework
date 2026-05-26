# Test Catalog

## Test Families

### 1. Smoke Tests

Purpose: verify imports, CLI availability, and script startup.

```powershell
python -m compileall main.py label_features.py train_classifier.py evaluate_classifier.py modules tests
python main.py --help
python label_features.py --help
python train_classifier.py --help
python evaluate_classifier.py --help
```

### 2. Unit Tests

Purpose: verify isolated behavior such as parsing, data flow, classification,
labeling rules, validator routing, and reporting.

```powershell
python -m unittest discover -s tests
```

### 3. Contract Tests

Purpose: ensure exported features, labeled datasets, model bundles, and result
files remain compatible across scripts.

### 4. Feature Engineering Tests

Purpose: check signals such as:

- `variable_is_sensitive`
- `has_secret_term_nearby`
- `has_placeholder_signal`
- `has_asset_reference`
- `has_downstream_usage`

### 5. Baseline Evaluation

Purpose: measure the heuristic reference model.

```powershell
python evaluate_classifier.py --input results/features_labeled.csv --label-column label
```

### 6. Bootstrap Labeling Tests

Purpose: verify that `label_features.py` does not over-promote documentation noise.

```powershell
python label_features.py --input results/features_labeled.csv --output results/features_labeled_bootstrapped.csv --target-positive-count 10 --review-queue-limit 80
```

### 7. Supervised Training Tests

Purpose: confirm `.joblib` training artifacts are produced correctly.

```powershell
python train_classifier.py --input results/features_labeled_bootstrapped.csv --output models/secret_classifier.joblib --label-column label
```

### 8. Supervised Evaluation Tests

Purpose: compare trained model behavior against the baseline.

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label --classifier-model models/secret_classifier.joblib
```

### 9. End-to-End Tests

Purpose: validate discovery, analysis, reporting, and optional validation.

```powershell
python main.py --token YOUR_GITHUB_TOKEN --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate --export-features results/features_next.csv
```

## Complete Test Flow

1. Smoke tests
2. Unit tests
3. Export features
4. Curate seed labels
5. Bootstrap and review
6. Evaluate baseline
7. Train supervised model
8. Evaluate supervised model
9. Compare quality
10. Run production-like scan
11. Review findings and validation outputs

## Main Artifacts

- `features.csv`
- `features_labeled.csv`
- `features_labeled_bootstrapped.csv`
- `*_review_queue.csv`
- `secret_classifier.joblib`
- `*_SCAN_RAW.csv`
- `*_HYBRID_FINDINGS.csv`
- `*_VALID_KEYS_CONFIRMED.csv`
