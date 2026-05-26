# HybridSecretFramework

HybridSecretFramework is the implementation artifact for **A Hybrid AST- and
Machine Learning-Based Framework for Secret Detection**. It is a hybrid
secret-detection pipeline designed to reduce false positives by combining broad
recovery heuristics with structural parsing, feature extraction, supervised
classification, and explainable reporting.

The repository implements the five-layer architecture discussed in the
systematic review on Machine Learning and AST-based analysis for secret
detection:

1. Recovery with Regex and entropy
2. Language-aware parsing and AST/context extraction
3. Syntactic, contextual, statistical, and asset-oriented features
4. ML-ready classification with heuristic and supervised modes
5. Risk scoring, explainability, and gated validation

## Documentation

- Documentation index: [docs/README.md](C:\Users\Oliveira\Documents\OmniKeyHunter\docs\README.md)
- Portuguese guide: [docs/PTBR/GUIA_REPOSITORIO.md](C:\Users\Oliveira\Documents\OmniKeyHunter\docs\PTBR\GUIA_REPOSITORIO.md)
- Portuguese test catalog: [docs/PTBR/CATALOGO_TESTES.md](C:\Users\Oliveira\Documents\OmniKeyHunter\docs\PTBR\CATALOGO_TESTES.md)
- Portuguese architecture alignment: [docs/PTBR/ALINHAMENTO_ARQUITETURA.md](C:\Users\Oliveira\Documents\OmniKeyHunter\docs\PTBR\ALINHAMENTO_ARQUITETURA.md)
- English guide: [docs/EN/REPOSITORY_GUIDE.md](C:\Users\Oliveira\Documents\OmniKeyHunter\docs\EN\REPOSITORY_GUIDE.md)

## Quick Start

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the baseline pipeline:

```powershell
python main.py --token YOUR_GITHUB_TOKEN --input config/shodan_patterns.csv --export-features results/features.csv
```

Train a supervised classifier from labeled features:

```powershell
python train_classifier.py --input results/features_labeled.csv --output models/secret_classifier.joblib --label-column label
```

Evaluate the baseline and the trained model:

```powershell
python evaluate_classifier.py --input results/features_labeled.csv --label-column label
python evaluate_classifier.py --input results/features_labeled.csv --label-column label --classifier-model models/secret_classifier.joblib
```

Run the pipeline with the trained model and auto-routed validation:

```powershell
python main.py --token YOUR_GITHUB_TOKEN --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate
```

## Main Entry Points

- `main.py`: end-to-end scan, analysis, reporting, and optional validation
- `train_classifier.py`: supervised model training
- `evaluate_classifier.py`: baseline or supervised model evaluation
- `label_features.py`: bootstrap labeling and review queue generation

## Status

The repository is structurally aligned with the academic architecture. The
remaining quality gains come from better labeled data, controlled review of
near misses, and periodic retraining with curated examples.
