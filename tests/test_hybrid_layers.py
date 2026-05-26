import unittest
import asyncio
import tempfile
from pathlib import Path

import joblib
import pandas as pd

from evaluate_classifier import evaluate
from label_features import apply_bootstrap_labels, classify_review_bucket
from train_classifier import extract_labeled_rows, resolve_labels, train_model
from modules.core.models import SourceFile
from modules.core.pipeline import HybridSecretPipeline
from modules.layer4_classification.feature_encoding import DEFAULT_FEATURE_ORDER
from modules.layer1_retrieval.candidate_retriever import CandidateRetriever
from modules.layer2_parsing.parser_registry import ParserRegistry
from modules.layer3_features.feature_extractor import FeatureExtractor
from modules.layer4_classification.heuristic_baseline import HeuristicBaselineClassifier
from modules.layer4_classification.sklearn_classifier import SklearnSecretClassifier
from modules.layer5_reporting.reporter import FindingReporter
from modules.validator import HybridSecretValidator


class AlwaysPositiveModel:
    def predict_proba(self, rows):
        return [[0.03, 0.97] for _ in rows]


class HybridLayerTests(unittest.TestCase):
    def test_pipeline_orchestrates_all_five_layers(self):
        secret = "Lt3whkyVHH7iAtP28iNIq7hVNlK638vR"
        source = SourceFile(
            repository="acme/app",
            path="src/settings.py",
            url="https://example.test/blob/settings.py",
            raw_url="https://example.test/raw/settings.py",
            content=f'SHODAN_API_KEY = "{secret}"\n',
        )

        class StaticFetcher:
            async def fetch_many(self, items):
                return [source]

        pipeline = HybridSecretPipeline()
        pipeline.fetcher = StaticFetcher()
        findings = asyncio.run(pipeline.run([{}]))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].variable_name, "SHODAN_API_KEY")
        self.assertEqual(findings[0].risk_level, "HIGH")

    def test_pipeline_can_replace_baseline_with_sklearn_model_bundle(self):
        secret = "Lt3whkyVHH7iAtP28iNIq7hVNlK638vR"
        source = SourceFile(
            repository="acme/app",
            path="src/settings.py",
            url="https://example.test/blob/settings.py",
            raw_url="https://example.test/raw/settings.py",
            content=f'SHODAN_API_KEY = "{secret}"\n',
        )

        class StaticFetcher:
            async def fetch_many(self, items):
                return [source]

        with tempfile.TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "secret_classifier.joblib"
            joblib.dump(
                {
                    "model": AlwaysPositiveModel(),
                    "feature_order": DEFAULT_FEATURE_ORDER,
                    "model_name": "unit-supervised-model",
                },
                model_path,
            )

            pipeline = HybridSecretPipeline(classifier=SklearnSecretClassifier(str(model_path)))
            pipeline.fetcher = StaticFetcher()
            findings = asyncio.run(pipeline.run([{}]))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].model_name, "unit-supervised-model")
        self.assertGreaterEqual(findings[0].confidence, 0.97)

    def test_python_data_flow_links_secret_to_call_and_asset(self):
        secret = "Lt3whkyVHH7iAtP28iNIq7hVNlK638vR"
        source = SourceFile(
            repository="acme/app",
            path="src/enrichment.py",
            url="https://example.test/blob/enrichment.py",
            raw_url="https://example.test/raw/enrichment.py",
            content=(
                f'SHODAN_API_KEY = "{secret}"\n'
                'response = requests.get("https://api.shodan.io/api-info", params={"key": SHODAN_API_KEY})\n'
            ),
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)
        finding = FindingReporter().build(candidate, features, decision)

        self.assertIn("requests.get", ast_context.downstream_calls)
        self.assertTrue(features.features["has_downstream_usage"])
        self.assertTrue(features.features["has_asset_reference"])
        self.assertIn("https://api.shodan.io/api-info", features.features["asset_references"])
        self.assertGreaterEqual(finding.risk_score, 0.85)

    def test_pipeline_analyze_exports_rejected_and_approved_candidates(self):
        good_secret = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        noisy_value = "1234567890abcdef1234567890abcdef"
        source = SourceFile(
            repository="acme/app",
            path="tests/test_settings.py",
            url="https://example.test/blob/test_settings.py",
            raw_url="https://example.test/raw/test_settings.py",
            content=(
                f'SHODAN_API_KEY = "{good_secret}"\n'
                f'CHECKSUM = "{noisy_value}"  # example hash\n'
            ),
        )

        class StaticFetcher:
            async def fetch_many(self, items):
                return [source]

        pipeline = HybridSecretPipeline()
        pipeline.fetcher = StaticFetcher()
        analyses = asyncio.run(pipeline.analyze([{}]))
        rows = [analysis.to_feature_row() for analysis in analyses]

        self.assertEqual(len(rows), 2)
        self.assertIn("Classifier Label", rows[0])
        self.assertIn("has_placeholder_signal", rows[0])

    def test_training_script_persists_sklearn_bundle(self):
        rows = [
            {
                "length": 32,
                "entropy": 4.2,
                "digit_ratio": 0.2,
                "alpha_ratio": 0.8,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_ast_context": True,
                "has_variable_name": True,
                "variable_is_sensitive": True,
                "call_is_auth_related": False,
                "is_assignment_context": True,
                "has_secret_term_nearby": True,
                "nearest_secret_term_distance": 10,
                "has_hash_or_identifier_term": False,
                "has_placeholder_signal": False,
                "is_documentation_or_test_path": False,
                "language": "python",
                "label": "real_secret",
            },
            {
                "length": 32,
                "entropy": 3.7,
                "digit_ratio": 0.8,
                "alpha_ratio": 0.2,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_ast_context": True,
                "has_variable_name": True,
                "variable_is_sensitive": False,
                "call_is_auth_related": False,
                "is_assignment_context": True,
                "has_secret_term_nearby": False,
                "nearest_secret_term_distance": "",
                "has_hash_or_identifier_term": True,
                "has_placeholder_signal": True,
                "is_documentation_or_test_path": True,
                "language": "python",
                "label": "false_positive",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "training.csv"
            model_path = Path(tmp) / "model.joblib"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            metrics = train_model(str(csv_path), str(model_path), "label", list(DEFAULT_FEATURE_ORDER), 0.25)
            artifact = joblib.load(model_path)

        self.assertEqual(metrics["training_rows"], 2)
        self.assertEqual(artifact["model_name"], "sklearn-logistic-regression-v1")
        self.assertEqual(artifact["feature_order"], DEFAULT_FEATURE_ORDER)

    def test_resolve_labels_accepts_one_hot_columns(self):
        data = pd.DataFrame(
            [
                {"real_secret": 1, "false_positive": 0},
                {"real_secret": 0, "false_positive": 1},
                {"real_secret": "", "false_positive": ""},
            ]
        )

        labels = resolve_labels(data, "label")
        self.assertEqual(labels, [1, 0, 0])

    def test_extract_labeled_rows_ignores_review_entries(self):
        data = pd.DataFrame(
            [
                {"label": "real_secret"},
                {"label": "false_positive"},
                {"label": "review"},
                {"label": ""},
            ]
        )

        filtered, labels = extract_labeled_rows(data, "label")
        self.assertEqual(len(filtered), 2)
        self.assertEqual(labels, [1, 0])

    def test_evaluation_script_reports_precision_recall_f1(self):
        rows = [
            {
                "length": 32,
                "entropy": 4.2,
                "digit_ratio": 0.2,
                "alpha_ratio": 0.8,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_variable_name": True,
                "variable_is_sensitive": True,
                "is_assignment_context": True,
                "has_secret_term_nearby": True,
                "has_downstream_usage": True,
                "has_asset_reference": True,
                "has_placeholder_signal": False,
                "is_documentation_or_test_path": False,
                "label": "real_secret",
            },
            {
                "length": 32,
                "entropy": 3.7,
                "digit_ratio": 0.8,
                "alpha_ratio": 0.2,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_variable_name": True,
                "variable_is_sensitive": False,
                "is_assignment_context": True,
                "has_secret_term_nearby": False,
                "has_hash_or_identifier_term": True,
                "has_placeholder_signal": True,
                "is_documentation_or_test_path": True,
                "label": "false_positive",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "eval.csv"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            metrics = evaluate(str(csv_path), "label", None)

        self.assertEqual(metrics["rows"], 2)
        self.assertIn("classification_report", metrics)
        self.assertIn("1", metrics["classification_report"])

    def test_evaluation_script_accepts_one_hot_label_columns(self):
        rows = [
            {
                "length": 32,
                "entropy": 4.2,
                "digit_ratio": 0.2,
                "alpha_ratio": 0.8,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_variable_name": True,
                "variable_is_sensitive": True,
                "is_assignment_context": True,
                "has_secret_term_nearby": True,
                "has_downstream_usage": True,
                "has_asset_reference": True,
                "real_secret": 1,
                "false_positive": 0,
            },
            {
                "length": 32,
                "entropy": 3.7,
                "digit_ratio": 0.8,
                "alpha_ratio": 0.2,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_variable_name": True,
                "variable_is_sensitive": False,
                "is_assignment_context": True,
                "has_secret_term_nearby": False,
                "has_hash_or_identifier_term": True,
                "has_placeholder_signal": True,
                "is_documentation_or_test_path": True,
                "real_secret": 0,
                "false_positive": 1,
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "eval_one_hot.csv"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            metrics = evaluate(str(csv_path), "label", None)

        self.assertEqual(metrics["rows"], 2)
        self.assertIn("classification_report", metrics)

    def test_python_assignment_with_sensitive_variable_is_approved(self):
        secret = "Lt3whkyVHH7iAtP28iNIq7hVNlK638vR"
        source = SourceFile(
            repository="acme/app",
            path="src/settings.py",
            url="https://example.test/blob/settings.py",
            raw_url="https://example.test/raw/settings.py",
            content=f'SHODAN_API_KEY = "{secret}"\n',
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)

        self.assertEqual(ast_context.variable_name, "SHODAN_API_KEY")
        self.assertTrue(features.features["variable_is_sensitive"])
        self.assertTrue(decision.approved)

    def test_placeholder_in_test_path_is_rejected(self):
        candidate_value = "1234567890abcdef1234567890abcdef"
        source = SourceFile(
            repository="acme/app",
            path="tests/test_settings.py",
            url="https://example.test/blob/test_settings.py",
            raw_url="https://example.test/raw/test_settings.py",
            content=f'API_KEY = "{candidate_value}"  # example value\n',
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)

        self.assertTrue(features.features["has_placeholder_signal"])
        self.assertTrue(features.features["is_documentation_or_test_path"])
        self.assertFalse(decision.approved)

    def test_documentation_template_github_token_is_rejected(self):
        candidate_value = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        source = SourceFile(
            repository="acme/app",
            path="API_KEYS.md",
            url="https://example.test/blob/API_KEYS.md",
            raw_url="https://example.test/raw/API_KEYS.md",
            content=(
                'github_api_key: "ghp_abcdefghijklmnopqrstuvwxyz1234567890"  '
                "# Only add the keys you actually have, leave others empty or delete\n"
            ),
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)

        self.assertTrue(features.features["has_template_language"])
        self.assertTrue(features.features["has_placeholder_signal"])
        self.assertTrue(features.features["is_template_file"])
        self.assertFalse(decision.approved)

    def test_documented_secret_dump_with_asset_remains_approved(self):
        candidate_value = "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"
        source = SourceFile(
            repository="acme/notes",
            path="ReconX/keys.md",
            url="https://example.test/blob/keys.md",
            raw_url="https://example.test/raw/keys.md",
            content=(
                "Github:\n"
                f"- {candidate_value}\n"
                "Amazon:\n"
                "- Access Key ID: AKIAWOZK5BFSA7IDTLF3\n"
                "- Secret Access Key: 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\n"
                "- FOFA_EMAIL: user@geekjun.com\n"
            ),
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)

        self.assertFalse(features.features["is_template_file"])
        self.assertFalse(features.features["is_weak_documentation_context"])
        self.assertTrue(features.features["has_asset_reference"])
        self.assertTrue(decision.approved)

    def test_config_parser_extracts_associated_key(self):
        secret = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
        source = SourceFile(
            repository="acme/app",
            path=".env",
            url="https://example.test/blob/.env",
            raw_url="https://example.test/raw/.env",
            content=f"SHODAN_KEY={secret}\n",
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)

        self.assertEqual(ast_context.ast_node_type, "ConfigProperty")
        self.assertEqual(ast_context.variable_name, "SHODAN_KEY")

    def test_report_masks_raw_value_by_default(self):
        secret = "Lt3whkyVHH7iAtP28iNIq7hVNlK638vR"
        source = SourceFile(
            repository="acme/app",
            path="src/settings.py",
            url="https://example.test/blob/settings.py",
            raw_url="https://example.test/raw/settings.py",
            content=f'SHODAN_API_KEY = "{secret}"\n',
        )

        candidate = CandidateRetriever().retrieve(source)[0]
        ast_context = ParserRegistry().analyze(source.path, source.content, candidate)
        features = FeatureExtractor().extract(source.content, candidate, ast_context)
        decision = HeuristicBaselineClassifier().classify(features)
        finding = FindingReporter().build(candidate, features, decision)
        row = finding.to_report_row()

        self.assertNotIn("Raw Value", row)
        self.assertEqual(row["Masked Value"], "Lt3w********38vR")

    def test_validator_auto_routing_skips_sensitive_github_tokens(self):
        validator = HybridSecretValidator()
        service_name = validator.resolve_service("GitHub Token", "auto")
        result = validator.validate(service_name, "ghp_abcdefghijklmnopqrstuvwxyz1234567890", "GitHub Token")

        self.assertEqual(service_name, "passive")
        self.assertFalse(result["valid"])
        self.assertIn("Skipped active validation", result["details"])

    def test_validator_auto_routing_uses_provider_specific_service(self):
        validator = HybridSecretValidator()
        self.assertEqual(validator.resolve_service("Google API Key", "auto"), "google")
        self.assertEqual(validator.resolve_service("Shodan API Key", "auto"), "shodan")
        self.assertEqual(validator.resolve_service("Unknown Type", "auto"), "generic")

    def test_label_bootstrap_promotes_realistic_code_and_preserves_placeholder_doc(self):
        rows = pd.DataFrame(
            [
                {
                    "Repository": "acme/code",
                    "File": ".env",
                    "Line": 1,
                    "Secret Type": "Generic 32-char Candidate",
                    "Classifier Confidence": 0.48,
                    "context_window": 'SHODAN_API_KEY="AbCdEfGhIjKlMnOpQrStUvWxYz123456"',
                    "language": "config",
                    "real_secret": 0,
                    "false_positive": 1,
                },
                {
                    "Repository": "acme/docs",
                    "File": "API_KEYS.md",
                    "Line": 20,
                    "Secret Type": "GitHub Token",
                    "Classifier Confidence": 0.06,
                    "context_window": 'github_api_key: "ghp_abcdefghijklmnopqrstuvwxyz1234567890" # Only add the keys you actually have, leave others empty',
                    "language": "documentation",
                    "real_secret": 0,
                    "false_positive": 1,
                    "has_placeholder_signal": True,
                    "has_template_language": True,
                    "is_documentation_or_test_path": True,
                },
            ]
        )

        labeled, summary = apply_bootstrap_labels(rows, target_positive_count=1)

        self.assertEqual(summary["final_positive_rows"], 1)
        self.assertEqual(int(labeled.loc[0, "real_secret"]), 1)
        self.assertEqual(str(labeled.loc[0, "label_source"]), "bootstrap_positive")
        self.assertEqual(int(labeled.loc[1, "false_positive"]), 1)
        self.assertEqual(str(labeled.loc[1, "review_bucket"]), "docs_placeholders")

    def test_label_bucket_marks_near_miss_for_review(self):
        suggestion, bucket, score = classify_review_bucket(
            {
                "File": "secrets.txt",
                "Secret Type": "Stripe Live Key",
                "Classifier Confidence": 0.31,
                "context_window": 'stripe_fake_key="sk_live_M0VZF6J7cA6sknGfjuVHOKmB"',
                "language": "plain_text",
            }
        )

        self.assertEqual(suggestion, "false_positive")
        self.assertEqual(bucket, "docs_placeholders")
        self.assertLess(score, 0.0)

    def test_label_bucket_keeps_reconx_generic_dump_in_review(self):
        suggestion, bucket, _ = classify_review_bucket(
            {
                "File": "ReconX/keys.md",
                "Secret Type": "Generic 32-char Candidate",
                "Classifier Confidence": 0.56,
                "context_window": "Secret_Key: NMEwY7k1uayUKOU8TTSIcGDA1Swv8WWi Github: ghp_xxx Amazon: Access Key ID: AKIA...",
                "language": "documentation",
            }
        )

        self.assertEqual(suggestion, "review")
        self.assertEqual(bucket, "near_miss_high_confidence")

    def test_label_bucket_rejects_operational_uuid_ids(self):
        suggestion, bucket, _ = classify_review_bucket(
            {
                "File": "docker-compose.yml",
                "Secret Type": "UUID-like Secret",
                "Classifier Confidence": 0.77,
                "context_window": "CONNECTOR_ID=7ff6b8fd-7a4c-4cdc-9f1d-c5a8ff65a724",
                "language": "yaml",
            }
        )

        self.assertEqual(suggestion, "false_positive")
        self.assertEqual(bucket, "operational_ids")

    def test_supervised_classifier_rejects_generic_documentation_even_with_high_probability(self):
        rows = [
            {
                "length": 32,
                "entropy": 4.2,
                "digit_ratio": 0.2,
                "alpha_ratio": 0.8,
                "symbol_ratio": 0.0,
                "signature_confidence": "MEDIUM",
                "provider": "Generic 32-char Candidate",
                "has_ast_context": True,
                "has_variable_name": False,
                "variable_is_sensitive": False,
                "call_is_auth_related": False,
                "is_assignment_context": False,
                "has_secret_term_nearby": True,
                "has_hash_or_identifier_term": False,
                "has_placeholder_signal": False,
                "has_template_language": False,
                "is_documentation_or_test_path": True,
                "file_path": "ReconX/keys.md",
                "context_window": "Secret_Key: NMEwY7k1uayUKOU8TTSIcGDA1Swv8WWi",
                "label": "real_secret",
            }
        ]

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "supervised_gate.csv"
            model_path = Path(tmp) / "model.joblib"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            joblib.dump(
                {
                    "model": AlwaysPositiveModel(),
                    "feature_order": DEFAULT_FEATURE_ORDER,
                    "model_name": "unit-supervised-model",
                },
                model_path,
            )
            metrics = evaluate(str(csv_path), "label", str(model_path))

        self.assertEqual(metrics["rows"], 1)
        self.assertEqual(metrics["confusion_matrix"], [[0, 0], [1, 0]])


if __name__ == "__main__":
    unittest.main()
