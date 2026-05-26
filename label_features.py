import argparse
import json
import math
import re
from pathlib import Path
from typing import Any

import pandas as pd


POSITIVE_PROVIDER_TYPES = {
    "AWS Access Key",
    "Google API Key",
    "GitHub Token",
    "GitLab Personal Access Token",
    "Stripe Live Key",
    "OpenAI API Key",
    "OpenAI Project Key",
    "Slack Token",
    "Twilio Account SID",
    "Mailgun API Key",
    "PyPI Upload Token",
    "Discord Bot Token",
    "Telegram Bot Token",
}
CODE_PATH_HINTS = (".env", ".py", ".sh", ".yml", ".yaml", ".go", ".php", ".c", ".conf", "docker-compose")
DOC_PATH_HINTS = (".md", "readme", "usage", "api_keys", "keys.md", "docs/")
PLACEHOLDER_TERMS = (
    "fake_key",
    "false_key",
    "example",
    "example.com",
    "only add the keys",
    "leave others empty",
    "delete",
    "xxxx",
    "xxx@xxx.com",
    "edit this",
    "you can change this",
    "changeme",
    "test key",
)
REALISTIC_SECRET_TERMS = (
    "api_key",
    "apikey",
    "secret_key",
    "access key",
    "token=",
    "token:",
    "password",
    "shodan_key",
    "shodan_api_key",
    "github token",
    "github:",
    "opencti_token",
    "cloudflare:   key",
    "wpscan:",
    "securitytrails:",
    "virustotal:",
    "alienvault:",
    "censys_api_secret",
    "censys_api_id",
    "connect",
    "environment:",
)
HASH_NOISE_TERMS = (
    "md5",
    "sha1",
    "sha256",
    "hash",
    "gist.githubusercontent.com",
    ".png",
    "go.mod h1:",
    "license",
    "file hash lookup",
    "identify un hash",
)
GENERIC_SECRET_TYPES = {
    "Generic 32-char Candidate",
    "Generic 40-char Hex Candidate",
    "Generic 64-char Hex Candidate",
    "UUID-like Secret",
}
SENSITIVE_NAME_PATTERN = re.compile(
    r"(api[_-]?key|secret[_-]?key|access[_-]?key|token|password|client[_-]?secret|shodan|censys|opencti|openrouter|gemini|google)",
    re.IGNORECASE,
)
SENSITIVE_BINDING_PATTERN = re.compile(
    r"([A-Za-z0-9_.-]*(api[_-]?key|secret[_-]?key|access[_-]?key|token|password|client[_-]?secret|shodan|censys|opencti|openrouter|gemini|google)[A-Za-z0-9_.-]*)\s*[:=]\s*[\"']?[A-Za-z0-9_./:+-]{8,}",
    re.IGNORECASE,
)
OPERATIONAL_ID_TERMS = (
    "connector_id",
    "job_id",
    "policy_id",
    "trace_id",
    "image(",
    ".png",
    "screenshot",
)


def label_from_row(row: dict[str, Any]) -> str | None:
    """Resolve existing labels from either text or one-hot columns."""

    if "label" in row and str(row["label"]).strip():
        return str(row["label"]).strip().lower()

    real_secret = str(row.get("real_secret", "")).strip().lower()
    false_positive = str(row.get("false_positive", "")).strip().lower()

    truthy = {"1", "1.0", "true", "yes", "y", "real_secret"}
    if real_secret in truthy and false_positive not in truthy:
        return "real_secret"
    if false_positive in truthy and real_secret not in truthy:
        return "false_positive"
    return None


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return False
        return bool(value)
    return str(value).strip().lower() in {"1", "1.0", "true", "yes", "y"}


def _has_sensitive_binding(context: str, variable_name: str) -> bool:
    if variable_name and SENSITIVE_NAME_PATTERN.search(variable_name):
        return True
    return bool(SENSITIVE_BINDING_PATTERN.search(context))


def classify_review_bucket(row: dict[str, Any]) -> tuple[str, str, float]:
    """Suggest label + bucket for active-learning style review.

    The policy is intentionally conservative. It bootstraps obvious positives
    and obvious negatives, while keeping ambiguous rows in review cohorts that
    mirror the academic discussion: near misses, documented real keys,
    placeholders, and code/config contexts.
    """

    context = str(row.get("context_window", "")).lower()
    file_path = str(row.get("File", row.get("file_path", ""))).lower()
    secret_type = str(row.get("Secret Type", row.get("provider", "")))
    confidence = float(row.get("Classifier Confidence", 0) or 0)

    is_doc_path = _safe_bool(row.get("is_documentation_or_test_path")) or any(hint in file_path for hint in DOC_PATH_HINTS)
    is_code_or_config = any(hint in file_path for hint in CODE_PATH_HINTS) or str(row.get("language", "")).lower() in {
        "python",
        "config",
        "yaml",
        "shell",
        "tree_sitter_candidate",
    }
    has_placeholder = _safe_bool(row.get("has_placeholder_signal")) or _safe_bool(row.get("has_template_language"))
    has_realistic_terms = any(term in context for term in REALISTIC_SECRET_TERMS)
    has_hash_noise = _safe_bool(row.get("has_hash_or_identifier_term")) or any(term in context for term in HASH_NOISE_TERMS)
    has_explicit_placeholder = any(term in context for term in PLACEHOLDER_TERMS)
    has_asset_reference = _safe_bool(row.get("has_asset_reference"))
    provider_specific = secret_type in POSITIVE_PROVIDER_TYPES
    generic_type = secret_type in GENERIC_SECRET_TYPES
    variable_name = str(row.get("Associated Variable", row.get("variable_name", ""))).strip()
    variable_is_sensitive = _safe_bool(row.get("variable_is_sensitive"))
    is_assignment_context = _safe_bool(row.get("is_assignment_context"))
    has_sensitive_binding = _has_sensitive_binding(context, variable_name)
    is_reconx_dump = "reconx/keys.md" in file_path
    is_operational_id = secret_type == "UUID-like Secret" and any(term in context for term in OPERATIONAL_ID_TERMS)

    positive_score = 0.0
    negative_score = 0.0

    if provider_specific:
        positive_score += 0.75
    if has_realistic_terms:
        positive_score += 0.30
    if is_code_or_config:
        positive_score += 0.20
    if has_asset_reference:
        positive_score += 0.10
    positive_score += min(confidence, 0.60)

    if generic_type and is_code_or_config and (has_sensitive_binding or variable_is_sensitive) and confidence >= 0.30:
        positive_score += 0.20

    if has_placeholder or has_explicit_placeholder:
        negative_score += 0.90
    if has_hash_noise:
        negative_score += 0.45
    if is_doc_path and not has_realistic_terms and not has_asset_reference:
        negative_score += 0.30
    if "fake_key" in context or "false_key" in context:
        negative_score += 0.60
    if generic_type and is_doc_path:
        negative_score += 0.40
    if generic_type and is_reconx_dump:
        negative_score += 0.25
    if is_operational_id:
        negative_score += 0.95

    score = positive_score - negative_score

    if generic_type and is_operational_id:
        return "false_positive", "operational_ids", score
    if negative_score >= 0.80:
        return "false_positive", "docs_placeholders", score
    if generic_type and is_reconx_dump:
        if has_realistic_terms and not has_placeholder and not has_hash_noise:
            return "review", "near_miss_high_confidence", score
        return "false_positive", "low_priority_noise", score
    if generic_type and is_doc_path:
        if has_realistic_terms and has_sensitive_binding and not has_placeholder and not has_hash_noise:
            return "review", "near_miss_high_confidence", score
        return "false_positive", "low_priority_noise", score
    if generic_type and not is_code_or_config:
        if has_realistic_terms and has_sensitive_binding and not has_hash_noise:
            return "review", "near_miss_high_confidence", score
        return "false_positive", "low_priority_noise", score
    if generic_type and not (has_sensitive_binding or variable_is_sensitive or is_assignment_context):
        if score >= 0.80:
            return "review", "near_miss_high_confidence", score
        return "false_positive", "low_priority_noise", score
    if score >= 0.95:
        bucket = "code_config_real_key" if is_code_or_config else "docs_real_keys"
        return "real_secret", bucket, score
    if score >= 0.70:
        bucket = "near_miss_high_confidence"
        return "review", bucket, score
    return "false_positive", "low_priority_noise", score


def apply_bootstrap_labels(
    data: pd.DataFrame,
    target_positive_count: int,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Bootstrap additional labels while preserving existing manual positives."""

    working = data.copy()
    for column in ("real_secret", "false_positive"):
        if column in working.columns:
            working[column] = working[column].astype(object)
    if "label_source" not in working.columns:
        working["label_source"] = ""
    if "suggested_label" not in working.columns:
        working["suggested_label"] = ""
    if "review_bucket" not in working.columns:
        working["review_bucket"] = ""
    if "review_score" not in working.columns:
        working["review_score"] = 0.0
    if "review_priority" not in working.columns:
        working["review_priority"] = 0
    if "label" not in working.columns:
        working["label"] = ""

    existing_positive_indices: list[int] = []
    suggestions: list[tuple[int, str, str, float]] = []
    for idx, row in working.iterrows():
        label = label_from_row(row.to_dict())
        if label == "real_secret":
            existing_positive_indices.append(idx)
            working.at[idx, "label"] = "real_secret"
            if not str(working.at[idx, "label_source"]).strip():
                working.at[idx, "label_source"] = "manual_seed"
        elif label == "false_positive" and not str(working.at[idx, "label"]).strip():
            working.at[idx, "label"] = "false_positive"

        suggested_label, bucket, score = classify_review_bucket(row.to_dict())
        working.at[idx, "suggested_label"] = suggested_label
        working.at[idx, "review_bucket"] = bucket
        working.at[idx, "review_score"] = round(score, 4)
        priority = 1 if bucket in {"code_config_real_key", "docs_real_keys"} else 2 if bucket == "near_miss_high_confidence" else 4
        working.at[idx, "review_priority"] = priority
        suggestions.append((idx, suggested_label, bucket, score))

    positives_needed = max(0, target_positive_count - len(existing_positive_indices))
    promoted_indices: list[int] = []
    positive_candidates = [
        item for item in suggestions
        if item[1] == "real_secret" and label_from_row(working.iloc[item[0]].to_dict()) != "real_secret"
    ]
    positive_candidates.sort(key=lambda item: item[3], reverse=True)

    for idx, _, _, _ in positive_candidates[:positives_needed]:
        working.at[idx, "real_secret"] = 1
        working.at[idx, "false_positive"] = 0
        working.at[idx, "label"] = "real_secret"
        working.at[idx, "label_source"] = "bootstrap_positive"
        promoted_indices.append(idx)

    positives_needed = max(0, target_positive_count - (len(existing_positive_indices) + len(promoted_indices)))
    near_miss_candidates = [
        item for item in suggestions
        if item[1] == "review"
        and item[2] == "near_miss_high_confidence"
        and label_from_row(working.iloc[item[0]].to_dict()) != "real_secret"
        and item[0] not in promoted_indices
    ]
    near_miss_candidates.sort(key=lambda item: item[3], reverse=True)
    for idx, _, _, _ in near_miss_candidates[:positives_needed]:
        working.at[idx, "real_secret"] = 1
        working.at[idx, "false_positive"] = 0
        working.at[idx, "label"] = "real_secret"
        working.at[idx, "label_source"] = "bootstrap_near_miss_positive"
        promoted_indices.append(idx)

    for idx, suggested_label, bucket, _ in suggestions:
        current_label = label_from_row(working.iloc[idx].to_dict())
        if current_label == "real_secret":
            continue
        if str(working.at[idx, "label_source"]).strip():
            continue

        if suggested_label == "false_positive":
            working.at[idx, "real_secret"] = 0
            working.at[idx, "false_positive"] = 1
            working.at[idx, "label"] = "false_positive"
            working.at[idx, "label_source"] = "bootstrap_negative"
        elif bucket == "near_miss_high_confidence":
            working.at[idx, "real_secret"] = pd.NA
            working.at[idx, "false_positive"] = pd.NA
            working.at[idx, "label"] = ""
            working.at[idx, "label_source"] = "needs_review"

    real_secret_numeric = pd.to_numeric(working["real_secret"], errors="coerce").fillna(0)
    summary = {
        "rows": len(working),
        "existing_positive_rows": len(existing_positive_indices),
        "promoted_positive_rows": len(promoted_indices),
        "final_positive_rows": int((real_secret_numeric == 1).sum()),
        "review_buckets": working["review_bucket"].value_counts().to_dict(),
    }
    return working, summary


def export_review_queue(data: pd.DataFrame, output_path: str, limit: int) -> str:
    review_rows = data[data["label_source"] == "needs_review"].copy()
    review_rows = review_rows.sort_values(by=["review_priority", "review_score"], ascending=[True, False]).head(limit)
    queue_path = str(Path(output_path).with_name(Path(output_path).stem + "_review_queue.csv"))
    review_rows.to_csv(queue_path, index=False)
    return queue_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap and prioritize HybridSecretFramework feature labeling."
    )
    parser.add_argument("--input", required=True, help="Input features or labeled CSV")
    parser.add_argument("--output", required=True, help="Output labeled CSV with review metadata")
    parser.add_argument("--target-positive-count", type=int, default=25, help="Desired number of positive rows after bootstrap")
    parser.add_argument("--review-queue-limit", type=int, default=80, help="Maximum review rows to export")
    args = parser.parse_args()

    data = pd.read_csv(args.input).fillna("")
    labeled, summary = apply_bootstrap_labels(data, target_positive_count=args.target_positive_count)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_csv(output, index=False)
    queue_path = export_review_queue(labeled, str(output), args.review_queue_limit)

    print(json.dumps({**summary, "output": str(output), "review_queue": queue_path}, indent=2))


if __name__ == "__main__":
    main()
