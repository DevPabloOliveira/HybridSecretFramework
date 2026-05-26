import argparse
import asyncio
import os
import sys
from datetime import datetime

import pandas as pd
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

try:
    from modules.core.pipeline import HybridSecretPipeline
    from modules.layer4_classification.classifier import SecretClassifier
    from modules.layer4_classification.sklearn_classifier import SklearnSecretClassifier
    from modules.layer4_classification.threshold_policy import ThresholdPolicy
    from modules.scanner import HybridSecretScanner
    from modules.validator import HybridSecretValidator
except ImportError as exc:
    print(f"[CRITICAL] Failed to import project modules: {exc}")
    sys.exit(1)


console = Console()


def save_results(rows: list[dict[str, object]], filename_suffix: str) -> str | None:
    """Persist a list of dictionaries as a timestamped CSV report."""

    if not rows:
        return None

    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"results/{timestamp}_{filename_suffix}.csv"
    pd.DataFrame(rows).to_csv(filename, index=False)
    return filename


async def async_hybrid_analysis_phase(
    raw_results: list[dict[str, str]],
    concurrency: int,
    classifier: SecretClassifier | None = None,
    export_features_path: str | None = None,
):
    """Run the five-layer architecture over files recovered from GitHub."""

    pipeline = HybridSecretPipeline(concurrency=concurrency, classifier=classifier)

    console.print("\n[bold yellow][LAYERS 1-5] Hybrid Regex + AST + Features + ML Gate[/bold yellow]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
    ) as progress:
        task = progress.add_task(
            f"[cyan]Analyzing {len(raw_results)} recovered files...",
            total=len(raw_results),
        )
        analyses = await pipeline.analyze(raw_results)
        if export_features_path:
            feature_rows = [analysis.to_feature_row() for analysis in analyses]
            pd.DataFrame(feature_rows).to_csv(export_features_path, index=False)
        findings = [
            pipeline.reporter.build(analysis.candidate, analysis.feature_vector, analysis.classification)
            for analysis in analyses
            if analysis.classification.approved
        ]
        findings.sort(key=lambda item: (item.risk_score, item.confidence), reverse=True)
        progress.update(task, advance=len(raw_results))

    return findings


def build_classifier(model_path: str | None) -> SecretClassifier | None:
    """Load a supervised classifier when a trained model bundle is provided."""

    if not model_path:
        return None
    return SklearnSecretClassifier(model_path=model_path)


def render_findings_table(report_rows: list[dict[str, object]]) -> None:
    """Render the highest priority findings in the terminal."""

    table = Table(title="Explainable High-Confidence Findings")
    table.add_column("Risk", style="red")
    table.add_column("Confidence", style="magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Masked Value", style="green")
    table.add_column("Location", style="white")
    table.add_column("AST / Variable", style="yellow")

    for row in report_rows[:10]:
        ast_variable = f"{row['AST Node']} / {row['Associated Variable']}".strip()
        table.add_row(
            str(row["Risk Level"]),
            str(row["Confidence"]),
            str(row["Secret Type"]),
            str(row["Masked Value"]),
            f"{row['File']}:{row['Line']}",
            ast_variable,
        )

    console.print(table)
    if len(report_rows) > 10:
        console.print(f"[dim]... plus {len(report_rows) - 10} additional findings in the CSV report.[/dim]")


def run_active_validation(
    findings,
    service_name: str,
    validation_threshold: float,
) -> list[dict[str, object]]:
    """Run Strategy validators only after the classification layer approves."""

    policy = ThresholdPolicy(validation_threshold=validation_threshold)
    validator = HybridSecretValidator()
    valid_hits = []
    targets = [item for item in findings if policy.allow_active_validation(item.confidence)]

    console.print(f"Validating {len(targets)} high-confidence candidates...")
    for item in targets:
        strategy_name, result = validator.validate_finding(item, requested_service=service_name)
        details = result.get("details", "") if result else ""
        if result and result.get("valid"):
            item.validation_details = f"{strategy_name}: {details}"
            valid_hits.append(item.to_report_row())
            console.print(
                f"[bold green][VALID] {item.masked_value} -> {item.validation_details}[/bold green]"
            )
        elif details:
            item.validation_details = f"{strategy_name}: {details}"
            console.print(f"[yellow][SKIPPED] {item.masked_value} -> {item.validation_details}[/yellow]")
        else:
            console.print(f"[red][INVALID/UNCONFIRMED] {item.masked_value} ({strategy_name})[/red]")

    return valid_hits


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HybridSecretFramework - A Hybrid AST- and Machine Learning-Based Framework for Secret Detection"
    )
    parser.add_argument("--token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("--input", required=True, help="Pattern CSV file, e.g. config/shodan_patterns.csv")
    parser.add_argument("--pages", type=int, default=1, help="GitHub search pages per dork")
    parser.add_argument("--validate", action="store_true", help="Enable active validation after ML gate")
    parser.add_argument(
        "--service",
        default="auto",
        help="Validation strategy. Use auto to route by Secret Type, or force shodan/google/scrapingbee/generic.",
    )
    parser.add_argument("--concurrency", type=int, default=30, help="Concurrent raw file downloads")
    parser.add_argument(
        "--classifier-model",
        help="Optional .joblib bundle produced by train_classifier.py; replaces heuristic-baseline-v1",
    )
    parser.add_argument(
        "--export-features",
        help="Optional CSV path with all candidate features for labeling, training, and evaluation",
    )
    parser.add_argument(
        "--validation-threshold",
        type=float,
        default=0.82,
        help="Minimum classifier confidence required before active validation",
    )

    args = parser.parse_args()

    console.print(
        "[bold blue]=== HYBRID SECRET FRAMEWORK (AST + MACHINE LEARNING SECRET DETECTION) ===[/bold blue]"
    )

    console.print("\n[bold green][DISCOVERY] GitHub recovery scanner[/bold green]")
    scanner = HybridSecretScanner(args.token)
    raw_results = scanner.run_scan(args.input, pages=args.pages)

    if not raw_results:
        console.print("[bold red][!] No files were recovered from GitHub.[/bold red]")
        return

    raw_file = save_results(raw_results, "1_SCAN_RAW")
    console.print(f"[green]Raw recovery report saved to: {raw_file}[/green]")

    try:
        classifier = build_classifier(args.classifier_model)
    except Exception as exc:
        console.print(f"[bold red][!] Failed to load classifier model: {exc}[/bold red]")
        return

    if classifier:
        console.print(f"[green]Using supervised classifier model: {args.classifier_model}[/green]")
    else:
        console.print("[yellow]Using heuristic-baseline-v1 classifier.[/yellow]")

    findings = asyncio.run(
        async_hybrid_analysis_phase(
            raw_results=raw_results,
            concurrency=args.concurrency,
            classifier=classifier,
            export_features_path=args.export_features,
        )
    )
    if args.export_features:
        console.print(f"[green]Feature dataset exported to: {args.export_features}[/green]")
    if not findings:
        console.print("[bold red][!] No candidates survived AST/features/classification.[/bold red]")
        return

    report_rows = [item.to_report_row() for item in findings]
    render_findings_table(report_rows)

    refined_file = save_results(report_rows, "2_HYBRID_FINDINGS")
    console.print(f"[bold green]Hybrid explainability report saved to: {refined_file}[/bold green]")

    if args.validate:
        console.print(f"\n[bold red][VALIDATION] Strategy validator ({args.service.upper()})[/bold red]")
        valid_rows = run_active_validation(findings, args.service, args.validation_threshold)
        if valid_rows:
            valid_file = save_results(valid_rows, "3_VALID_KEYS_CONFIRMED")
            console.print(f"[bold green]Confirmed validation report saved to: {valid_file}[/bold green]")
        else:
            console.print("[yellow]No active keys were confirmed by the selected validator.[/yellow]")


if __name__ == "__main__":
    main()
