"""Language and artifact type detection helpers."""

from __future__ import annotations

from pathlib import Path


CONFIG_FILENAMES = {
    ".env",
    "docker-compose.yml",
    "docker-compose.yaml",
}

CONFIG_EXTENSIONS = {
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}


def detect_language(file_path: str) -> str:
    """Infer the most useful parser family for a file path."""

    path = Path(file_path)
    name = path.name.lower()
    suffix = path.suffix.lower()

    if suffix == ".py":
        return "python"
    if name in CONFIG_FILENAMES or suffix in CONFIG_EXTENSIONS:
        return "config"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    if suffix in {".java", ".kt", ".kts"}:
        return "jvm"
    if suffix in {".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h"}:
        return "tree_sitter_candidate"
    if suffix in {".md", ".rst", ".txt"}:
        return "documentation"
    return "plain_text"


def is_documentation_or_test_path(file_path: str) -> bool:
    """Detect paths that commonly host examples, fixtures, or documentation."""

    normalized = file_path.replace("\\", "/").lower()
    markers = (
        "api_keys",
        "api_keys.md",
        "test_",
        "tests/",
        "/test/",
        "/tests/",
        "__tests__",
        "/spec/",
        "/docs/",
        "/doc/",
        "/examples/",
        "/example/",
        "readme",
        "usage.md",
        "fixture",
        "sample",
        "mock",
    )
    return any(marker in normalized for marker in markers)
