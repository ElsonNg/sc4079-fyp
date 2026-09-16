"""Shared helpers for the tiered evaluation benchmark (Tier 1 / Tier 2)."""

from __future__ import annotations

from pathlib import Path

# Six advisory-diverse categories for the 22 seed packages (see report Ch.3 §3.6).
PACKAGE_CATEGORY: dict[str, str] = {
    # Application frameworks & runtimes
    "parse-server": "frameworks",
    "nuxt": "frameworks",
    "next": "frameworks",
    "electron": "frameworks",
    "fastify": "frameworks",
    # HTTP, transport & messaging
    "undici": "transport",
    "axios": "transport",
    "ws": "transport",
    "nodemailer": "transport",
    # Parsing, serialisation & general utilities
    "qs": "utilities",
    "lodash": "utilities",
    "minimist": "utilities",
    "moment": "utilities",
    "semver": "utilities",
    # Templating & rendering
    "liquidjs": "templating",
    "mermaid": "templating",
    "handlebars": "templating",
    # Security primitives (sanitisation, validation, auth)
    "dompurify": "security",
    "better-auth": "security",
    "validator": "security",
    # Upload & build tooling
    "vite": "tooling",
    "multer": "tooling",
}

DEFAULT_SNAPSHOT_DB = (
    Path(__file__).resolve().parent.parent
    / "corpus" / "data" / "corpus.db"
)

_EXTENSION_BY_LANGUAGE = {"javascript": ".js", "typescript": ".ts", "tsx": ".tsx"}


def category_for(package_name: str) -> str:
    return PACKAGE_CATEGORY.get(package_name, "other")


def extension_for(source_language: str) -> str:
    return _EXTENSION_BY_LANGUAGE.get(source_language, ".js")


def extract_ghsa_ids(obj) -> set[str]:
    """Recursively collect every ``ghsa_id`` value present in a nested result dict."""
    found: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            value = node.get("ghsa_id")
            if isinstance(value, str) and value:
                found.add(value)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(obj)
    return found
