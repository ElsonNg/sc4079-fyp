"""Compatibility imports for the GitHub API adapter."""

from corpus.integrations.github import (
    GITHUB_API_BASE, GITHUB_RAW_BASE, GITHUB_API_VERSION, GitHubRateLimitError,
    _github_get, _github_headers, _rate_limit_delay, fetch_advisories,
    fetch_advisory, fetch_blob_content, fetch_commit, fetch_file_content,
    fetch_raw_file_content, fetch_source_tree,
)
