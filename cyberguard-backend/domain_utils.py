"""Deterministic, offline public-suffix extraction for security decisions."""

import tldextract


_extract_domain = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)


def extract_domain(value: str):
    """Split a URL or hostname using the Public Suffix List bundled with tldextract."""
    return _extract_domain(value)
