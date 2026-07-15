from mail_sovereignty.constants import (
    PARKED_MX_PATTERNS,
    SKIP_DOMAINS,
    CONCURRENCY_POSTPROCESS,
)


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_parked_mx_patterns_contains_confirmed_cases():
    assert "kv.de" in PARKED_MX_PATTERNS
    assert "stackmail.com" in PARKED_MX_PATTERNS


def test_concurrency_postprocess():
    assert CONCURRENCY_POSTPROCESS == 10
