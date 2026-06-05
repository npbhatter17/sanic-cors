"""
Regression test for CVE-2026-37737.

sanic-cors <= 2.2.0 matched the request Origin against configured regex
origins using re.match(), which is not end-anchored. A pattern intended to
match exactly "https://trusted.com" therefore also matched any origin that
merely *began* with that string (e.g. "https://trusted.com.attacker.io"),
allowing the attacker origin to be reflected in Access-Control-Allow-Origin.

These tests assert that legitimate origins still match while suffix-appended
and trailing-variant origins do not.
"""

import re

from sanic_cors.core import try_match


def test_regex_origin_is_end_anchored():
    # Contains a backslash, so it is treated as a regex by try_match.
    pattern = r'https://trusted\.com'

    # Legitimate, exact origin still matches.
    assert try_match('https://trusted.com', pattern)

    # CVE-2026-37737: a domain that begins with the trusted string but has an
    # attacker-controlled suffix must NOT match.
    assert not try_match('https://trusted.com.attacker.io', pattern)

    # A trailing variation such as an added port must NOT match this pattern.
    assert not try_match('https://trusted.com:8080', pattern)


def test_compiled_regex_origin_is_end_anchored():
    pattern = re.compile(r'https://.*\.example\.com')

    # Legitimate subdomain still matches.
    assert try_match('https://app.example.com', pattern)

    # Suffix-appended attacker origin must NOT match.
    assert not try_match('https://app.example.com.attacker.io', pattern)


def test_plain_string_origin_unaffected():
    # Plain strings use exact comparison and were never vulnerable; this just
    # confirms the fix does not change that path.
    assert try_match('https://trusted.com', 'https://trusted.com')
    assert not try_match('https://trusted.com.attacker.io', 'https://trusted.com')
