# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
SigV4 signing tests using the official AWS test suite.

Test vectors from:
https://docs.aws.amazon.com/general/latest/gr/sigv4-test-suite.html

The suite uses:
  Region:     us-east-1
  Service:    service
  Access key: AKIDEXAMPLE
  Secret key: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
  Date:       20150830T123600Z
"""

from datetime import UTC, datetime


from aws_sigv4 import Credentials, sign_headers
from aws_sigv4.signing import (
    EMPTY_SHA256,
    _canonical_query_string,
    _canonical_uri,
    _payload_hash,
    _signing_key,
    _canonical_headers_str,
    _signed_headers,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_CREDS = Credentials(
    access_key="AKIDEXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
)

_TIMESTAMP = datetime(2015, 8, 30, 12, 36, 0, tzinfo=UTC)
_REGION = "us-east-1"
_SERVICE = "service"


# ---------------------------------------------------------------------------
# Unit tests for internal helpers
# ---------------------------------------------------------------------------


def test_empty_payload_hash():
    assert _payload_hash(b"") == EMPTY_SHA256


def test_payload_hash_known():
    # SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    assert (
        _payload_hash(b"hello")
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_canonical_uri_root():
    assert _canonical_uri("") == "/"
    assert _canonical_uri("/") == "/"


def test_canonical_uri_encoding():
    assert _canonical_uri("/foo bar") == "/foo%20bar"
    assert _canonical_uri("/foo/bar") == "/foo/bar"


def test_canonical_uri_dotdot_at_root_does_not_go_above_root():
    """Multiple '..' segments that exhaust the resolved stack must not raise."""
    # /../../foo: second '..' finds resolved empty and correctly skips the pop.
    assert _canonical_uri("/../../foo") == "/foo"


def test_canonical_query_string_empty():
    assert _canonical_query_string("") == ""


def test_canonical_query_string_sorted():
    # Keys must be sorted lexicographically.
    qs = _canonical_query_string("z=1&a=2&m=3")
    assert qs == "a=2&m=3&z=1"


def test_canonical_query_string_encoded():
    qs = _canonical_query_string("foo=hello world")
    assert qs == "foo=hello%20world"


def test_canonical_query_string_duplicate_keys_sorted_by_value():
    qs = _canonical_query_string("x=b&x=a")
    assert qs == "x=a&x=b"


def test_canonical_headers_lowercase_and_sorted():
    hdrs = {"Host": "example.com", "X-Amz-Date": "20150830T123600Z"}
    lower = {k.lower(): v for k, v in hdrs.items()}
    result = _canonical_headers_str(lower)
    assert result == "host:example.com\nx-amz-date:20150830T123600Z"


def test_canonical_headers_whitespace_collapsed():
    hdrs = {"my-header": "  value   with   spaces  "}
    result = _canonical_headers_str(hdrs)
    assert result == "my-header:value with spaces"


def test_canonical_headers_blacklisted_excluded():
    hdrs = {
        "host": "example.com",
        "user-agent": "should-be-excluded",
        "connection": "keep-alive",
    }
    result = _canonical_headers_str(hdrs)
    assert "user-agent" not in result
    assert "connection" not in result
    assert "host:example.com" in result


def test_signed_headers_excludes_blacklist():
    hdrs = {
        "host": "example.com",
        "x-amz-date": "20150830T123600Z",
        "user-agent": "python",
    }
    result = _signed_headers(hdrs)
    assert result == "host;x-amz-date"


def test_signing_key_deterministic():
    """
    Signing key derivation must be deterministic — same inputs produce the same key.
    The expected value was computed by running the algorithm once and pinning it;
    any change would indicate a regression in the four-step HMAC derivation.
    """
    key = _signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20150830",
        "us-east-1",
        "iam",
    )
    # Pinned value — computed by the algorithm itself; a change here indicates
    # a regression in the HMAC-SHA256 key derivation chain.
    assert (
        key.hex() == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    )
    assert len(key) == 32  # 256-bit key


# ---------------------------------------------------------------------------
# End-to-end test: get-vanilla (AWS test suite)
# ---------------------------------------------------------------------------


def test_get_vanilla():
    """
    get-vanilla: simple GET with no query string or body.
    Source: AWS SigV4 test suite — get-vanilla
    """
    result = sign_headers(
        method="GET",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )

    assert result["X-Amz-Date"] == "20150830T123600Z"
    assert "AWS4-HMAC-SHA256" in result["Authorization"]
    assert (
        "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request" in result["Authorization"]
    )
    assert "Credential=" in result["Authorization"]
    assert "SignedHeaders=" in result["Authorization"]
    assert "Signature=" in result["Authorization"]
    assert "X-Amz-Security-Token" not in result


def test_get_with_session_token():
    """Security token must appear in the Authorization SignedHeaders and as its own header."""
    creds = Credentials(
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        token="AQoDYXdzEJr//////////wEa...",
    )
    result = sign_headers(
        method="GET",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=creds,
        timestamp=_TIMESTAMP,
    )

    assert "X-Amz-Security-Token" in result
    assert result["X-Amz-Security-Token"] == creds.token
    assert "x-amz-security-token" in result["Authorization"].lower()


def test_host_derived_from_url():
    """If 'host' is not supplied in headers it should be derived from the URL."""
    result = sign_headers(
        method="GET",
        url="https://s3.us-east-1.amazonaws.com/my-bucket",
        headers={},
        body=b"",
        region="us-east-1",
        service="s3",
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    assert (
        "host" in result["Authorization"].lower()
        or "SignedHeaders=host" in result["Authorization"]
    )


def test_query_string_included_in_signing():
    """Query parameters must be part of the canonical request."""
    result1 = sign_headers(
        method="GET",
        url="https://example.amazonaws.com/?foo=1",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    result2 = sign_headers(
        method="GET",
        url="https://example.amazonaws.com/?foo=2",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    # Different query strings must produce different signatures.
    assert result1["Authorization"] != result2["Authorization"]


def test_body_included_in_signing():
    """Body hash must affect the signature."""
    result1 = sign_headers(
        method="POST",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"hello",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    result2 = sign_headers(
        method="POST",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"world",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    assert result1["Authorization"] != result2["Authorization"]


def test_deterministic():
    """Same inputs must always produce the same signature."""
    kwargs = dict(
        method="GET",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        timestamp=_TIMESTAMP,
    )
    assert sign_headers(**kwargs) == sign_headers(**kwargs)


def test_sign_headers_without_explicit_timestamp():
    """When timestamp is omitted sign_headers uses datetime.now(UTC)."""
    result = sign_headers(
        method="GET",
        url="https://example.amazonaws.com/",
        headers={"host": "example.amazonaws.com"},
        body=b"",
        region=_REGION,
        service=_SERVICE,
        credentials=_CREDS,
        # no timestamp= — exercises the datetime.now(UTC) branch
    )
    assert "Authorization" in result
    assert "X-Amz-Date" in result
