# Design

## Overview

`aws-sigv4` is a minimal Python library for signing HTTP requests with AWS
Signature Version 4 and resolving AWS credentials — without pulling in `boto3`
or `botocore`.

The goal is to let callers use AWS HTTP APIs directly (via `aiohttp`, `httpx`,
`requests`, or anything else) while this library handles the authentication
plumbing.

### Design goals

**Zero Python package dependencies.** The library uses only the Python stdlib
(`hashlib`, `hmac`, `urllib`, `xml.etree`, `configparser`, `threading`,
`datetime`). Installing `aws-sigv4` adds nothing to your dependency tree beyond
itself. This is a deliberate constraint — new runtime dependencies require
explicit justification and a strong case.

**Correct.** The signing implementation is validated against the official AWS
SigV4 test suite. See [Conformance Testing](#conformance-testing) below.

**Lightweight.** The signing algorithm itself is pure computation with no I/O.
Credential fetching (STS, IMDS, ECS) only happens on first use and on refresh,
not on every request.

IRSA is just one of several supported credential sources. The library works
equally well with environment variables, `~/.aws/credentials`, ECS task roles,
EC2 instance profiles, or explicit static credentials passed directly to
`sign_headers()`.

---

## Code Structure

```
src/aws_sigv4/
├── __init__.py        # Public API re-exports
├── py.typed           # PEP 561 marker (typed package)
├── signing.py         # SigV4 algorithm — pure functions, zero I/O
├── credentials.py     # Credentials dataclass + RefreshableCredentials
├── resolve.py         # resolve_credentials() — the provider chain
├── signer.py          # Signer — high-level sign() wrapper
└── providers/
    ├── env.py          # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
    ├── web_identity.py # IRSA: token file → STS AssumeRoleWithWebIdentity
    ├── config_file.py  # ~/.aws/credentials and ~/.aws/config
    ├── container.py    # ECS task role endpoint
    └── imds.py         # EC2 Instance Metadata Service (IMDSv2)
```

---

## Two-Layer API

### Low-level: `sign_headers()`

Pure function in `signing.py`. Takes a `Credentials` dataclass directly.
Does zero I/O. Runs in microseconds. Suitable for callers that manage their
own credentials and need predictable, non-blocking latency.

```python
from aws_sigv4 import Credentials, sign_headers

headers = sign_headers(
    method="GET",
    url="https://s3.us-east-1.amazonaws.com/my-bucket",
    headers={"host": "s3.us-east-1.amazonaws.com"},
    body=b"",
    region="us-east-1",
    service="s3",
    credentials=Credentials(access_key="...", secret_key="..."),
)
```

### High-level: `Signer`

Wraps credential resolution, auto-refresh, and signing into a single object.
Most callers should use this.

```python
from aws_sigv4 import Signer

signer = Signer(region="us-east-1", service="s3")
signer.credentials.refresh()  # optional pre-warm
headers = signer.sign(method="GET", url="https://s3.us-east-1.amazonaws.com/my-bucket")
```

---

## SigV4 Signing Algorithm (`signing.py`)

Implements the [AWS Signature Version 4 specification](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
All logic is pure Python stdlib (`hashlib`, `hmac`, `urllib.parse`).

Steps per the [AWS SigV4 signing elements reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-elements.html):

1. **Timestamp** — `YYYYMMDDTHHMMSSZ` format for `X-Amz-Date`
2. **Canonical Request** — 6 components joined by newline:
   - HTTP method (uppercased)
   - Canonical URI — path normalized per [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) (resolve `.` and `..`, collapse `//`), then percent-encoded
   - Canonical query string — keys and values sorted lexicographically and percent-encoded
   - Canonical headers — lowercased, sorted, whitespace-collapsed
   - Blank line
   - Signed headers — semicolon-joined sorted lowercase names
   - Payload hash — SHA-256 hex of body (`EMPTY_SHA256` for empty body)
3. **String to Sign** — algorithm + date + credential scope + SHA-256 of canonical request
4. **Signing key** — four-step HMAC-SHA256 key derivation: `AWS4+secret` → date → region → service → `aws4_request`
5. **Signature** — HMAC-SHA256 of string-to-sign with signing key, hex-encoded
6. **Authorization header** — `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`

**Headers excluded from signing** — the following headers are never included
in the signature. The [AWS signing documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
specifies that hop-by-hop and volatile transport headers mutated by proxies,
load balancers, and distributed system nodes must not be signed:
`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`,
`trailer`, `transfer-encoding`, `upgrade`, `user-agent`, `x-amzn-trace-id`.

Additionally, `authorization` is excluded because it contains the signature
itself, and `expect` is excluded because the Expect mechanism is hop-by-hop
(RFC 9110 §10.1.1) and may be consumed or modified by intermediaries before
the request reaches AWS.

---

## Conformance Testing

The signing implementation is validated against the **official AWS SigV4 test
suite**, vendored from
[botocore's test fixtures](https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite)
at `tests/data/aws4_testsuite/`.

Each test case provides a raw HTTP request (`.req`) and expected outputs at
three intermediate stages — canonical request (`.creq`), string to sign
(`.sts`), and final `Authorization` header (`.authz`) — allowing failures to
be pinpointed to the exact step that diverges from the spec.

The parametrized test runner is at `tests/test_aws_test_suite.py`. It covers
all test cases in the suite, including cases that botocore itself skips (e.g.
paths with literal spaces and duplicate query parameter keys), which pass here
because the request-line parser and `urllib.parse.parse_qsl` handle them
correctly.

To keep the vendored suite current, a [monthly GitHub Actions workflow](.github/workflows/sync-test-suite.yaml)
sparse-clones botocore upstream and opens a draft PR if any test files have
changed.

---

## Credential Model (`credentials.py`)

### `Credentials`

Frozen dataclass. Immutable — a new instance is created on each refresh.

```python
@dataclass(frozen=True)
class Credentials:
    access_key: str
    secret_key: str
    token: str | None = None      # STS session token (IRSA, ECS, IMDS)
    expires_at: datetime | None = None  # UTC; None for long-lived IAM creds
```

### `CredentialProvider` (Protocol)

```python
class CredentialProvider(Protocol):
    def load(self) -> Credentials | None: ...
```

Return `None` if this provider cannot supply credentials in the current
environment (env vars not set, not on EC2, etc.).

### `RefreshableCredentials`

Wraps a `CredentialProvider` with thread-safe lazy fetching and auto-refresh.

**Refresh thresholds** — chosen to match botocore's documented behaviour and
give adequate time for a retry if the first refresh attempt fails:
- **Advisory** (15 min before expiry): one thread attempts refresh; if it
  fails, others continue using the still-valid cached credentials
- **Mandatory** (10 min before expiry): all callers block until fresh
  credentials are obtained

**Observable properties**:
- `is_ready` — fetched at least once and not expired
- `needs_refresh` — in advisory or mandatory window
- `expires_at` — expiry of current credentials

**Pre-warming**:
```python
creds = resolve_credentials()
creds.refresh()   # fetch now, on your schedule
```

---

## Credential Provider Chain (`resolve.py`)

`resolve_credentials()` iterates providers in priority order. The first
provider that returns credentials wins; providers that return `None` or raise
are skipped. IRSA is not required — any provider in the chain can supply
credentials independently.

| # | Provider | Trigger |
|---|----------|---------|
| 1 | `EnvProvider` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| 2 | `WebIdentityProvider` | `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` (IRSA) |
| 3 | `ConfigFileProvider` | `~/.aws/credentials` / `~/.aws/config` (see [AWS config file docs](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)) |
| 4 | `ContainerProvider` | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `AWS_CONTAINER_CREDENTIALS_FULL_URI` — container credential endpoint ([ECS task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html), [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)) |
| 5 | `IMDSProvider` | EC2 instance metadata at `169.254.169.254` ([IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)) |

---

## IRSA Flow (`providers/web_identity.py`)

[IRSA (IAM Roles for Service Accounts)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
allows EKS pods to assume IAM roles without long-lived credentials by
exchanging a Kubernetes-issued JWT for temporary STS credentials.

Steps per the [STS AssumeRoleWithWebIdentity API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html):

1. Read `AWS_WEB_IDENTITY_TOKEN_FILE` path and `AWS_ROLE_ARN`
2. Open the token file and read the JWT — **re-read on every refresh**, because
   [Kubernetes rotates projected service account tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume)
   before they expire (typically at 80% of their lifetime). Caching the file
   contents would cause signing failures after rotation.
3. POST to STS `AssumeRoleWithWebIdentity` with the JWT — no AWS credentials
   needed, the signed JWT is the proof of identity
4. Parse the XML response with `xml.etree.ElementTree` (stdlib)
5. Return a `Credentials` with the temporary `AccessKeyId`, `SecretAccessKey`,
   `SessionToken`, and `Expiration` from the STS response

The `Expiration` returned by STS drives `RefreshableCredentials`' advisory and
mandatory refresh thresholds, ensuring credentials are renewed before they
expire and before Kubernetes rotates the token file.

---

## Dependencies

**Python package dependencies:** none — pure stdlib only (`hashlib`, `hmac`,
`urllib`, `xml.etree`, `configparser`, `threading`, `datetime`)

**Dev:** `pytest`, `mypy`, `ruff`

---

## Security

This library handles AWS credentials. Any code path that could emit credential
material — through logging, print statements, exception messages, or string
representations — is a security defect.

**Principle:** if it cannot be determined from a cursory analysis of the source
that no credentials are leaked, the construct is banned.

The following rules are enforced by `scripts/check-no-credential-leaks.py`, an
AST-based CI check that cannot be suppressed by `# noqa` or `# type: ignore`:

1. **`print()` is banned.** No `print()` calls anywhere in library source.

2. **Exception messages must be string literals.** No f-strings, `.format()`,
   string concatenation, or variable references in exception constructors. A
   user-provided URL, for example, could contain a credential embedded in the
   query string — echoing it back in an exception leaks it. Messages should
   tell the user what to check, not repeat what they provided.

3. **`raise ... from <exception>` is banned** (except `from None`). Chained
   exceptions can contain credential data in their `__str__` — e.g.,
   `json.JSONDecodeError` includes a snippet of the decoded input,
   `urllib.error.HTTPError` can include the response body. Use `from None`
   or omit the cause entirely.

4. **Only `AWSv4SigError` and its subclasses may be raised.** `RuntimeError`
   and other built-in exceptions are banned. `AWSv4SigError.__init__` accepts
   only a `LiteralString`, enforced by mypy at type-check time.

5. **Logging is restricted to a single internal module** (`_log.py`). No other
   module may import `logging` or call `logging.*` / `logger.*` directly. The
   public API is `aws_sigv4._log.warning(message: LiteralString)` — only
   `warning` level is exposed, and only string literals are accepted. This
   prevents variable data (which could contain credentials) from ever being
   logged. An environment variable value, for instance, could be a URL with a
   credential in it — the warning message should describe the problem in
   general terms, not echo the value back.

6. **`Credentials.__repr__` and `__str__` are fully redacted.** Even if a
   `Credentials` object is accidentally passed to a log or exception, no
   secret material is visible.

7. **`# type: ignore` is banned from all source files under `src/`.** This
   prevents suppressing the `LiteralString` constraint on `AWSv4SigError` and
   `warning()`, and prevents bypassing any other mypy check. If mypy reports
   an error, fix the code.

---

## References

- [AWS Signature Version 4 — Create a signed request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
- [AWS Signature Version 4 — Signing elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-elements.html)
- [STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [EKS — IAM roles for service accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Kubernetes — Projected service account token rotation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume)
- [EC2 — Instance Metadata Service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [ECS — Task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [AWS CLI — Configuration and credential files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [RFC 3986 — URI generic syntax](https://datatracker.ietf.org/doc/html/rfc3986)
- [AWS SigV4 test suite (vendored from botocore)](https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite)
