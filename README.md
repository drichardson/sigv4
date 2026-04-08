# sigv4

Sign AWS HTTP requests with AWS Signature Version 4 — no `boto3` or `botocore` required.

Supports IRSA (IAM Roles for Service Accounts on EKS), ECS task roles, EC2 instance profiles, environment variables, and `~/.aws/credentials`. Zero Python package dependencies (pure stdlib).

## Installation

```sh
# uv
uv add sigv4

# pip
pip install sigv4
```

## Quick Start

### High-level API (recommended)

```python
import aiohttp
from sigv4 import Signer

signer = Signer(region="us-east-1", service="execute-api")

# Pre-warm credentials at startup (optional — avoids latency on first request)
signer.credentials.refresh()

# Later, sign any HTTP request:
url = "https://api-id.execute-api.us-east-1.amazonaws.com/stage/resource"
auth_headers = signer.sign(method="GET", url=url)

# Merge auth_headers into your request:
async with aiohttp.ClientSession() as session:
    async with session.get(url, headers=auth_headers) as resp:
        data = await resp.json()
```

### Low-level API (zero I/O, predictable latency)

```python
from sigv4 import Credentials, sign_headers

# Manage credentials yourself (e.g. fetched via your own IRSA logic)
creds = Credentials(
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    token="optional-session-token",
)

# Pure computation — no I/O, microseconds
headers = sign_headers(
    method="POST",
    url="https://dynamodb.us-east-1.amazonaws.com/",
    headers={"host": "dynamodb.us-east-1.amazonaws.com", "content-type": "application/x-amz-json-1.0"},
    body=b'{"TableName": "MyTable"}',
    region="us-east-1",
    service="dynamodb",
    credentials=creds,
)
# headers = {"Authorization": "AWS4-HMAC-SHA256 ...", "X-Amz-Date": "..."}
```

## Credential Chain

Credentials are resolved in this order:

1. **Environment variables** — `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + optional `AWS_SESSION_TOKEN`
2. **IRSA** (EKS) — `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` → STS `AssumeRoleWithWebIdentity`
3. **Config file** — `~/.aws/credentials` and `~/.aws/config` (respects `AWS_PROFILE`)
4. **Container credential endpoint** — `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `AWS_CONTAINER_CREDENTIALS_FULL_URI` (ECS task roles, EKS Pod Identity, and compatible runtimes)
5. **EC2 instance profile** — IMDSv2 at `169.254.169.254`

## Observability and Pre-warming

```python
from sigv4 import resolve_credentials

creds = resolve_credentials()

# Check state
print(creds.is_ready)       # False until first fetch
print(creds.needs_refresh)  # True if in advisory refresh window
print(creds.expires_at)     # datetime | None

# Pre-warm (blocks until credentials are fetched)
creds.refresh()
print(creds.is_ready)       # True
```
