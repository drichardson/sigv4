# Test Data

## aws4_testsuite/

Official AWS Signature Version 4 test vectors, vendored from
[botocore](https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite).

Each subdirectory is one test case. Each test case contains:

| File | Purpose |
|------|---------|
| `<name>.req` | Raw HTTP request (input) |
| `<name>.creq` | Expected canonical request |
| `<name>.sts` | Expected string to sign |
| `<name>.authz` | Expected `Authorization` header |
| `<name>.sreq` | Expected signed request |

The test runner is `tests/test_aws_test_suite.py`. It discovers all test case
directories, parses each `.req` file, runs the signing algorithm at each
intermediate step, and asserts the output matches the corresponding expected
file.

The upstream commit SHA is recorded in `.upstream-commit`. A monthly GitHub
Actions workflow (`.github/workflows/sync-test-suite.yaml`) checks for updates
upstream and opens a draft PR if anything has changed.
