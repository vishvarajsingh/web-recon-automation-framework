# Changelog

## Unreleased

- Added per-factor evidence, confidence, and explanation to deterministic risk scoring. TLS expiry contributions are mutually exclusive so an expired certificate is not counted again as merely nearing expiry; malformed and out-of-range HTTP statuses do not affect the score.
- Extended exposure findings with a consistent set of description, affected asset, confidence, detection method, timestamp, impact rationale, remediation, and references fields.
- Expanded generated HTML reports with assessment scope and methodology, richer finding context, risk score contributions, and an explicit limitations and authorized-use statement.
- Added ignore rules for environment secrets, local databases, and generated backend reports.
- Updated README setup guidance and documented CVE correlation and technology versioning as limitations because those capabilities are not implemented.
- Added regression coverage for score explanations, duplicate TLS expiry contributions, and ignoring failed/invalid check evidence.
- Audited direct imports and consolidated runtime plus test dependencies in the root requirements file; the backend requirements file now includes it. Added version constraints, PostgreSQL driver and dotenv support, and test dependencies. Starlette's TestClient warning prompted replacing `httpx` with `httpx2`.
- Verification: requirements installation succeeded in the existing Python 3.14 environment. Full pytest run: 46 passed, with one Starlette deprecation warning before the `httpx2` switch. The post-switch installation and test run are recorded in the dependency audit report.
