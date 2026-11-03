# Changelog

## Unreleased

- Clarified the additive risk metric as observed risk points (higher means more observed risk), added per-module evidence completeness, returned `Unknown` risk interpretations for incomplete checks, and persisted the evidence state through database/API/history responses.
- Separated unique candidate URLs, heuristic observations, exact-request attempts, HTTP responses, and unassessed misconfiguration/vulnerability categories in JSON, CLI, dashboard, and HTML report wording. Removed the misleading exposed-resource total.
- Recorded exact requested URLs and response statuses, including redirect responses, and prevented root-page status attribution to other candidate paths. Discovered candidate paths remain unrequested.
- Made robots.txt and sitemap comparisons treat truncated or structurally incomplete content as `UNKNOWN` for removals/resolutions.
- Expanded passive technology fingerprints to explicit response headers, HTML generator metadata, selected cookie names/attributes, and known asset paths. Results now carry source evidence/confidence and distinguish identified, no-match, incomplete, and failed states.
- Added deterministic tests for complete/incomplete risk evidence, candidate deduplication and exact-request attribution, truncated historical evidence, technology false positives/confidence, and CLI/API/dashboard/HTML terminology consistency.
- Added normalized asset records linked to investigations, with a safe startup migration that backfills existing scan rows without deleting their reports or result data.
- Added paginated asset inventory/history APIs, first/last-seen timestamps, and reruns as new historical investigations.
- Added a deterministic scan-diff engine for DNS, HTTP/security headers, cookies and collected cookie flags, TLS fields, technologies, exposure observations, and risk factors/scores.
- Added `UNKNOWN` comparisons for missing or failed evidence so absence is not treated as a removal or resolution; risk deltas are withheld when scoring inputs are incomplete.
- Added the asset history and scan comparison controls to the existing browser page, plus an on-demand escaped HTML comparison report with expandable evidence.
- Added deterministic regression tests for asset normalization/deduplication, migration backfill, pagination, API validation, evidence changes, incomplete modules, report escaping, and failed-module false-resolution cases.
- Added per-factor evidence, confidence, and explanation to deterministic risk scoring. TLS expiry contributions are mutually exclusive so an expired certificate is not counted again as merely nearing expiry; malformed and out-of-range HTTP statuses do not affect the score.
- Extended exposure findings with a consistent set of description, affected asset, confidence, detection method, timestamp, impact rationale, remediation, and references fields.
- Expanded generated HTML reports with assessment scope and methodology, richer finding context, risk score contributions, and an explicit limitations and authorized-use statement.
- Added ignore rules for environment secrets, local databases, and generated backend reports.
- Updated README setup guidance and documented CVE correlation and technology versioning as limitations because those capabilities are not implemented.
- Added regression coverage for score explanations, duplicate TLS expiry contributions, and ignoring failed/invalid check evidence.
- Audited direct imports and consolidated runtime plus test dependencies in the root requirements file; the backend requirements file now includes it. Added version constraints, PostgreSQL driver and dotenv support, and test dependencies. Starlette's TestClient warning prompted replacing `httpx` with `httpx2`.
- Verification: full pytest suite **60 passed** on Python 3.14; `compileall`, JavaScript syntax check, root/database health checks, and `pip check` passed. `httpx2` resolved the Starlette TestClient warning. Browser automation tools were unavailable, so the new page flow was verified through served-HTML/API tests and JavaScript syntax validation rather than visual browser automation.
