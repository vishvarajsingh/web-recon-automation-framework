# Web Recon Automation Framework

Web Recon Automation Framework is a passive-only web reconnaissance application for authorized security assessments. It collects publicly available security-relevant information and produces structured JSON and HTML reports.

The current project includes:

- A Python CLI for direct reconnaissance runs.
- A FastAPI application with a browser-based scanner.
- The existing passive reconnaissance engine shared by both entry points.
- Local database persistence for web investigations.
- Real-time persisted scan status and report retrieval.

Use this project only against systems you own or are explicitly authorized to assess.

## Web Application

The verified local browser flow is:

```text
Browser -> FastAPI frontend -> passive recon engine -> SQLite database -> JSON/HTML reports -> browser results
```

The frontend is served by FastAPI at `/app/`. A user enters a public domain or URL, starts a scan, watches the persisted status update, and reviews the returned evidence categories and generated reports.

The public browser scanner uses these same-origin endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /web-api/investigations/` | Queue a target for passive reconnaissance |
| `GET /web-api/investigations/{id}` | Read persisted status, progress, and completed results |
| `GET /web-api/investigations/{id}/report/download` | Retrieve the generated JSON report |
| `GET /web-api/investigations/{id}/report/html` | Retrieve the generated HTML report |
| `GET /health/db` | Check local database availability |

The separate `/api` investigation and dashboard routes are protected by the configured backend API key and are intended for internal/API clients. The browser UI does not request or expose that key.

## Features

- Passive WHOIS lookup.
- DNS records: A, AAAA, MX, NS, TXT, and CNAME.
- IPv4, IPv6, and reverse-DNS resolution.
- HTTP response metadata, redirects, cookies, cache headers, and bounded response content.
- Verified TLS certificate inspection, including issuer, subject, validity, signature algorithm, and SAN entries.
- `robots.txt` collection.
- `sitemap.xml` and `sitemap_index.xml` collection.
- Technology detection from public headers and response content.
- Security-header inspection for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- Passive exposure detection from robots content, sitemap entries, headers, and bounded HTML content.
- Deterministic security-risk scoring and exposure severity counts.
- Rich CLI output with scan status, exposure findings, and execution summary.
- Structured JSON reports and generated HTML reports.
- File logging through `logs/recon.log`.
- FastAPI web scanning with persisted investigation status and results.
- Browser result viewing for DNS/IP, HTTP, SSL/TLS, technologies, security headers, exposures, risk, and reports.

## Web UI Flow

1. Open the local scanner.
2. Enter a public domain or URL, such as `example.com`.
3. Select **Scan target**.
4. The browser displays the real queued/running status from FastAPI.
5. After completion, the results card opens the real evidence categories returned by the backend.
6. Individual categories show the persisted module data.
7. JSON and HTML report actions retrieve the generated report files.
8. Invalid, blocked, unavailable, or failed targets show the backend error and a retry action.

## Recon Modules

| Module | What it collects or analyzes | Status |
| --- | --- | --- |
| WHOIS | Registrar, domain dates, and name servers when available | Implemented and exercised by the CLI/web engine |
| DNS | A, AAAA, MX, NS, TXT, and CNAME records | Implemented and tested |
| IP resolution | IPv4, IPv6, and reverse DNS | Implemented and exercised by the CLI/web engine |
| HTTP | Response metadata, bounded content, redirects, cookies, and cache headers | Implemented and tested |
| SSL/TLS | Verified peer certificate details and validity | Implemented and tested |
| robots.txt | Publicly referenced paths | Implemented and exercised by the CLI/web engine |
| Sitemap | Sitemap and sitemap-index content | Implemented and exercised by the CLI/web engine |
| Technology detection | Public server/framework indicators | Implemented and exercised by the CLI/web engine |
| Security headers | Common browser and transport security headers | Implemented and exercised by the CLI/web engine |
| Exposure detection | Passive indicators in robots, sitemaps, headers, and page content | Implemented and tested |
| Risk engine | Deterministic score and rating from observed security conditions | Implemented and tested |

## Risk Engine

The security score starts at zero and adds:

- `15` for missing HSTS.
- `15` for missing Content-Security-Policy.
- `10` for missing X-Frame-Options.
- `35` for an expired TLS certificate when TLS inspection succeeds.
- `10` for a TLS certificate with fewer than 30 days remaining when TLS inspection succeeds.
- `10` for an HTTP status code of 500 or higher.

The score is capped at 100. Ratings are:

| Score | Rating |
| --- | --- |
| 0–20 | Low |
| 21–40 | Medium |
| 41–70 | High |
| 71–100 | Critical |

Exposure findings use the highest observed finding severity. If no findings exist, the exposure rating is `Informational`.

## Security Controls

The current implementation includes:

- Passive collection only; it does not add exploitation or intrusive scanning features.
- Public-target validation before web scans.
- Blocking of private, loopback, link-local, reserved, and other non-global destinations.
- Blocking of targets containing embedded credentials.
- Redirect validation for every outbound HTTP redirect.
- A three-redirect limit.
- A bounded response-content limit of 1 MiB.
- Backend scan concurrency limited by configuration, defaulting to two workers.
- Backend scan timeout limited by configuration, defaulting to 120 seconds.
- API-key protection for the internal `/api` investigation, dashboard, chat, and report routes.
- Configurable CORS origins; credentials are disabled by default.
- Report path containment under the configured backend report directory.
- HTML value escaping in generated reports and frontend result rendering.

The public browser scanner intentionally does not ask users for the internal API key. Deployments exposing the public scanner should add operational controls such as authentication, rate limiting, and an appropriate reverse proxy policy before making it internet-facing.

## Reporting and Persistence

CLI runs write timestamped JSON and HTML reports to `reports/` by default. Web-triggered investigations write reports to `backend_reports/` and persist investigation metadata, progress, risk values, report paths, and completed raw output in the configured database.

Local backend execution defaults to SQLite at `backend_data.db`. A PostgreSQL connection can be supplied through `DATABASE_URL` for an appropriately configured environment. Generated reports, logs, and the local database are runtime artifacts and are ignored by the repository configuration.

Generated JSON contains metadata, normalized target information, module results, module statuses, risk output, exposure output, executive summary, and report paths. Generated HTML contains an executive summary, severity overview, exposure findings, summary metrics, and rendered module data.

## Project Structure

```text
Web Recon Automation Framework/
├── backend/
│   └── app/
│       ├── api/
│       │   ├── web.py
│       │   ├── investigations.py
│       │   ├── investigation_reports.py
│       │   ├── dashboard.py
│       │   └── chat.py
│       ├── core/
│       │   ├── config.py
│       │   └── database.py
│       ├── services/
│       │   ├── engine_runner.py
│       │   ├── job_service.py
│       │   ├── target_security.py
│       │   └── report_service.py
│       ├── main.py
│       ├── models.py
│       ├── schemas.py
│       └── security.py
├── frontend/
│   └── app/
│       ├── index.html
│       ├── app.js
│       └── styles.css
├── modules/
│   ├── whois_lookup.py
│   ├── dns_lookup.py
│   ├── ip_lookup.py
│   ├── http_headers.py
│   ├── ssl_info.py
│   ├── robots.py
│   ├── sitemap.py
│   ├── tech_detector.py
│   ├── security_headers.py
│   ├── exposure_engine.py
│   ├── risk_engine.py
│   ├── input_validator.py
│   └── network_policy.py
├── reporting/
│   └── report_generator.py
├── tests/
├── main.py
├── config.py
├── requirements.txt
├── pyproject.toml
├── test_framework.py
└── LICENSE
```

## Installation

Requirements:

- Python 3.10 or newer.
- pip.

From the project root on Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m pip install pytest httpx2
```

`backend\requirements.txt` contains the backend dependencies and the runtime dependencies used by the reconnaissance engine.

## Run the Web Application

From the project root with the virtual environment activated:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/app/
```

The command and URL above have been verified against the current application.

## CLI Usage

The direct CLI remains available:

```powershell
.\.venv\Scripts\python.exe main.py example.com
```

The CLI prints module completion, exposure findings, risk values, and report paths. Its reports are written to `reports/`.

## Testing

Run the complete test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The current verified result is **34 passed**. The standalone compatibility script can also be run with:

```powershell
.\.venv\Scripts\python.exe test_framework.py
```

## Limitations

- Results depend on DNS, WHOIS, TLS, and HTTP availability from the executing environment.
- Some domains block or omit WHOIS, robots, sitemaps, headers, or certificate access; those modules report structured failure or not-found states.
- Exposure detection identifies passive references and indicators; it does not verify exploitability or perform intrusive requests.
- The public web scanner is designed for local or controlled authorized use and does not provide production-grade user identity, rate limiting, or multi-tenant isolation by itself.
- Docker files are present in the repository, but a complete Docker build/start validation has not been verified in the current environment and is not documented as a supported deployment method here.
- The repository contains generated runtime artifacts locally, but they are not treated as versioned example outputs by this README.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
