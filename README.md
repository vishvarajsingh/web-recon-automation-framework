# Web Recon Automation Framework

A locally runnable Python reconnaissance framework for authorized domain and website analysis. It gathers public information such as WHOIS, DNS, IP resolution, HTTP headers, SSL details, robots.txt, sitemaps, security headers, and passive exposure indicators.

## Features

- Accepts a domain or full URL from the command line.
- Normalizes the target and validates it safely.
- Collects publicly available data without exploitation.
- Separates security risk from exposure risk.
- Produces a structured JSON report and a professional HTML report with an executive summary and exposed-resource alerts.
- Keeps all checks passive and based only on publicly observable information.

## Run

```powershell
.\.venv\Scripts\python.exe main.py example.com
.\.venv\Scripts\python.exe main.py https://example.com
```

## Report Contents

The framework now includes:

- Security scoring with deterministic thresholds (Low, Medium, High, Critical)
- Exposure detection based on robots.txt, sitemap.xml, HTML content, JavaScript references, and HTTP headers
- Structured exposure findings with title, resource, category, severity, source, evidence, reason, and recommendation
- Terminal alert panels and a richer HTML report with severity cards and remediation guidance

## Notes

- Use only for domains you own or are explicitly authorized to test.
- The framework is limited to passive reconnaissance and information gathering.
- It does not perform brute force, exploitation, credential attacks, or destructive requests.
