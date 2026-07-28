# Features

## WHOIS Module
The WHOIS module collects passive registrar and domain registration details when available.

## DNS Module
The DNS module queries common DNS records such as A, AAAA, MX, NS, TXT, and CNAME.

## HTTP Module
The HTTP module inspects response status, redirects, server headers, content type, and cookies.

## SSL Module
The SSL module inspects TLS certificate data and reports validity windows and certificate metadata.

## Technology Detection
The framework identifies common server and framework clues from headers and page content.

## Exposure Detection
Exposure detection analyzes public evidence such as robots.txt, sitemap.xml, HTML links, JavaScript references, and headers to identify potentially exposed resources without performing intrusive scanning.

## Risk Engine
The risk engine converts observed security issues into a deterministic score and rating.

## Reporting Engine
The reporting engine writes both JSON and HTML reports with executive summaries and structured findings.

## Logger
A reusable logger captures scan state and module execution details.

## Utilities
Helper functions provide safe JSON serialization, timestamps, and normalization utilities.
