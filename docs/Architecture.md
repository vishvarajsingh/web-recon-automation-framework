# Architecture

The framework is organized as a modular, passive reconnaissance pipeline.

```mermaid
flowchart TD
    A[User] --> B[Input Validation]
    B --> C[Recon Engine]
    C --> D[WHOIS]
    C --> E[DNS]
    C --> F[HTTP]
    C --> G[SSL/TLS]
    C --> H[robots.txt]
    C --> I[sitemap.xml]
    D --> J[Exposure Detection Engine]
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J
    J --> K[Risk Engine]
    K --> L[Report Generator]
    L --> M[JSON Report]
    L --> N[HTML Dashboard]
```

## Design Principles

- Passive-only data collection
- Graceful failure for unsupported or blocked resources
- Modular execution for maintainability
- Structured JSON and HTML reporting
