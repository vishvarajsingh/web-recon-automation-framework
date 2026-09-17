# Backend API - Web Recon Automation Platform

This backend provides a REST API wrapper for the existing Python reconnaissance engine.

## Features

- FastAPI app with CORS enabled
- PostgreSQL persistence for investigations
- Structured JSON report storage
- Investigation CRUD and reporting endpoints

## Getting started

1. Create a Python environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate
pip install -r requirements.txt
```

2. Start the backend:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3. Open the API docs:

- http://localhost:8000/docs

## Docker

```bash
docker-compose up --build
```

## Notes

This backend is scaffolded to support the existing `modules` engine and future AI/chat integrations.
