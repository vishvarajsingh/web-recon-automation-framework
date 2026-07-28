# Installation

## Requirements

- Python 3.10+
- pip

## Setup

```powershell
git clone <repository-url>
cd web-recon-automation-framework
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt pytest rich cryptography
```

## Run the Framework

```powershell
.\.venv\Scripts\python.exe main.py example.com
```

## Run Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
