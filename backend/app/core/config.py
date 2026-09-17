import os
from pathlib import Path
from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Web Recon Automation Platform")
    DATABASE_URL: str = os.getenv("DATABASE_URL", os.getenv("SQLALCHEMY_DATABASE_URL", f"sqlite:///{ROOT_DIR / 'backend_data.db'}"))
    REPORTS_DIR: Path = ROOT_DIR / "reports"
    OUTPUT_DIR: Path = ROOT_DIR / "backend_reports"
    API_PREFIX: str = "/api"
    DEBUG: bool = os.getenv("DEBUG", "0") == "1"
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "ollama")
    API_KEY: str = os.getenv("BACKEND_API_KEY", "")
    ALLOWED_ORIGINS: tuple[str, ...] = tuple(
        origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if origin.strip()
    )
    ALLOW_CREDENTIALS: bool = os.getenv("ALLOW_CREDENTIALS", "0") == "1"
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))


settings = Settings()
