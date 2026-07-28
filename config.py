"""Configuration values for the reconnaissance framework."""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = ROOT_DIR / "reports"
LOGS_DIR = ROOT_DIR / "logs"
ASSETS_DIR = ROOT_DIR / "assets"

TIMEOUT_SECONDS = 8
USER_AGENT = "WebReconAutomationFramework/1.0 (+https://example.com)"
OUTPUT_DIRECTORY = REPORTS_DIR
LOG_FILE = LOGS_DIR / "recon.log"

# Optional API keys. Leave empty unless you explicitly configure a provider.
GEOCODING_API_KEY = ""
