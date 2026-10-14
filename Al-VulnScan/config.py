"""Central configuration for AI-VulnScan."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project directory.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# NVD configuration.
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

NVD_API_URL = os.getenv(
    "NVD_API_URL",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
).strip()

NVD_TIMEOUT = int(os.getenv("NVD_TIMEOUT", "20"))

NVD_RESULTS_LIMIT = int(
    os.getenv("NVD_RESULTS_LIMIT", "10")
)

# Ollama configuration.
OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434",
).rstrip("/")

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3:latest",
).strip()

OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# Scan and report configuration.
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "900"))

REPORT_PATH = os.getenv(
    "REPORT_PATH",
    str(BASE_DIR / "report.md"),
).strip()
