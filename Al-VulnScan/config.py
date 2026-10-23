"""Validated, centralized configuration for AI-VulnScan."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")


def _positive_int(name: str, default: int, *, maximum: int | None = None) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be greater than zero{upper}.")
    return value


NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_API_URL = os.getenv(
    "NVD_API_URL",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
).strip()
_nvd_url = urlsplit(NVD_API_URL)
if _nvd_url.scheme != "https" or not _nvd_url.netloc:
    raise ValueError("NVD_API_URL must be a valid HTTPS URL.")
NVD_TIMEOUT = _positive_int("NVD_TIMEOUT", 20, maximum=300)
NVD_RESULTS_LIMIT = _positive_int("NVD_RESULTS_LIMIT", 20, maximum=100)
NVD_RETRIES = _positive_int("NVD_RETRIES", 2, maximum=5)

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL", "http://localhost:11434"
).strip().rstrip("/")
_ollama_url = urlsplit(OLLAMA_BASE_URL)
if _ollama_url.scheme not in {"http", "https"} or not _ollama_url.netloc:
    raise ValueError("OLLAMA_BASE_URL must be a valid HTTP(S) URL.")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:latest").strip()
OLLAMA_TIMEOUT = _positive_int("OLLAMA_TIMEOUT", 120, maximum=900)

SCAN_TIMEOUT = _positive_int("SCAN_TIMEOUT", 300, maximum=3600)
MAX_HOST_COUNT = _positive_int("MAX_HOST_COUNT", 16, maximum=256)
MAX_CIDR_SIZE = _positive_int("MAX_CIDR_SIZE", 16, maximum=256)
MAX_CUSTOM_PORTS = _positive_int("MAX_CUSTOM_PORTS", 256, maximum=65535)

REPORT_OUTPUT_DIR = Path(
    os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports"))
).expanduser()
if not REPORT_OUTPUT_DIR.is_absolute():
    REPORT_OUTPUT_DIR = (BASE_DIR / REPORT_OUTPUT_DIR).resolve()
SCAN_STORAGE_DIR = Path(
    os.getenv("SCAN_STORAGE_DIR", str(BASE_DIR / "scan_history"))
).expanduser()
if not SCAN_STORAGE_DIR.is_absolute():
    SCAN_STORAGE_DIR = (BASE_DIR / SCAN_STORAGE_DIR).resolve()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
if not isinstance(getattr(logging, LOG_LEVEL, None), int):
    raise ValueError("LOG_LEVEL must be a valid Python logging level.")
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
