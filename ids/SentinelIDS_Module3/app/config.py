import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "SentinelIDS"
    APP_VERSION: str = "1.0.0"
    MODULE_NAME: str = "Module 3 - Network Intrusion Detection System"
    API_PREFIX: str = "/api/v1"
    DEBUG: bool = True
    
    # Server Binding
    HOST: str = "0.0.0.0"
    PORT: int = 8002
    
    # Storage Paths
    BASE_DIR: Path = BASE_DIR
    CAPTURES_DIR: Path = BASE_DIR / "captures"
    REPORTS_DIR: Path = BASE_DIR / "reports"
    RULES_PATH: Path = BASE_DIR / "app" / "rules" / "snort_rules.rules"
    MODEL_PATH: Path = BASE_DIR / "app" / "models" / "rf_ids_model.joblib"
    SCALER_PATH: Path = BASE_DIR / "app" / "models" / "rf_scaler.joblib"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/sentinel_ids.db")
    
    # Capture Settings
    DEFAULT_INTERFACE: str = ""
    FLOW_TIMEOUT_SECONDS: int = 15
    MAX_PACKETS_PER_BATCH: int = 500
    
    # Hybrid Detection Settings
    ML_ANOMALY_THRESHOLD: float = 0.60
    HIGH_RISK_THRESHOLD: float = 70.0
    CRITICAL_RISK_THRESHOLD: float = 85.0
    
    # Bounded Nmap Scanner Settings (Strictly bounded per slide 10 & 11)
    NMAP_ENABLED: bool = True
    NMAP_TIMEOUT_SECONDS: int = 30
    NMAP_DEFAULT_FLAGS: str = "-Pn -sV -sC --top-ports 20"
    
    # Alert & Incident Analysis
    AUTO_TRIGGER_NMAP_ON_HIGH_RISK: bool = True
    AUTO_TRIGGER_AI_ON_CRITICAL: bool = True
    AI_SUMMARY_PROVIDER: str = os.getenv("AI_SUMMARY_PROVIDER", "heuristic_llm_hybrid")
    
    # Notification Settings
    EMAIL_NOTIFICATIONS_ENABLED: bool = False
    ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "")
    
    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

# Ensure directories exist
settings.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
(BASE_DIR / "app" / "rules").mkdir(parents=True, exist_ok=True)
(BASE_DIR / "app" / "models").mkdir(parents=True, exist_ok=True)
