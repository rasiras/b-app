from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/bug_bounty_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # Security
    SECRET_KEY: str = "your-secret-key-here-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"
    
    # Scanning Tools Paths
    SUBFINDER_PATH: str = "subfinder"
    AMASS_PATH: str = "amass"
    HTTPX_PATH: str = "httpx"
    NUCLEI_PATH: str = "nuclei"
    NAABU_PATH: str = "naabu"
    
    # Scanning Configuration
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 3600  # 1 hour
    SCAN_RESULTS_DIR: str = "/app/scan_results"
    
    # Notifications
    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    REQUESTS_PER_MINUTE: int = 100
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # CVE Database
    CVE_UPDATE_INTERVAL: int = 86400  # 24 hours
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Create global settings instance
settings = Settings()

# Create scan results directory if it doesn't exist
if not os.path.exists(settings.SCAN_RESULTS_DIR):
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)