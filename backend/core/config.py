"""
Central configuration for DNSentinel.
Loads settings from environment variables (.env) with sensible defaults
so the project runs out-of-the-box for a hackathon demo.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "DNSentinel"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = True

    database_url: str = "sqlite:///./dnsentinel.db"

    # Risk engine bands (0-100 scale) - mirrors the SIH260003 playbook
    risk_allow_max: int = 29
    risk_monitor_max: int = 59
    risk_alert_max: int = 79
    # 80-100 => BLOCK

    ml_model_path: str = "backend/ml/model.pkl"
    ml_block_threshold: float = 0.80

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
