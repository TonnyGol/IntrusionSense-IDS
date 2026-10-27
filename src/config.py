from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent

ATTACK_LABELS = {
    0: 'Bots',
    1: 'Brute Force',
    2: 'DDoS',
    3: 'DoS',
    4: 'Port Scanning',
    5: 'Web Attacks'
}


class Settings(BaseSettings):
    """Values come from environment variables, then the repo-root .env file."""
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", extra="ignore")

    db_user: str = "intrusionsense"
    db_password: str  # required: no default credentials
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "intrusionsense"

    # Layer 1 "suspicious" probability above which a flow goes to Layer 2
    l1_threshold: float = 0.20


settings = Settings()
