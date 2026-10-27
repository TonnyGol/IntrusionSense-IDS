from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_DIR = PACKAGE_DIR / "models"


class ServerSettings(BaseSettings):
    """Server-side settings, from environment variables or a .env file in the working directory."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    db_user: str = "intrusionsense"
    db_password: str  # required: no default credentials
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "intrusionsense"

    # Layer 1 "suspicious" probability above which a flow goes to Layer 2
    l1_threshold: float = 0.20
    model_dir: Path = DEFAULT_MODEL_DIR

    # localhost only by default: exposing the UI to the network must be a deliberate choice
    web_host: str = "127.0.0.1"
    web_port: int = 8000

    log_level: str = "INFO"
