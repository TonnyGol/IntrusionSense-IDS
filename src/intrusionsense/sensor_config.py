"""Where the packaged sensor finds its server address and token when the command line does not give them.
Kept free of server and machine-learning imports, like sensor_cli.py."""

import sys
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILE_NAME = "sensor.conf"
SERVER_KEY = "server"
TOKEN_KEY = "token"
COMMENT_PREFIX = "#"
FILE_ENCODING = "utf-8-sig"  # Windows Notepad adds a byte-order mark
PROMPT_SERVER = "Server address [{default}]: "
PROMPT_TOKEN = "Sensor token (shown once when you register the sensor in the dashboard): "
PROMPT_CLOSE = "Press Enter to close this window."


@dataclass(frozen=True)
class SensorConfig:
    server: str | None = None
    token: str | None = None


def config_path() -> Path:
    # Next to the program, so a downloaded sensor.conf and the .exe just sit in one folder.
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()
    return base / CONFIG_FILE_NAME


def load_config(path: Path) -> SensorConfig:
    if not path.is_file():
        return SensorConfig()
    values = {}
    for line in path.read_text(encoding=FILE_ENCODING).splitlines():
        line = line.strip()
        if not line or line.startswith(COMMENT_PREFIX) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().lower()] = value.strip().strip("\"'")
    return SensorConfig(server=values.get(SERVER_KEY) or None, token=values.get(TOKEN_KEY) or None)


def save_config(path: Path, config: SensorConfig) -> None:
    path.write_text(f"{SERVER_KEY}={config.server}\n{TOKEN_KEY}={config.token}\n", encoding="utf-8")


def ask_and_save(path: Path, default_server: str) -> SensorConfig:
    server = input(PROMPT_SERVER.format(default=default_server)).strip() or default_server
    token = input(PROMPT_TOKEN).strip()
    config = SensorConfig(server=server, token=token or None)
    if config.token:
        save_config(path, config)
    return config


def wait_before_window_closes() -> None:
    """A double-clicked program closes its window the moment it exits, hiding the reason."""
    if getattr(sys, "frozen", False) and sys.stdin and sys.stdin.isatty():
        input(PROMPT_CLOSE)
