import hashlib
import secrets

from sqlalchemy.orm import Session

from intrusionsense.storage.models import Sensor, utc_now

TOKEN_BYTES = 32


def hash_token(token: str) -> str:
    # tokens are 256 random bits, so a fast hash is safe here (unlike passwords, which need argon2)
    return hashlib.sha256(token.encode()).hexdigest()


def create_sensor(session: Session, name: str) -> str:
    """Register a sensor and return its token. Only the hash is stored: the token is shown once."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    session.add(Sensor(Name=name, TokenHash=hash_token(token)))
    session.commit()
    return token


def authenticate_sensor(session: Session, token: str) -> Sensor | None:
    sensor = session.query(Sensor).filter_by(TokenHash=hash_token(token), IsActive=True).first()
    if sensor is not None:
        sensor.LastSeenAt = utc_now()
        session.commit()
    return sensor
