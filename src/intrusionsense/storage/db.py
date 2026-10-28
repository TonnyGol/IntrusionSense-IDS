from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from intrusionsense.config import ServerSettings
from intrusionsense.storage.models import Base


def mysql_url(settings: ServerSettings) -> URL:
    # URL.create escapes special characters in the password
    return URL.create(
        "mysql+pymysql",
        username=settings.db_user,
        password=settings.db_password,
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def create_db_engine(url: URL | str) -> Engine:
    # pre-ping: MySQL closes idle connections, and the first query after a quiet period would fail
    return create_engine(url, pool_pre_ping=True)


def init_db(engine: Engine) -> sessionmaker:
    """Create any missing tables and return a session factory."""
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
