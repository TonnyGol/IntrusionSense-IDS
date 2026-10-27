import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from config import settings
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

# URL.create escapes special characters in the password
SERVER_URI = URL.create(
    "mysql+pymysql",
    username=settings.db_user,
    password=settings.db_password,
    host=settings.db_host,
    port=settings.db_port,
)

server_engine = create_engine(SERVER_URI, echo=False)

create_db_sql = f"CREATE DATABASE IF NOT EXISTS `{settings.db_name}` DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;"
with server_engine.connect() as conn:
    conn.execution_options(isolation_level="AUTOCOMMIT")
    conn.execute(text(create_db_sql))
    conn.commit()

# connect to the specific database
DATABASE_URI = SERVER_URI.set(database=settings.db_name)
engine = create_engine(DATABASE_URI, echo=False)

# create a base class for the models
Base = declarative_base()

SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

# tables are created in database/models.py, once the model classes exist
print("Connected to IntrusionSenseDB successfully!")
