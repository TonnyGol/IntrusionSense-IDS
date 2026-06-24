import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

# First connect to the server 
SERVER_URI = f'mysql+pymysql://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}/'

server_engine = create_engine(SERVER_URI, echo=False)

create_db_sql = f"CREATE DATABASE IF NOT EXISTS {config.DB_NAME} DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;"
with server_engine.connect() as conn:
    conn.execution_options(isolation_level="AUTOCOMMIT")
    conn.execute(text(create_db_sql))
    conn.commit()

# connect to the specific database
DATABASE_URI = f'mysql+pymysql://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}/{config.DB_NAME}'
engine = create_engine(DATABASE_URI, echo=False)

# create a base class for the models
Base = declarative_base()

SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

Base.metadata.create_all(engine)

print("Connected to IntrusionSenseDB successfully!")