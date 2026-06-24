import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError

# החלף את user ו-password בשם המשתמש והסיסמה שלך ב-MySQL
# במקרה של עבודה מקומית, ה-host הוא localhost
# First connect to the server (no database) so we can create the DB if missing
SERVER_URI = f'mysql+pymysql://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}/'

# יצירת מנוע חיבור לשרת ההודעה
server_engine = create_engine(SERVER_URI, echo=False)

# Create database if it doesn't exist
create_db_sql = f"CREATE DATABASE IF NOT EXISTS {config.DB_NAME} DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;"
with server_engine.connect() as conn:
    conn.execution_options(isolation_level="AUTOCOMMIT")
    conn.execute(text(create_db_sql))
    conn.commit()

# Now connect to the specific database
DATABASE_URI = f'mysql+pymysql://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}/{config.DB_NAME}'
engine = create_engine(DATABASE_URI, echo=False)

# יצירת מחלקה בסיסית עבור המודלים
Base = declarative_base()

# יצירת סשן (Session) לעבודה מול המסד
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

# Import models to register them with Base, then create tables
import database.models
Base.metadata.create_all(engine)

print("Connected to IntrusionSenseDB successfully!")