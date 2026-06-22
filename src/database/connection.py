import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import config
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# החלף את user ו-password בשם המשתמש והסיסמה שלך ב-MySQL
# במקרה של עבודה מקומית, ה-host הוא localhost
DATABASE_URI = f'mysql+pymysql://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}/{config.DB_NAME}'

# יצירת מנוע החיבור למסד הנתונים
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