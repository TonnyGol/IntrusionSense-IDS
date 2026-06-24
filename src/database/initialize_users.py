import sys
import os
import hashlib

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from database.connection import SessionLocal, engine, Base
from database.models import User

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def seed_users():
    session = SessionLocal()
    
    try:
        existing_admin = session.query(User).filter_by(Username='admin_root').first()
        if existing_admin:
            print("❌ Users already exist in the database. Skipping seeding.")
            return
        
        # Define users with clear-text passwords (only in this script)
        users_data = [
            {
                'username': 'admin_root',
                'email': 'admin@intrusionsense.local',
                'password': 'admin123',
                'role': 'Admin'
            },
            {
                'username': 'soc_manager',
                'email': 'manager@intrusionsense.local',
                'password': 'manager345',
                'role': 'Manager'
            },
            {
                'username': 'analyst_tonny',
                'email': 'tonny@intrusionsense.local',
                'password': 't123',
                'role': 'SOC Analyst'
            },
            {
                'username': 'analyst_daniel',
                'email': 'daniel@intrusionsense.local',
                'password': 'd123',
                'role': 'SOC Analyst'
            }
        ]
        
        # Create and insert users
        for user_data in users_data:
            hashed_pwd = hash_password(user_data['password'])
            user = User(
                Username=user_data['username'],
                Email=user_data['email'],
                PasswordHash=hashed_pwd,
                Role=user_data['role']
            )
            session.add(user)
            print(f"✅ Added user: {user_data['username']} (Role: {user_data['role']})")
        
        session.commit()
        print("\n✅ All users seeded successfully!")
        
    except Exception as e:
        session.rollback()
        print(f"❌ Error seeding users: {e}")
        raise
    finally:
        session.close()

if __name__ == '__main__':
    seed_users()
