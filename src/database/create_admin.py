"""Create (or reset the password of) an Admin user. Run from src/: python -m database.create_admin"""
import getpass
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from argon2 import PasswordHasher
from database.connection import SessionLocal
from database.models import User

MIN_PASSWORD_LENGTH = 12


def create_admin():
    username = input("Admin username [admin]: ").strip() or "admin"
    email = input("Email (optional): ").strip() or None
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")

    password_hash = PasswordHasher().hash(password)
    with SessionLocal() as session:
        user = session.query(User).filter_by(Username=username).first()
        if user:
            user.PasswordHash = password_hash
            user.Role = "Admin"
            action = "Password reset for"
        else:
            session.add(User(Username=username, Email=email, PasswordHash=password_hash, Role="Admin"))
            action = "Created"
        session.commit()
    print(f"{action} admin user '{username}'.")


if __name__ == "__main__":
    create_admin()
