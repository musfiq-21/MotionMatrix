from backend.app.core.database import SessionLocal
from backend.app.models.user import User
from backend.app.utils.enums import UserStatus
from backend.app.core.security import hash_password

from bcrypt import _bcrypt



def create_superadmin(full_name, email, password, phone_number):
    db = SessionLocal()   # ✅ FIXED

    try:
        # Check if already exists
        existing = db.query(User).filter(
            (User.email == email) | (User.full_name == full_name)
        ).first()

        if existing:
            print("User already exists")
            return
        password = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
        hashed = hash_password(password)
        user = User(
            full_name=full_name,
            email=email,
            hashed_password= hashed,
            phone_number=phone_number,
            role='ADMIN',
            status=UserStatus.ACTIVE.value,
            is_first_login=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        print(f"Superadmin created with ID: {user.id}")

    finally:
        db.close()   # ✅ proper cleanup


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--fullname", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--phonenumber", required=True)

    args = parser.parse_args()

    create_superadmin(args.fullname, args.email, args.password, args.phonenumber)