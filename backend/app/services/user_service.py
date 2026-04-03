"""
User service layer.

Business logic for creating and querying users.
"""

from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.core.security import hash_password
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserResponse
from backend.app.utils.enums import UserRole, UserStatus


def get_user_by_id(db: Session, user_id: UUID):
    """Return a User by UUID primary key, or None."""
    return db.query(User).filter(User.id == user_id).first()


def get_all_users_service(db: Session, skip: int = 0, limit: int = 50):
    """Return a paginated list of all users."""
    return db.query(User).offset(skip).limit(limit).all()


def create_user(db: Session, user_data: UserCreate) -> UserResponse:
    """
    Create a new user.

    Raises:
        ValueError: If the email is already registered.
    """
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise ValueError("Email already registered")

    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        phone_number=user_data.phone_number,
        role=user_data.role.value if hasattr(user_data.role, "value") else user_data.role,
        status=UserStatus.ACTIVE.value,
        is_first_login=True,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        full_name=new_user.full_name,
        phone_number=new_user.phone_number,
        role=UserRole(new_user.role),
        status=UserStatus(new_user.status),
        is_first_login=new_user.is_first_login,
        created_at=new_user.created_at,
        updated_at=new_user.updated_at,
        created_by_id=new_user.created_by_id,
    )
