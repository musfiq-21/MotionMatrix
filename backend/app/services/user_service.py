from backend.app.core.security import hash_password
from backend.app.models.user import  User
from backend.app.schemas.user import UserCreate, UserResponse
from backend.app.utils.enums import UserRole, UserStatus
from sqlalchemy.orm import Session

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_all_users_service(db: Session, skip: int = 0, limit: int = 5):
    return db.query(User).offset(skip).limit(limit).all()

def create_user(db: Session, user_data:UserCreate)-> UserResponse:
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )
    if existing_user:
        raise ValueError("Email already registered")
    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
        status="ACTIVE"
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    new_user_response = UserResponse(
        id=new_user.id,
        email=new_user.email,
        full_name=new_user.full_name,
        role=UserRole(new_user.role),
        status=UserStatus(new_user.status),
        created_at=new_user.created_at,
        is_first_login=False,
        updated_at=new_user.created_at
    )
    return new_user_response
