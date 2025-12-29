from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.schemas.user import UserResponse, UserLogin
from backend.app.services.user_service import login_user

router = APIRouter()

@router.post(
    "/login",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def login(
    user_in: UserLogin,
    db: Session = Depends(get_db),
):
    try:
        user = login_user(db, user_in)
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
