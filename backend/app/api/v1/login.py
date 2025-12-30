from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.schemas.user import UserLogin
from backend.app.schemas.token import Token
from backend.app.services.auth_service import AuthService

router = APIRouter()

@router.post(
    "/login",
    response_model=Token,
    status_code=status.HTTP_201_CREATED,
)
def login(
    user_in: UserLogin,
    db: Session = Depends(get_db),
):
    try:
        authentication = AuthService()
        user = authentication.login(user_in, db)
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
