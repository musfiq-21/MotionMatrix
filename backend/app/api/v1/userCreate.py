from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.utils.enums import UserRole, APIEndpoint
from backend.app.core.database import get_db
from backend.app.schemas.user import UserResponse, UserCreate
from backend.app.services.user_service import create_user
from backend.app.services.auth_service import require_authorization
router = APIRouter()

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_in: UserCreate,
    db: Session = Depends(get_db),
    current_user: UserRole = Depends(require_authorization(APIEndpoint.REGISTER_USER)),
):
    print("Current user role:", current_user)
    try:
        user = create_user(db, user_in)
        return user #atm, it is not userResponse, edit it. * fixed at 27/12/25
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
