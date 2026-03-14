"""
Authentication API endpoints.

POST /auth/login - Login with email/password
POST /auth/refresh - Refresh JWT token
POST /auth/logout - Logout
POST /auth/change-password - Change password
POST /auth/forgot-password - Request password reset
POST /auth/reset-password - Reset password with token
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    TokenResponse,
    RefreshTokenRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    # TODO: Implement using auth_service
    pass


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh an expired access token."""
    # TODO: Implement token refresh
    pass


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(current_user: User = Depends(get_current_user)):
    """Invalidate the current token."""
    # TODO: Implement token invalidation
    pass


@router.post("/change-password")
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change password for the current user."""
    # TODO: Implement password change
    pass


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Send password reset email."""
    # TODO: Implement forgot password flow
    pass


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using a reset token."""
    # TODO: Implement password reset
    pass
