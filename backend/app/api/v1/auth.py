"""
Authentication API endpoints.

POST /auth/login            - Login with email/password
POST /auth/refresh          - Refresh JWT token
POST /auth/logout           - Logout (blacklist token)
POST /auth/change-password  - Change password for authenticated user
POST /auth/forgot-password  - Request password reset token
POST /auth/reset-password   - Reset password using a reset token
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user
from backend.app.core.security import (
    create_access_token,
    verify_password,
    hash_password,
    blacklist_token,
    generate_secure_token,
)
from backend.app.models.user import User
from backend.app.repositories.user_repo import UserRepository
from backend.app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    TokenResponse,
    RefreshTokenRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# In-memory store for password reset tokens: {token: email}
# In production this should be persisted (e.g. Redis or a DB table).
_reset_tokens: dict[str, str] = {}

_http_bearer = HTTPBearer(auto_error=False)


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    from backend.app.core.config import get_settings
    settings = get_settings()

    user_repo = UserRepository()
    user = user_repo.get_by_email(data.email, db)

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.email})
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh an expired access token using a refresh token."""
    from backend.app.core.security import decode_access_token
    from jose import JWTError
    from backend.app.core.config import get_settings
    settings = get_settings()

    try:
        payload = decode_access_token(data.refresh_token)
    except (JWTError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    new_token = create_access_token(data={"sub": email})
    return TokenResponse(
        access_token=new_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(_http_bearer),
    current_user: User = Depends(get_current_user),
):
    """Invalidate the current access token."""
    if credentials:
        blacklist_token(credentials.credentials)


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change password for the currently authenticated user."""
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password and confirm password do not match",
        )

    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    current_user.hashed_password = hash_password(data.new_password)
    current_user.is_first_login = False
    db.commit()
    return {"message": "Password changed successfully"}


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Generate a password reset token for the given email.

    The token is returned in the response body (for development).
    In production this should be sent via email.
    """
    user_repo = UserRepository()
    user = user_repo.get_by_email(data.email, db)

    # Always return 200 to avoid leaking whether an email is registered
    if not user:
        return {"message": "If the email is registered you will receive a reset link"}

    token = generate_secure_token(32)
    _reset_tokens[token] = user.email
    # TODO: send_reset_email(user.email, token)
    return {
        "message": "Password reset token generated",
        "reset_token": token,  # Remove this in production
    }


@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using a previously issued reset token."""
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password and confirm password do not match",
        )

    email = _reset_tokens.pop(data.token, None)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    user_repo = UserRepository()
    user = user_repo.get_by_email(email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = hash_password(data.new_password)
    user.is_first_login = False
    db.commit()
    return {"message": "Password reset successfully"}
