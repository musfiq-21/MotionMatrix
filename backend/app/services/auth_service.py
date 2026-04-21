from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Annotated, Callable

from backend.app.core.database import get_db
from backend.app.core.security import verify_password, create_refresh_token, decode_access_token
from backend.app.repositories.user_repo import UserRepository
from backend.app.schemas.token import TokenPayload, Token, RefreshToken
from backend.app.core.exceptions import AuthenticationException, InvalidTokenException, BusinessLogicException
from backend.app.schemas.user import UserLogin
from backend.app.utils.enums import UserRole, APIEndpoint
from backend.app.models.user import User

def auth_service_login(user_login: UserLogin, db: Session = Depends(get_db)) -> Token:
    user_repo = UserRepository()
    user = user_repo.get_by_email(user_login.email, db)
    print(user.email, user.hashed_password)

    if not user:
        raise AuthenticationException("Invalid email or password")
    hashed_password = user.hashed_password
    if not verify_password(user_login.password, hashed_password):
        raise AuthenticationException("Invalid email or password")

    access_token = create_refresh_token(data={"sub": user.email})

    return Token(access_token=access_token, token_type="bearer")


def auth_service_validate_token(token: RefreshToken, db: Session = Depends(get_db)) -> TokenPayload:
    payload = decode_access_token(token.refresh_token)
    if not payload:
        raise InvalidTokenException("Token is invalid or expired")

    dt = datetime.fromtimestamp(int(payload['exp'])) + timedelta(days=7)    # exp date increased 7 days

    user_email = payload['sub']
    user_repo = UserRepository()
    user = user_repo.get_by_email(email=user_email, db=db)
    token = TokenPayload(sub=user.id, role=UserRole(user.role), email=user.email, exp=dt)

    return token
AUTHORIZATION_MAP: Dict[APIEndpoint, List[UserRole]] = {
    APIEndpoint.REGISTER_USER: [UserRole.ADMIN],
    APIEndpoint.DELETE_USER: [UserRole.ADMIN]
}

def get_authorized_roles(endpoint: APIEndpoint) -> List[UserRole]:
    """Get list of roles authorized for an endpoint"""
    return AUTHORIZATION_MAP.get(endpoint, [])

def is_authorized(user_role: str, endpoint: APIEndpoint) -> bool:
    """Check if a user role is authorized for an endpoint"""
    authorized_roles = get_authorized_roles(endpoint)
    return user_role in [role.value for role in authorized_roles]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Session = Depends(get_db)
):
    payload = decode_access_token(token)
    if not payload:
        raise InvalidTokenException("Token is invalid or expired")

    print(payload)
    user_repo = UserRepository()
    user = user_repo.get_by_email(payload.get("sub"), db)   #the sub is the email

    return user

def require_authorization(endpoint: APIEndpoint):
    """
    Dependency factory that checks if current user is authorized for an endpoint.

    Usage:
        @router.post("/register")
        def register(
            current_user: User = Depends(require_authorization(APIEndpoint.REGISTER_USER))
        ):
            ...
    """

    async def authorization_checker(
            current_user: Annotated[User, Depends(get_current_user)]
    ):
        print(f"Checking authorization for user {current_user.email} with role {current_user.role} on endpoint {endpoint}")
        if not is_authorized(current_user.role, endpoint):
            authorized_roles = get_authorized_roles(endpoint)
            roles_str = ", ".join([role.value for role in authorized_roles])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {roles_str}. Your role: {current_user.role}"
            )
        return current_user

    return authorization_checker
