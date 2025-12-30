from fastapi import Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import verify_password, create_access_token, decode_access_token
from backend.app.repositories.user_repo import UserRepository
from backend.app.schemas.token import TokenPayload, Token
from backend.app.core.exceptions import AuthenticationException
from backend.app.schemas.user import UserLogin

class AuthService :
    def login(self, user_login: UserLogin, db: Session = Depends(get_db)) -> Token:
        user_repo = UserRepository()
        user = user_repo.get_by_email(db , user_login.email)

        if not user:
            raise AuthenticationException("Invalid email or password")
        hashed_password = user.hashed_password
        if not verify_password(user_login.password, hashed_password):
            raise AuthenticationException("Invalid email or password")
        
        access_token = create_access_token(data={"sub": user.email})

        return Token(access_token=access_token, token_type="bearer")


    # def validate_token(self, token: str) -> TokenPayload:
    #     payload = decode_access_token(token)
    #     if not payload:
    #         raise InvalidTokenError("Token is invalid or expired")
    #     #TokenPayload(payload, payload)
    #     return TokenPayload(**payload)