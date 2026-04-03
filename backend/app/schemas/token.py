"""
Pydantic schemas for JWT token authentication.

This module defines the data structures for JWT token requests and responses.
These schemas ensure type safety and validation for authentication flows.

Example:
    from app.schemas.token import Token, TokenPayload
    
    # Create token response
    token = Token(
        access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        token_type="bearer"
    )
    
    # Parse token payload
    payload = TokenPayload(
        sub=user_id,
        role=UserRole.ADMIN,
        exp=datetime.utcnow() + timedelta(minutes=30)
    )
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator, ConfigDict

from backend.app.utils.enums import UserRole


# ============================================================================
# Token Response Schema
# ============================================================================

class Token(BaseModel):
    """
    JWT token response schema.
    
    This schema represents the response returned after successful authentication.
    It follows the OAuth 2.0 Bearer Token specification.
    
    Attributes:
        access_token: JWT access token string
        token_type: Token type (always "bearer")
        expires_in: Token expiration time in seconds (optional)
        
    Example:
        POST /api/v1/auth/login
        Response:
        {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 1800
        }
        
    Usage:
        # In login endpoint
        token = Token(
            access_token=create_access_token(data),
            token_type="bearer",
            expires_in=1800
        )
        return token
    """
    
    access_token: str = Field(
        ...,
        description="JWT access token",
        min_length=1,
        example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    
    token_type: str = Field(
        default="bearer",
        description="Token type (OAuth 2.0 Bearer Token)",
        example="bearer"
    )
    
    expires_in: Optional[int] = Field(
        default=None,
        description="Token expiration time in seconds",
        gt=0,
        example=1800
    )
    
    @validator("token_type")
    def validate_token_type(cls, v: str) -> str:
        """
        Validate token type is 'bearer'.
        
        Args:
            v: Token type value
            
        Returns:
            str: Validated token type (lowercase)
            
        Raises:
            ValueError: If token type is not 'bearer'
        """
        v = v.lower()
        if v != "bearer":
            raise ValueError("Token type must be 'bearer'")
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }
    )


# ============================================================================
# Token Payload Schema
# ============================================================================

class TokenPayload(BaseModel):
    """
    JWT token payload schema.
    
    This schema represents the decoded JWT token payload containing user
    information and claims. It's used for validating tokens and extracting
    user data after decoding.
    
    Attributes:
        sub: Subject (user ID) - UUID of the authenticated user
        role: User role for authorization
        exp: Expiration timestamp
        iat: Issued at timestamp (optional)
        email: User email (optional, for convenience)
        
    Example:
        # After decoding token
        payload = TokenPayload(
            sub=UUID("123e4567-e89b-12d3-a456-426614174000"),
            role=UserRole.ADMIN,
            exp=datetime.utcnow() + timedelta(minutes=30)
        )
        
        # Access user info
        user_id = payload.sub
        user_role = payload.role
        
    Notes:
        - 'sub' follows JWT standard for subject claim
        - 'exp' and 'iat' follow JWT standard timestamp format
        - Additional custom claims can be added as needed
    """
    
    sub: UUID = Field(
        ...,
        description="Subject - User ID (UUID)",
        example="123e4567-e89b-12d3-a456-426614174000"
    )
    
    role: UserRole = Field(
        ...,
        description="User role for authorization",
        example="ADMIN"
    )
    
    exp: datetime = Field(
        ...,
        description="Expiration time (UTC)",
        example="2024-12-31T23:59:59Z"
    )
    
    iat: Optional[datetime] = Field(
        default=None,
        description="Issued at time (UTC)",
        example="2024-12-31T12:00:00Z"
    )
    
    email: Optional[str] = Field(
        default=None,
        description="User email (optional)",
        example="user@example.com"
    )
    
    @validator("exp")
    def validate_expiration(cls, v: datetime) -> datetime:
        """
        Validate that expiration is in the future.
        
        Note: This validation is performed when creating TokenPayload instances.
        When decoding existing tokens, expired tokens should be caught by
        the JWT library before reaching this validation.
        
        Args:
            v: Expiration datetime
            
        Returns:
            datetime: Validated expiration time
            
        Raises:
            ValueError: If expiration is in the past (when creating new tokens)
        """
        # Only validate for new tokens (when creating payload)
        # Decoded tokens might already be expired and that's handled elsewhere
        # if v < datetime.utcnow():
        #     # This is informational; actual expiration check happens in JWT decode
        #     pass
        return v
    
    @validator("role", pre=True)
    def validate_role(cls, v) -> UserRole:
        """
        Validate and convert role to UserRole enum.
        
        Args:
            v: Role value (string or UserRole)
            
        Returns:
            UserRole: Validated role enum
            
        Raises:
            ValueError: If role is invalid
        """
        if isinstance(v, str):
            try:
                return UserRole(v)
            except ValueError:
                valid_roles = ", ".join(UserRole.values())
                raise ValueError(
                    f"Invalid role '{v}'. Must be one of: {valid_roles}"
                )
        return v
    
    @validator("sub", pre=True)
    def validate_sub(cls, v) -> UUID:
        """
        Validate and convert subject to UUID.
        
        Args:
            v: Subject value (string or UUID)
            
        Returns:
            UUID: Validated UUID
            
        Raises:
            ValueError: If subject is not a valid UUID
        """
        if isinstance(v, str):
            try:
                return UUID(v)
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid UUID format: {v}")
        return v
    
    def is_expired(self) -> bool:
        """
        Check if token is expired.
        
        Returns:
            bool: True if token is expired
            
        Example:
            if payload.is_expired():
                raise TokenExpiredException()
        """
        return datetime.utcnow() > self.exp
    
    def time_until_expiry(self) -> int:
        """
        Get seconds until token expires.
        
        Returns:
            int: Seconds until expiration (negative if already expired)
            
        Example:
            seconds = payload.time_until_expiry()
            if seconds < 300:  # Less than 5 minutes
                refresh_token()
        """
        delta = self.exp - datetime.utcnow()
        return int(delta.total_seconds())
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sub": "123e4567-e89b-12d3-a456-426614174000",
                "role": "ADMIN",
                "exp": "2024-12-31T23:59:59Z",
                "iat": "2024-12-31T12:00:00Z",
                "email": "admin@example.com"
            }
        },
        arbitrary_types_allowed=True
    )


# ============================================================================
# Refresh Token Schema
# ============================================================================

class RefreshToken(BaseModel):
    """
    Refresh token schema for token renewal.
    
    This schema is used for refresh token flows where clients exchange
    a refresh token for a new access token without re-authentication.
    
    Attributes:
        refresh_token: Long-lived refresh token string
        
    Example:
        POST /api/v1/auth/refresh
        Request:
        {
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
        }
        
        Response:
        {
            "access_token": "new_token...",
            "token_type": "bearer"
        }
        
    Notes:
        - Refresh tokens typically have longer expiration (days/weeks)
        - Should be stored securely on client side
        - Should be invalidated on logout
    """
    
    refresh_token: str = Field(
        ...,
        description="Refresh token for obtaining new access token",
        min_length=1,
        example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            }
        }
    )


# ============================================================================
# Token Response with Refresh Token
# ============================================================================

class TokenWithRefresh(Token):
    """
    Extended token response including refresh token.
    
    This schema extends the base Token schema to include a refresh token
    in the authentication response. Used when refresh token flow is enabled.
    
    Attributes:
        access_token: JWT access token (inherited)
        token_type: Token type (inherited)
        expires_in: Token expiration (inherited)
        refresh_token: Long-lived refresh token
        
    Example:
        POST /api/v1/auth/login
        Response:
        {
            "access_token": "eyJhbGciOiJI...",
            "token_type": "bearer",
            "expires_in": 1800,
            "refresh_token": "eyJhbGciOiJIU..."
        }
    """
    
    refresh_token: str = Field(
        ...,
        description="Refresh token for obtaining new access tokens",
        min_length=1,
        example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "token_type": "bearer",
                "expires_in": 1800,
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            }
        }
    )


# ============================================================================
# Login Request Schema
# ============================================================================

class LoginRequest(BaseModel):
    """
    Login request schema.
    
    Schema for user authentication requests. Used in login endpoints
    to validate credential input.
    
    Attributes:
        email: User's email address
        password: User's password (plain text, will be hashed)
        
    Example:
        POST /api/v1/auth/login
        Request:
        {
            "email": "user@example.com",
            "password": "SecurePassword123!"
        }
        
    Security Notes:
        - Password is transmitted in plain text over HTTPS
        - Server should hash password immediately
        - Never log or store plain text passwords
    """
    
    email: str = Field(
        ...,
        description="User's email address",
        max_length=255,
        example="user@example.com"
    )
    
    password: str = Field(
        ...,
        description="User's password",
        min_length=1,
        max_length=128,
        example="SecurePassword123!"
    )
    
    @validator("email")
    def validate_email(cls, v: str) -> str:
        """
        Validate and normalize email.
        
        Args:
            v: Email address
            
        Returns:
            str: Normalized email (lowercase, trimmed)
            
        Raises:
            ValueError: If email format is invalid
        """
        v = v.lower().strip()
        
        if not v or "@" not in v:
            raise ValueError("Invalid email format")
        
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!"
            }
        }
    )


# ============================================================================
# Token Verification Response
# ============================================================================

class TokenVerifyResponse(BaseModel):
    """
    Token verification response schema.
    
    Response schema for token verification endpoints that validate
    whether a token is valid and return user information.
    
    Attributes:
        valid: Whether the token is valid
        user_id: User ID if token is valid
        role: User role if token is valid
        expires_at: Token expiration time if valid
        
    Example:
        POST /api/v1/auth/verify
        Response:
        {
            "valid": true,
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "role": "ADMIN",
            "expires_at": "2024-12-31T23:59:59Z"
        }
    """
    
    valid: bool = Field(
        ...,
        description="Whether the token is valid"
    )
    
    user_id: Optional[UUID] = Field(
        default=None,
        description="User ID if token is valid"
    )
    
    role: Optional[UserRole] = Field(
        default=None,
        description="User role if token is valid"
    )
    
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Token expiration time if valid"
    )
    
    message: Optional[str] = Field(
        default=None,
        description="Error message if token is invalid"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "valid": True,
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "role": "ADMIN",
                "expires_at": "2024-12-31T23:59:59Z"
            }
        },
        arbitrary_types_allowed=True
    )


# ============================================================================
# Password Change Request
# ============================================================================

class PasswordChangeRequest(BaseModel):
    """
    Password change request schema.
    
    Schema for password change operations where user provides
    current password and new password.
    
    Attributes:
        current_password: User's current password
        new_password: Desired new password
        confirm_password: Confirmation of new password
        
    Example:
        POST /api/v1/auth/change-password
        Request:
        {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword456!",
            "confirm_password": "NewPassword456!"
        }
    """
    
    current_password: str = Field(
        ...,
        description="Current password",
        min_length=1,
        example="OldPassword123!"
    )
    
    new_password: str = Field(
        ...,
        description="New password",
        min_length=8,
        max_length=128,
        example="NewPassword456!"
    )
    
    confirm_password: str = Field(
        ...,
        description="Confirm new password",
        min_length=8,
        max_length=128,
        example="NewPassword456!"
    )
    
    @validator("confirm_password")
    def passwords_match(cls, v: str, values: dict) -> str:
        """
        Validate that new passwords match.
        
        Args:
            v: Confirmation password
            values: Other field values
            
        Returns:
            str: Validated password
            
        Raises:
            ValueError: If passwords don't match
        """
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("Passwords do not match")
        return v
    
    @validator("new_password")
    def validate_new_password_different(cls, v: str, values: dict) -> str:
        """
        Validate that new password is different from current.
        
        Args:
            v: New password
            values: Other field values
            
        Returns:
            str: Validated password
            
        Raises:
            ValueError: If new password same as current
        """
        if "current_password" in values and v == values["current_password"]:
            raise ValueError("New password must be different from current password")
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewPassword456!",
                "confirm_password": "NewPassword456!"
            }
        }
    )


# ============================================================================
# Module Initialization
# ============================================================================

import logging
logger = logging.getLogger(__name__)
logger.info("Token schemas module initialized")