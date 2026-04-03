"""
Pydantic schemas for User operations.

This module defines data transfer objects (DTOs) for user-related API operations.
Schemas handle validation, serialization, and provide clear API contracts.

Example:
    from app.schemas.user import UserCreate, UserResponse
    
    # Validate user creation data
    user_data = UserCreate(
        email="user@example.com",
        full_name="John Doe",
        password="SecurePass123!",
        confirm_password="SecurePass123!"
    )
    
    # Return user data in response
    user_response = UserResponse.from_orm(user)
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator, ConfigDict
from email_validator import validate_email, EmailNotValidError

from backend.app.utils.enums import UserRole, UserStatus
from backend.app.core.security import validate_password_strength


# ============================================================================
# Base User Schema
# ============================================================================

class UserBase(BaseModel):
    """
    Base user schema with common fields.
    
    This schema contains fields that are common across different user operations.
    It serves as a parent class for other user schemas.
    
    Attributes:
        email: User's email address (unique identifier)
        full_name: User's full name
        phone_number: Optional contact phone number
        
    Example:
        # Not used directly, but inherited by other schemas
        class UserCreate(UserBase):
            password: str
    """
    
    email: EmailStr = Field(
        ...,
        description="User's email address",
        max_length=255,
        example="john.doe@example.com"
    )
    
    full_name: str = Field(
        ...,
        description="User's full name",
        min_length=1,
        max_length=255,
        example="John Doe"
    )
    
    phone_number: Optional[str] = Field(
        default=None,
        description="User's contact phone number",
        max_length=20,
        example="+1234567890"
    )
    
    @validator("email")
    def validate_email_format(cls, v: str) -> str:
        """
        Validate email format using email-validator library.
        
        Provides more comprehensive email validation than Pydantic's default.
        
        Args:
            v: Email address to validate
            
        Returns:
            str: Normalized email (lowercase)
            
        Raises:
            ValueError: If email format is invalid
        """
        try:
            # Validate and normalize email
            validated = validate_email(v, check_deliverability=False)
            return validated.email.lower()
        except EmailNotValidError as e:
            raise ValueError(f"Invalid email format: {str(e)}")
    
    @validator("full_name")
    def validate_full_name(cls, v: str) -> str:
        """
        Validate and normalize full name.
        
        Args:
            v: Full name to validate
            
        Returns:
            str: Normalized name (trimmed whitespace)
            
        Raises:
            ValueError: If name is empty or contains only whitespace
        """
        v = v.strip()
        if not v:
            raise ValueError("Full name cannot be empty")
        
        # Normalize multiple spaces to single space
        v = " ".join(v.split())
        
        if len(v) < 2:
            raise ValueError("Full name must be at least 2 characters")
        
        return v
    
    @validator("phone_number")
    def validate_phone_number(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate phone number format.
        
        Allows international formats with + prefix and digits.
        
        Args:
            v: Phone number to validate
            
        Returns:
            Optional[str]: Cleaned phone number or None
            
        Raises:
            ValueError: If phone format is invalid
        """
        if not v:
            return None
        
        # Remove common separators
        cleaned = "".join(c for c in v if c.isdigit() or c == "+")
        
        if not cleaned:
            return None
        
        # Must start with + or digit
        if not (cleaned[0] == "+" or cleaned[0].isdigit()):
            raise ValueError("Phone number must start with + or digit")
        
        # Must have at least 10 digits (excluding +)
        digits_only = cleaned.replace("+", "")
        if len(digits_only) < 10:
            raise ValueError("Phone number must have at least 10 digits")
        
        if len(cleaned) > 20:
            raise ValueError("Phone number is too long (max 20 characters)")
        
        return cleaned
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "phone_number": "+1234567890"
            }
        }
    )


# ============================================================================
# User Creation Schema
# ============================================================================

class UserCreate(UserBase):
    """
    Schema for creating a new user.
    
    Used in registration and admin user creation endpoints.
    Includes password fields and optional role assignment.
    
    Attributes:
        email: User's email (inherited)
        full_name: User's full name (inherited)
        phone_number: Optional phone (inherited)
        password: User's password (plain text, will be hashed)
        confirm_password: Password confirmation
        role: User role (optional, defaults to WORKER)
        
    Example:
        POST /api/v1/users
        {
            "email": "new.user@example.com",
            "full_name": "New User",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
            "role": "WORKER"
        }
    """
    
    password: str = Field(
        ...,
        description="User's password",
        min_length=8,
        max_length=128,
        example="SecurePassword123!"
    )
    
    confirm_password: str = Field(
        ...,
        description="Password confirmation",
        min_length=8,
        max_length=128,
        example="SecurePassword123!"
    )
    
    role: UserRole = Field(
        default=UserRole.WORKER,
        description="User role (ADMIN, OWNER, MANAGER, FLOOR_MANAGER, WORKER)"
    )
    
    @validator("password")
    def validate_password_strength(cls, v: str) -> str:
        """
        Validate password meets security requirements.
        
        Uses the security module's password strength validator.
        
        Args:
            v: Password to validate
            
        Returns:
            str: Validated password
            
        Raises:
            ValueError: If password doesn't meet requirements
        """
        is_valid, errors = validate_password_strength(v)
        if not is_valid:
            # Combine all error messages
            error_msg = "; ".join(errors)
            raise ValueError(f"Password validation failed: {error_msg}")
        return v
    
    @validator("confirm_password")
    def validate_passwords_match(cls, v: str, values: dict) -> str:
        """
        Validate that password and confirm_password match.
        
        Args:
            v: Confirm password value
            values: Other field values
            
        Returns:
            str: Validated confirm password
            
        Raises:
            ValueError: If passwords don't match
        """
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "new.user@example.com",
                "full_name": "New User",
                "phone_number": "+1234567890",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!",
                "role": "WORKER"
            }
        }
    )


# ============================================================================
# User Update Schema
# ============================================================================

class UserUpdate(BaseModel):
    """
    Schema for updating user information.
    
    All fields are optional to support partial updates.
    Role and status are excluded - use dedicated endpoints for those.
    
    Attributes:
        email: New email address (optional)
        full_name: New full name (optional)
        phone_number: New phone number (optional)
        
    Example:
        PATCH /api/v1/users/{user_id}
        {
            "full_name": "John Smith",
            "phone_number": "+9876543210"
        }
        
    Notes:
        - At least one field must be provided
        - Email uniqueness is checked at the database level
        - Role/status changes require separate endpoints with proper authorization
    """
    
    email: Optional[EmailStr] = Field(
        default=None,
        description="New email address",
        max_length=255,
        example="updated.email@example.com"
    )
    
    full_name: Optional[str] = Field(
        default=None,
        description="New full name",
        min_length=1,
        max_length=255,
        example="John Smith"
    )
    
    phone_number: Optional[str] = Field(
        default=None,
        description="New phone number",
        max_length=20,
        example="+9876543210"
    )
    
    @validator("email")
    def validate_email_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate email format if provided."""
        if v is None:
            return None
        
        try:
            validated = validate_email(v, check_deliverability=False)
            return validated.email.lower()
        except EmailNotValidError as e:
            raise ValueError(f"Invalid email format: {str(e)}")
    
    @validator("full_name")
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate full name if provided."""
        if v is None:
            return None
        
        v = v.strip()
        if not v:
            raise ValueError("Full name cannot be empty")
        
        v = " ".join(v.split())
        
        if len(v) < 2:
            raise ValueError("Full name must be at least 2 characters")
        
        return v
    
    @validator("phone_number")
    def validate_phone_number(cls, v: Optional[str]) -> Optional[str]:
        """Validate phone number if provided."""
        if v is None:
            return None
        
        cleaned = "".join(c for c in v if c.isdigit() or c == "+")
        
        if not cleaned:
            return None
        
        if not (cleaned[0] == "+" or cleaned[0].isdigit()):
            raise ValueError("Phone number must start with + or digit")
        
        digits_only = cleaned.replace("+", "")
        if len(digits_only) < 10:
            raise ValueError("Phone number must have at least 10 digits")
        
        if len(cleaned) > 20:
            raise ValueError("Phone number is too long")
        
        return cleaned
    
    @validator("phone_number", "email", "full_name")
    def check_at_least_one_field(cls, v, values):
        """Ensure at least one field is being updated."""
        # This validator runs for each field, so we just pass through
        # The actual check happens in the endpoint
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "full_name": "John Smith",
                "phone_number": "+9876543210"
            }
        }
    )


# ============================================================================
# User Response Schema
# ============================================================================

class UserResponse(BaseModel):
    """
    Schema for user data in API responses.
    
    Excludes sensitive information (password) and includes metadata.
    Used when returning user information to clients.
    
    Attributes:
        id: User's unique identifier
        email: User's email address
        full_name: User's full name
        phone_number: User's phone number (if any)
        role: User's role
        status: User's account status
        is_first_login: Whether user needs to change password
        created_at: When user was created
        updated_at: When user was last updated
        created_by_id: ID of user who created this account
        
    Example:
        GET /api/v1/users/{user_id}
        Response:
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "user@example.com",
            "full_name": "John Doe",
            "role": "WORKER",
            "status": "ACTIVE",
            "created_at": "2024-01-15T10:30:00Z"
        }
    """
    
    id: UUID = Field(
        ...,
        description="User's unique identifier"
    )
    
    email: str = Field(
        ...,
        description="User's email address"
    )
    
    full_name: str = Field(
        ...,
        description="User's full name"
    )
    
    phone_number: Optional[str] = Field(
        default=None,
        description="User's phone number"
    )
    
    role: UserRole = Field(
        ...,
        description="User's role"
    )
    
    status: UserStatus = Field(
        ...,
        description="User's account status"
    )
    
    is_first_login: bool = Field(
        ...,
        description="Whether user needs to change password on first login"
    )
    
    created_at: datetime = Field(
        ...,
        description="When user was created"
    )
    
    updated_at: datetime = Field(
        ...,
        description="When user was last updated"
    )
    
    created_by_id: Optional[UUID] = Field(
        default=None,
        description="ID of user who created this account"
    )
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "phone_number": "+1234567890",
                "role": "WORKER",
                "status": "ACTIVE",
                "is_first_login": False,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
                "created_by_id": "456e7890-e89b-12d3-a456-426614174000"
            }
        }
    )


# ============================================================================
# User Login Schema
# ============================================================================

class UserLogin(BaseModel):
    """
    Schema for user login credentials.
    
    Simple schema for authentication endpoints.
    
    Attributes:
        email: User's email address
        password: User's password
        
    Example:
        POST /api/v1/auth/login
        {
            "email": "user@example.com",
            "password": "SecurePassword123!"
        }
    """
    
    email: EmailStr = Field(
        ...,
        description="User's email address",
        example="user@example.com"
    )
    
    password: str = Field(
        ...,
        description="User's password",
        min_length=1,
        example="SecurePassword123!"
    )
    
    @validator("email")
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower().strip()
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!"
            }
        }
    )


# ============================================================================
# Password Change Schema
# ============================================================================

class PasswordChange(BaseModel):
    """
    Schema for user-initiated password change.
    
    Requires current password for security verification.
    Used when a logged-in user wants to change their password.
    
    Attributes:
        current_password: User's current password
        new_password: Desired new password
        confirm_password: Confirmation of new password
        
    Example:
        POST /api/v1/users/me/change-password
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
    
    @validator("new_password")
    def validate_new_password_strength(cls, v: str) -> str:
        """Validate new password meets security requirements."""
        is_valid, errors = validate_password_strength(v)
        if not is_valid:
            error_msg = "; ".join(errors)
            raise ValueError(f"Password validation failed: {error_msg}")
        return v
    
    @validator("new_password")
    def validate_new_different_from_current(cls, v: str, values: dict) -> str:
        """Validate that new password is different from current."""
        if "current_password" in values and v == values["current_password"]:
            raise ValueError("New password must be different from current password")
        return v
    
    @validator("confirm_password")
    def validate_passwords_match(cls, v: str, values: dict) -> str:
        """Validate that new passwords match."""
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("Passwords do not match")
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
# Password Reset Schema (Admin)
# ============================================================================

class PasswordReset(BaseModel):
    """
    Schema for admin-initiated password reset.
    
    Used by administrators to reset a user's password without
    knowing their current password. Typically generates a temporary
    password or allows setting a new one.
    
    Attributes:
        new_password: New password to set
        force_change: Whether to force user to change password on next login
        
    Example:
        POST /api/v1/users/{user_id}/reset-password
        {
            "new_password": "TempPassword123!",
            "force_change": true
        }
        
    Notes:
        - Requires admin privileges
        - Should mark user for password change on next login
        - Consider sending notification to user
    """
    
    new_password: str = Field(
        ...,
        description="New password to set",
        min_length=8,
        max_length=128,
        example="TempPassword123!"
    )
    
    force_change: bool = Field(
        default=True,
        description="Force user to change password on next login"
    )
    
    @validator("new_password")
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        is_valid, errors = validate_password_strength(v)
        if not is_valid:
            error_msg = "; ".join(errors)
            raise ValueError(f"Password validation failed: {error_msg}")
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "new_password": "TempPassword123!",
                "force_change": True
            }
        }
    )


# ============================================================================
# User List Response Schema
# ============================================================================

class UserListResponse(BaseModel):
    """
    Schema for paginated user list responses.
    
    Used when returning multiple users with pagination metadata.
    
    Attributes:
        users: List of user objects
        total: Total number of users
        page: Current page number
        page_size: Number of users per page
        pages: Total number of pages
        
    Example:
        GET /api/v1/users?page=1&page_size=10
        Response:
        {
            "users": [...],
            "total": 45,
            "page": 1,
            "page_size": 10,
            "pages": 5
        }
    """
    
    users: list[UserResponse] = Field(
        ...,
        description="List of users"
    )
    
    total: int = Field(
        ...,
        description="Total number of users",
        ge=0
    )
    
    page: int = Field(
        ...,
        description="Current page number",
        ge=1
    )
    
    page_size: int = Field(
        ...,
        description="Number of users per page",
        ge=1,
        le=100
    )
    
    pages: int = Field(
        ...,
        description="Total number of pages",
        ge=0
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "users": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426614174000",
                        "email": "user1@example.com",
                        "full_name": "User One",
                        "role": "WORKER",
                        "status": "ACTIVE",
                        "is_first_login": False,
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-15T10:30:00Z",
                        "created_by_id": None
                    }
                ],
                "total": 45,
                "page": 1,
                "page_size": 10,
                "pages": 5
            }
        }
    )


# ============================================================================
# User Status Update Schema
# ============================================================================

class UserStatusUpdate(BaseModel):
    """
    Schema for updating user status.
    
    Separate endpoint for status changes to enforce proper authorization.
    
    Attributes:
        status: New status to set
        
    Example:
        PATCH /api/v1/users/{user_id}/status
        {
            "status": "INACTIVE"
        }
    """
    
    status: UserStatus = Field(
        ...,
        description="New user status"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "INACTIVE"
            }
        }
    )


# ============================================================================
# User Role Update Schema
# ============================================================================

class UserRoleUpdate(BaseModel):
    """
    Schema for updating user role.
    
    Separate endpoint for role changes to enforce proper authorization.
    Only admins can change roles.
    
    Attributes:
        role: New role to assign
        
    Example:
        PATCH /api/v1/users/{user_id}/role
        {
            "role": "MANAGER"
        }
    """
    
    role: UserRole = Field(
        ...,
        description="New user role"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "role": "MANAGER"
            }
        }
    )


# ============================================================================
# Module Initialization
# ============================================================================

import logging
logger = logging.getLogger(__name__)
logger.info("User schemas module initialized")