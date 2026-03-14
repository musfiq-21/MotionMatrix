"""
User database model.

This module defines the User model representing employees and administrators
in the employee management system. It includes authentication, authorization,
and user management functionality.

Example:
    from app.models.user import User
    from app.utils.enums import UserRole, UserStatus
    
    user = User(
        email="admin@example.com",
        hashed_password=hash_password("password"),
        full_name="Admin User",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE
    )
    db.add(user)
    db.commit()
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, validates

from backend.app.core.database import Base
from backend.app.utils.enums import UserRole, UserStatus


# ============================================================================
# User Model
# ============================================================================

class User(Base):
    """
    User model representing employees and administrators.
    
    This model stores user authentication and profile information.
    It supports role-based access control and tracks user relationships
    (who created whom).
    
    Attributes:
        id: Unique identifier (UUID)
        email: User's email address (unique, used for login)
        hashed_password: Bcrypt hashed password
        full_name: User's full name
        role: User role for authorization (UserRole enum)
        status: Account status (UserStatus enum)
        phone_number: Optional contact phone number
        is_first_login: Flag indicating if user needs to change password
        created_at: Timestamp of user creation
        updated_at: Timestamp of last update
        created_by_id: ID of user who created this account
        
    Relationships:
        created_by: User who created this account
        created_users: Users created by this user
        attendance_records: User's attendance records
        leave_requests: User's leave requests
        notifications: User's notifications
        
    Example:
        # Create a new user
        user = User(
            email="john.doe@example.com",
            hashed_password=hash_password("SecurePass123!"),
            full_name="John Doe",
            role=UserRole.WORKER,
            status=UserStatus.PENDING_PASSWORD_CHANGE
        )
        
        # Query users
        admin_users = session.query(User).filter(
            User.role == UserRole.ADMIN.value
        ).all()
        
        # Check relationships
        if user.created_by:
            print(f"Created by: {user.created_by.full_name}")
    """
    
    __tablename__ = "users"
    
    # ========================================================================
    # Primary Key
    # ========================================================================
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
        comment="Unique identifier for the user"
    )
    
    # ========================================================================
    # Authentication Fields
    # ========================================================================
    
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address (used for login)"
    )
    
    hashed_password = Column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # ========================================================================
    # Profile Fields
    # ========================================================================
    
    full_name = Column(
        String(255),
        nullable=False,
        index=True,
        comment="User's full name"
    )
    
    phone_number = Column(
        String(20),
        nullable=True,
        comment="User's contact phone number"
    )
    
    # ========================================================================
    # Authorization Fields
    # ========================================================================
    
    role = Column(
        String(50),
        nullable=False,
        default=UserRole.WORKER.value,
        index=True,
        comment="User role for authorization (ADMIN, OWNER, MANAGER, FLOOR_MANAGER, WORKER)"
    )
    
    status = Column(
        String(50),
        nullable=False,
        default=UserStatus.ACTIVE.value,
        index=True,
        comment="Account status (ACTIVE, INACTIVE, PENDING_PASSWORD_CHANGE, SUSPENDED, LOCKED)"
    )
    
    # ========================================================================
    # Security Fields
    # ========================================================================
    
    is_first_login = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Flag indicating if user must change password on first login"
    )
    
    # ========================================================================
    # Audit Fields
    # ========================================================================
    
    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        comment="Timestamp when user was created"
    )
    
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Timestamp when user was last updated"
    )
    
    created_by_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="ID of user who created this account"
    )
    
    # ========================================================================
    # Relationships
    # ========================================================================
    
    # Self-referential relationship: user who created this account
    created_by = relationship(
        "User",
        remote_side=[id],
        foreign_keys=[created_by_id],
        backref="created_users",
        doc="User who created this account"
    )
    
    # One-to-one: Worker profile (if user is a worker)
    worker = relationship("Worker", back_populates="user", uselist=False)
    
    # One-to-many: Attendance records
    # Defined in Attendance model to avoid circular imports
    # attendance_records = relationship("Attendance", back_populates="user")
    
    # One-to-many: Leave requests
    # Defined in LeaveRequest model to avoid circular imports
    # leave_requests = relationship("LeaveRequest", back_populates="user")
    
    # One-to-many: Notifications
    # Defined in Notification model to avoid circular imports
    # notifications = relationship("Notification", back_populates="user")
    
    # ========================================================================
    # Table Configuration
    # ========================================================================
    
    __table_args__ = (
        # Unique constraint on email (explicit for better error messages)
        Index("idx_users_email_unique", "email", unique=True),
        
        # Check constraint for valid email format (basic validation)
        CheckConstraint(
            "email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'",
            name="check_valid_email_format"
        ),
        
        # Check constraint for valid role values
        CheckConstraint(
            f"role IN ('{UserRole.ADMIN.value}', '{UserRole.OWNER.value}', "
            f"'{UserRole.MANAGER.value}', '{UserRole.FLOOR_MANAGER.value}', "
            f"'{UserRole.WORKER.value}')",
            name="check_valid_role"
        ),
        
        # Check constraint for valid status values
        CheckConstraint(
            f"status IN ('{UserStatus.ACTIVE.value}', '{UserStatus.INACTIVE.value}', "
            f"'{UserStatus.PENDING_PASSWORD_CHANGE.value}', '{UserStatus.SUSPENDED.value}', "
            f"'{UserStatus.LOCKED.value}')",
            name="check_valid_status"
        ),
        
        # Check constraint for non-empty full name
        CheckConstraint(
            "LENGTH(TRIM(full_name)) > 0",
            name="check_full_name_not_empty"
        ),
        
        # Index for common queries
        Index("idx_users_role_status", "role", "status"),
        Index("idx_users_created_at", "created_at"),
        
        # Table comment
        {
            "comment": "Users table storing employee and administrator information"
        }
    )
    
    # ========================================================================
    # Validators
    # ========================================================================
    
    @validates("email")
    def validate_email(self, key: str, email: str) -> str:
        """
        Validate email format.
        
        This validator ensures the email is properly formatted before
        saving to the database. It normalizes the email to lowercase.
        
        Args:
            key: Field name (always "email")
            email: Email address to validate
            
        Returns:
            str: Normalized email address (lowercase)
            
        Raises:
            ValueError: If email format is invalid
            
        Example:
            user.email = "John.Doe@Example.com"  # Stored as "john.doe@example.com"
        """
        if not email:
            raise ValueError("Email address is required")
        
        # Normalize to lowercase
        email = email.lower().strip()
        
        # Basic validation (database constraint handles detailed validation)
        if "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError(f"Invalid email format: {email}")
        
        if len(email) > 255:
            raise ValueError("Email address is too long (max 255 characters)")
        
        return email
    
    @validates("role")
    def validate_role(self, key: str, role: str) -> str:
        """
        Validate user role.
        
        Ensures the role is a valid UserRole enum value.
        
        Args:
            key: Field name (always "role")
            role: Role value to validate
            
        Returns:
            str: Validated role value
            
        Raises:
            ValueError: If role is invalid
        """
        if not role:
            raise ValueError("User role is required")
        
        # Accept both enum and string values
        if isinstance(role, UserRole):
            return role.value
        
        if not UserRole.has_value(role):
            valid_roles = ", ".join(UserRole.values())
            raise ValueError(
                f"Invalid role '{role}'. Must be one of: {valid_roles}"
            )
        
        return role
    
    @validates("status")
    def validate_status(self, key: str, status: str) -> str:
        """
        Validate user status.
        
        Ensures the status is a valid UserStatus enum value.
        
        Args:
            key: Field name (always "status")
            status: Status value to validate
            
        Returns:
            str: Validated status value
            
        Raises:
            ValueError: If status is invalid
        """
        if not status:
            raise ValueError("User status is required")
        
        # Accept both enum and string values
        if isinstance(status, UserStatus):
            return status.value
        
        if not UserStatus.has_value(status):
            valid_statuses = ", ".join(UserStatus.values())
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {valid_statuses}"
            )
        
        return status
    
    @validates("full_name")
    def validate_full_name(self, key: str, full_name: str) -> str:
        """
        Validate full name.
        
        Ensures the full name is not empty and properly formatted.
        
        Args:
            key: Field name (always "full_name")
            full_name: Name to validate
            
        Returns:
            str: Validated and normalized name
            
        Raises:
            ValueError: If name is invalid
        """
        if not full_name or not full_name.strip():
            raise ValueError("Full name is required")
        
        # Normalize whitespace
        full_name = " ".join(full_name.split())
        
        if len(full_name) > 255:
            raise ValueError("Full name is too long (max 255 characters)")
        
        return full_name
    
    @validates("phone_number")
    def validate_phone_number(self, key: str, phone_number: Optional[str]) -> Optional[str]:
        """
        Validate phone number format.
        
        Args:
            key: Field name (always "phone_number")
            phone_number: Phone number to validate
            
        Returns:
            Optional[str]: Validated phone number or None
            
        Raises:
            ValueError: If phone number format is invalid
        """
        if not phone_number:
            return None
        
        # Remove whitespace and common separators
        cleaned = "".join(c for c in phone_number if c.isdigit() or c in "+")
        
        if not cleaned:
            return None
        
        if len(cleaned) > 20:
            raise ValueError("Phone number is too long (max 20 characters)")
        
        # Store the cleaned version
        return cleaned
    
    # ========================================================================
    # Instance Methods
    # ========================================================================
    
    def get_role_enum(self) -> UserRole:
        """
        Get role as UserRole enum.
        
        Returns:
            UserRole: User's role as enum
            
        Example:
            if user.get_role_enum() == UserRole.ADMIN:
                grant_admin_access()
        """
        return UserRole(self.role)
    
    def get_status_enum(self) -> UserStatus:
        """
        Get status as UserStatus enum.
        
        Returns:
            UserStatus: User's status as enum
            
        Example:
            if user.get_status_enum() == UserStatus.ACTIVE:
                allow_login()
        """
        return UserStatus(self.status)
    
    def is_active(self) -> bool:
        """
        Check if user account is active.
        
        Returns:
            bool: True if user can access the system
            
        Example:
            if user.is_active():
                generate_token()
        """
        return UserStatus.is_active(self.get_status_enum())
    
    def can_manage_user(self, target_user: 'User') -> bool:
        """
        Check if this user can manage another user.
        
        Uses role hierarchy to determine management permissions.
        
        Args:
            target_user: User to check management permission for
            
        Returns:
            bool: True if this user can manage target user
            
        Example:
            if manager.can_manage_user(employee):
                allow_edit()
        """
        current_role = self.get_role_enum()
        target_role = target_user.get_role_enum()
        return UserRole.can_manage(current_role, target_role)
    
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.get_role_enum() == UserRole.ADMIN
    
    def is_owner(self) -> bool:
        """Check if user has owner role."""
        return self.get_role_enum() == UserRole.OWNER
    
    def is_manager(self) -> bool:
        """Check if user has manager role."""
        return self.get_role_enum() in [UserRole.ADMIN, UserRole.OWNER, UserRole.MANAGER]
    
    def needs_password_change(self) -> bool:
        """
        Check if user needs to change password.
        
        Returns:
            bool: True if password change is required
        """
        return (
            self.is_first_login or 
            self.get_status_enum() == UserStatus.PENDING_PASSWORD_CHANGE
        )
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary.
        
        Args:
            include_sensitive: If True, include sensitive fields (default: False)
            
        Returns:
            dict: User data as dictionary
            
        Example:
            user_data = user.to_dict()
            # Returns: {
            #     "id": "123e4567-e89b-12d3-a456-426614174000",
            #     "email": "user@example.com",
            #     "full_name": "John Doe",
            #     "role": "WORKER",
            #     ...
            # }
        """
        data = {
            "id": str(self.id),
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "status": self.status,
            "phone_number": self.phone_number,
            "is_first_login": self.is_first_login,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by_id": str(self.created_by_id) if self.created_by_id else None,
        }
        
        if include_sensitive:
            data["hashed_password"] = self.hashed_password
        
        return data
    
    # ========================================================================
    # Magic Methods
    # ========================================================================
    
    def __repr__(self) -> str:
        """Developer-friendly string representation."""
        return (
            f"<User(id={self.id}, email='{self.email}', "
            f"full_name='{self.full_name}', role='{self.role}', "
            f"status='{self.status}')>"
        )
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"{self.full_name} ({self.email})"


# ============================================================================
# Model Indexes (Additional indexes beyond table_args)
# ============================================================================

# Composite index for efficient queries by role and status
Index(
    "idx_users_role_status_created",
    User.role,
    User.status,
    User.created_at.desc(),
    postgresql_using="btree"
)

# Index for searching by name
Index(
    "idx_users_full_name_trgm",
    User.full_name,
    postgresql_using="gin",
    postgresql_ops={"full_name": "gin_trgm_ops"}
)


# ============================================================================
# Model Events (SQLAlchemy event listeners)
# ============================================================================

from sqlalchemy import event

@event.listens_for(User, "before_insert")
def receive_before_insert(mapper, connection, target):
    """
    Event handler called before inserting a new user.
    
    This ensures proper initialization of timestamps and default values.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: User instance being inserted
    """
    # Ensure timestamps are set
    if not target.created_at:
        target.created_at = datetime.utcnow()
    if not target.updated_at:
        target.updated_at = datetime.utcnow()


@event.listens_for(User, "before_update")
def receive_before_update(mapper, connection, target):
    """
    Event handler called before updating a user.
    
    This ensures the updated_at timestamp is always current.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: User instance being updated
    """
    # Always update the timestamp
    target.updated_at = datetime.utcnow()


# ============================================================================
# Module Initialization
# ============================================================================

import logging
logger = logging.getLogger(__name__)
logger.info("User model initialized")