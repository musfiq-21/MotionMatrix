"""
User management API endpoints.

GET    /users          - List all users (Admin)
GET    /users/{id}     - Get user by ID
POST   /users          - Create user (Admin)
PUT    /users/{id}     - Update user
DELETE /users/{id}     - Delete user (Admin)
PATCH  /users/{id}/activate   - Activate user (Admin)
PATCH  /users/{id}/deactivate - Deactivate user (Admin)
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """List all users with pagination."""
    # TODO: Implement using user_service
    pass


@router.get("/{user_id}")
def get_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific user by ID."""
    # TODO: Implement
    pass


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Create a new user (Admin only)."""
    # TODO: Implement using user_service
    pass


@router.put("/{user_id}")
def update_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update user information."""
    # TODO: Implement
    pass


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete a user (Admin only)."""
    # TODO: Implement
    pass


@router.patch("/{user_id}/activate")
def activate_user(
    user_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Activate a deactivated user account."""
    # TODO: Implement
    pass


@router.patch("/{user_id}/deactivate")
def deactivate_user(
    user_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Deactivate a user account."""
    # TODO: Implement
    pass
