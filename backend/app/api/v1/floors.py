"""
Floor management API endpoints.

CRUD operations for factory floors.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User
from backend.app.schemas.floor import FloorCreate, FloorResponse, FloorUpdate
from backend.app.services.floor_service import FloorService

router = APIRouter(prefix="/floors", tags=["Floors"])


@router.get("/", response_model=List[FloorResponse])
def list_floors(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all factory floors."""
    service = FloorService(db)
    return service.get_all_floors()


@router.get("/{floor_id}", response_model=FloorResponse)
def get_floor(
    floor_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific floor."""
    service = FloorService(db)
    floor = service.get_floor_by_id(floor_id)
    if not floor:
        raise HTTPException(status_code=404, detail="Floor not found")
    return floor


@router.post("/", response_model=FloorResponse, status_code=status.HTTP_201_CREATED)
def create_floor(
    data: FloorCreate,
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Create a new floor."""
    service = FloorService(db)
    return service.create_floor(data)


@router.put("/{floor_id}", response_model=FloorResponse)
def update_floor(
    floor_id: UUID,
    data: FloorUpdate,
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Update floor information."""
    service = FloorService(db)
    floor = service.update_floor(floor_id, data)
    if not floor:
        raise HTTPException(status_code=404, detail="Floor not found")
    return floor


@router.delete("/{floor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_floor(
    floor_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete a floor."""
    service = FloorService(db)
    if not service.delete_floor(floor_id):
        raise HTTPException(status_code=404, detail="Floor not found")
