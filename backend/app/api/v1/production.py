"""
Production management API endpoints.

CRUD operations for production records.
"""

from datetime import date
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User
from backend.app.schemas.production import ProductionCreate, ProductionResponse, ProductionUpdate
from backend.app.services.production_service import ProductionService

router = APIRouter(prefix="/production", tags=["Production"])


@router.get("/worker/{worker_id}", response_model=List[ProductionResponse])
def get_worker_production(
    worker_id: UUID,
    target_date: Optional[date] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get production records for a specific worker."""
    service = ProductionService(db)
    return service.get_production_by_worker(worker_id, target_date)


@router.post("/", response_model=ProductionResponse, status_code=status.HTTP_201_CREATED)
def create_production(
    data: ProductionCreate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """Record production data for a worker."""
    service = ProductionService(db)
    return service.create_production(data, recorded_by=current_user.id)


@router.put("/{production_id}", response_model=ProductionResponse)
def update_production(
    production_id: UUID,
    data: ProductionUpdate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """Update a production record."""
    service = ProductionService(db)
    record = service.update_production(production_id, data)
    if not record:
        raise HTTPException(status_code=404, detail="Production record not found")
    return record


@router.delete("/{production_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_production(
    production_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete a production record."""
    service = ProductionService(db)
    if not service.delete_production(production_id):
        raise HTTPException(status_code=404, detail="Production record not found")
