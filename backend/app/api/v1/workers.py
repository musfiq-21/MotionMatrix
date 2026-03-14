"""
Worker management API endpoints.

CRUD operations for workers.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User
from backend.app.schemas.worker import WorkerCreate, WorkerResponse, WorkerUpdate
from backend.app.services.worker_service import WorkerService

router = APIRouter(prefix="/workers", tags=["Workers"])


@router.get("/", response_model=List[WorkerResponse])
def list_workers(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """List all workers with pagination."""
    service = WorkerService(db)
    return service.get_all_workers(skip=skip, limit=limit)


@router.get("/{worker_id}", response_model=WorkerResponse)
def get_worker(
    worker_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific worker by ID."""
    service = WorkerService(db)
    worker = service.get_worker_by_id(worker_id)
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found")
    return worker


@router.post("/", response_model=WorkerResponse, status_code=status.HTTP_201_CREATED)
def create_worker(
    data: WorkerCreate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Create a new worker record."""
    service = WorkerService(db)
    return service.create_worker(data)


@router.put("/{worker_id}", response_model=WorkerResponse)
def update_worker(
    worker_id: UUID,
    data: WorkerUpdate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Update worker information."""
    service = WorkerService(db)
    worker = service.update_worker(worker_id, data)
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found")
    return worker


@router.delete("/{worker_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_worker(
    worker_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete a worker record."""
    service = WorkerService(db)
    if not service.delete_worker(worker_id):
        raise HTTPException(status_code=404, detail="Worker not found")
