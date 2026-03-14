"""
Leave request API endpoints.

Submit, review, and manage leave requests.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User
from backend.app.schemas.leave import LeaveRequestCreate, LeaveRequestResponse, LeaveRequestUpdate
from backend.app.services.leave_service import LeaveService

router = APIRouter(prefix="/leave", tags=["Leave"])


@router.get("/pending", response_model=List[LeaveRequestResponse])
def list_pending_requests(
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """List all pending leave requests."""
    service = LeaveService(db)
    return service.get_pending_leave_requests()


@router.get("/worker/{worker_id}", response_model=List[LeaveRequestResponse])
def get_worker_leave_requests(
    worker_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get leave requests for a specific worker."""
    service = LeaveService(db)
    return service.get_leave_requests_by_worker(worker_id)


@router.post("/", response_model=LeaveRequestResponse, status_code=status.HTTP_201_CREATED)
def submit_leave_request(
    data: LeaveRequestCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Submit a new leave request."""
    service = LeaveService(db)
    return service.submit_leave_request(data)


@router.patch("/{leave_id}/review", response_model=LeaveRequestResponse)
def review_leave_request(
    leave_id: UUID,
    data: LeaveRequestUpdate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """Approve or reject a leave request."""
    service = LeaveService(db)
    request = service.review_leave_request(leave_id, data, reviewer_id=current_user.id)
    if not request:
        raise HTTPException(status_code=404, detail="Leave request not found or already reviewed")
    return request
