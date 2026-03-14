"""
Attendance management API endpoints.

CRUD operations for attendance records.
"""

from datetime import date
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user, require_role
from backend.app.models.user import User
from backend.app.schemas.attendance import AttendanceCreate, AttendanceResponse, AttendanceUpdate
from backend.app.services.attendance_service import AttendanceService

router = APIRouter(prefix="/attendance", tags=["Attendance"])


@router.get("/", response_model=List[AttendanceResponse])
def list_attendance(
    target_date: Optional[date] = None,
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """List attendance records, optionally filtered by date."""
    service = AttendanceService(db)
    if target_date:
        return service.get_attendance_by_date(target_date)
    return service.get_attendance_by_date(date.today())


@router.get("/worker/{worker_id}", response_model=List[AttendanceResponse])
def get_worker_attendance(
    worker_id: UUID,
    target_date: Optional[date] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get attendance records for a specific worker."""
    service = AttendanceService(db)
    return service.get_attendance_by_worker(worker_id, target_date)


@router.post("/", response_model=AttendanceResponse, status_code=status.HTTP_201_CREATED)
def create_attendance(
    data: AttendanceCreate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """Record attendance for a worker (manual entry by floor manager)."""
    service = AttendanceService(db)
    return service.create_attendance(data, recorded_by=current_user.id)


@router.put("/{attendance_id}", response_model=AttendanceResponse)
def update_attendance(
    attendance_id: UUID,
    data: AttendanceUpdate,
    current_user: User = Depends(require_role(["ADMIN", "MANAGER", "FLOOR_MANAGER"])),
    db: Session = Depends(get_db),
):
    """Update an attendance record."""
    service = AttendanceService(db)
    record = service.update_attendance(attendance_id, data)
    if not record:
        raise HTTPException(status_code=404, detail="Attendance record not found")
    return record


@router.delete("/{attendance_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_attendance(
    attendance_id: UUID,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete an attendance record."""
    service = AttendanceService(db)
    if not service.delete_attendance(attendance_id):
        raise HTTPException(status_code=404, detail="Attendance record not found")
