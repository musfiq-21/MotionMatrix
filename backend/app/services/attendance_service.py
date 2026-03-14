"""
Attendance service layer.

Business logic for attendance tracking and management.
"""

from datetime import date
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.attendance import Attendance
from backend.app.schemas.attendance import AttendanceCreate, AttendanceUpdate


class AttendanceService:
    def __init__(self, db: Session):
        self.db = db

    def create_attendance(self, data: AttendanceCreate, recorded_by: UUID) -> Attendance:
        record = Attendance(
            worker_id=data.worker_id,
            date=data.date,
            clock_in=data.clock_in,
            clock_out=data.clock_out,
            status=data.status,
            remarks=data.remarks,
            recorded_by=recorded_by,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def get_attendance_by_id(self, attendance_id: UUID) -> Optional[Attendance]:
        return self.db.query(Attendance).filter(Attendance.id == attendance_id).first()

    def get_attendance_by_worker(self, worker_id: UUID, target_date: Optional[date] = None) -> List[Attendance]:
        query = self.db.query(Attendance).filter(Attendance.worker_id == worker_id)
        if target_date:
            query = query.filter(Attendance.date == target_date)
        return query.order_by(Attendance.date.desc()).all()

    def get_attendance_by_date(self, target_date: date) -> List[Attendance]:
        return self.db.query(Attendance).filter(Attendance.date == target_date).all()

    def update_attendance(self, attendance_id: UUID, data: AttendanceUpdate) -> Optional[Attendance]:
        record = self.get_attendance_by_id(attendance_id)
        if not record:
            return None
        for field, value in data.dict(exclude_unset=True).items():
            setattr(record, field, value)
        self.db.commit()
        self.db.refresh(record)
        return record

    def delete_attendance(self, attendance_id: UUID) -> bool:
        record = self.get_attendance_by_id(attendance_id)
        if not record:
            return False
        self.db.delete(record)
        self.db.commit()
        return True
