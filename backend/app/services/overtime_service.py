"""
Overtime service layer.

Business logic for overtime tracking.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.overtime import Overtime
from backend.app.schemas.overtime import OvertimeCreate, OvertimeUpdate


class OvertimeService:
    def __init__(self, db: Session):
        self.db = db

    def create_overtime(self, data: OvertimeCreate) -> Overtime:
        record = Overtime(
            worker_id=data.worker_id,
            date=data.date,
            hours=data.hours,
            reason=data.reason,
            status="PENDING",
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def get_overtime_by_id(self, overtime_id: UUID) -> Optional[Overtime]:
        return self.db.query(Overtime).filter(Overtime.id == overtime_id).first()

    def get_overtime_by_worker(self, worker_id: UUID) -> List[Overtime]:
        return (
            self.db.query(Overtime)
            .filter(Overtime.worker_id == worker_id)
            .order_by(Overtime.date.desc())
            .all()
        )

    def approve_overtime(self, overtime_id: UUID, approved_by: UUID) -> Optional[Overtime]:
        record = self.get_overtime_by_id(overtime_id)
        if not record or record.status != "PENDING":
            return None
        record.status = "APPROVED"
        record.approved_by = approved_by
        self.db.commit()
        self.db.refresh(record)
        return record

    def reject_overtime(self, overtime_id: UUID) -> Optional[Overtime]:
        record = self.get_overtime_by_id(overtime_id)
        if not record or record.status != "PENDING":
            return None
        record.status = "REJECTED"
        self.db.commit()
        self.db.refresh(record)
        return record
