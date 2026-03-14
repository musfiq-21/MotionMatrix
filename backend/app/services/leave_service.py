"""
Leave service layer.

Business logic for leave request management (submit, approve, reject).
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.leave_request import LeaveRequest
from backend.app.schemas.leave import LeaveRequestCreate, LeaveRequestUpdate


class LeaveService:
    def __init__(self, db: Session):
        self.db = db

    def submit_leave_request(self, data: LeaveRequestCreate) -> LeaveRequest:
        total_days = (data.end_date - data.start_date).days + 1
        request = LeaveRequest(
            worker_id=data.worker_id,
            leave_type=data.leave_type,
            start_date=data.start_date,
            end_date=data.end_date,
            total_days=total_days,
            reason=data.reason,
            status="PENDING",
        )
        self.db.add(request)
        self.db.commit()
        self.db.refresh(request)
        return request

    def get_leave_request_by_id(self, leave_id: UUID) -> Optional[LeaveRequest]:
        return self.db.query(LeaveRequest).filter(LeaveRequest.id == leave_id).first()

    def get_leave_requests_by_worker(self, worker_id: UUID) -> List[LeaveRequest]:
        return (
            self.db.query(LeaveRequest)
            .filter(LeaveRequest.worker_id == worker_id)
            .order_by(LeaveRequest.created_at.desc())
            .all()
        )

    def get_pending_leave_requests(self) -> List[LeaveRequest]:
        return (
            self.db.query(LeaveRequest)
            .filter(LeaveRequest.status == "PENDING")
            .order_by(LeaveRequest.created_at.asc())
            .all()
        )

    def review_leave_request(self, leave_id: UUID, data: LeaveRequestUpdate, reviewer_id: UUID) -> Optional[LeaveRequest]:
        request = self.get_leave_request_by_id(leave_id)
        if not request or request.status != "PENDING":
            return None
        request.status = data.status
        request.review_comment = data.review_comment
        request.reviewed_by = reviewer_id
        request.reviewed_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(request)
        return request
