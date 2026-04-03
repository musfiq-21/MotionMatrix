"""
Report service layer.

Business logic for generating reports (attendance, production, leave).
Supports JSON data output and CSV export using Python stdlib only.
"""

import csv
import io
from datetime import date
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.attendance import Attendance
from backend.app.models.production import Production
from backend.app.models.leave_request import LeaveRequest
from backend.app.models.worker import Worker


class ReportService:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Data generators
    # ------------------------------------------------------------------

    def generate_attendance_report(
        self, start_date: date, end_date: date, floor_id: Optional[UUID] = None
    ) -> List[Dict[str, Any]]:
        """Generate attendance report for a date range, optionally filtered by floor."""
        query = (
            self.db.query(Attendance, Worker)
            .join(Worker, Worker.id == Attendance.worker_id)
            .filter(Attendance.date >= start_date, Attendance.date <= end_date)
        )
        if floor_id:
            query = query.filter(Worker.floor_id == floor_id)

        rows = query.order_by(Attendance.date.asc()).all()

        result = []
        for attendance, worker in rows:
            result.append(
                {
                    "id": str(attendance.id),
                    "worker_id": str(worker.id),
                    "employee_id": worker.employee_id,
                    "date": attendance.date.isoformat(),
                    "clock_in": str(attendance.clock_in) if attendance.clock_in else None,
                    "clock_out": str(attendance.clock_out) if attendance.clock_out else None,
                    "status": attendance.status,
                    "remarks": attendance.remarks,
                    "recorded_by": str(attendance.recorded_by) if attendance.recorded_by else None,
                }
            )
        return result

    def generate_production_report(
        self, start_date: date, end_date: date, worker_id: Optional[UUID] = None
    ) -> List[Dict[str, Any]]:
        """Generate production report for a date range, optionally filtered by worker."""
        query = (
            self.db.query(Production, Worker)
            .join(Worker, Worker.id == Production.worker_id)
            .filter(Production.date >= start_date, Production.date <= end_date)
        )
        if worker_id:
            query = query.filter(Production.worker_id == worker_id)

        rows = query.order_by(Production.date.asc()).all()

        result = []
        for production, worker in rows:
            result.append(
                {
                    "id": str(production.id),
                    "worker_id": str(worker.id),
                    "employee_id": worker.employee_id,
                    "date": production.date.isoformat(),
                    "target_quantity": production.target_quantity,
                    "achieved_quantity": production.achieved_quantity,
                    "defect_quantity": production.defect_quantity,
                    "efficiency": production.efficiency,
                    "product_type": production.product_type,
                    "remarks": production.remarks,
                    "recorded_by": str(production.recorded_by) if production.recorded_by else None,
                }
            )
        return result

    def generate_leave_report(
        self, start_date: date, end_date: date
    ) -> List[Dict[str, Any]]:
        """Generate leave report for a date range (requests that overlap the window)."""
        rows = (
            self.db.query(LeaveRequest)
            .filter(
                LeaveRequest.start_date <= end_date,
                LeaveRequest.end_date >= start_date,
            )
            .order_by(LeaveRequest.start_date.asc())
            .all()
        )

        result = []
        for req in rows:
            result.append(
                {
                    "id": str(req.id),
                    "worker_id": str(req.worker_id),
                    "leave_type": req.leave_type,
                    "start_date": req.start_date.isoformat(),
                    "end_date": req.end_date.isoformat(),
                    "total_days": req.total_days,
                    "status": req.status,
                    "reason": req.reason,
                    "reviewed_by": str(req.reviewed_by) if req.reviewed_by else None,
                    "reviewed_at": req.reviewed_at.isoformat() if req.reviewed_at else None,
                    "review_comment": req.review_comment,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def export_csv(self, data: List[Dict[str, Any]]) -> str:
        """
        Export report data to CSV format.

        Returns the CSV content as a string (suitable for StreamingResponse).
        Uses Python stdlib csv module — no pandas dependency required.
        """
        if not data:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()
