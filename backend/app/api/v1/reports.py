"""
Reports API endpoints.

GET /reports/attendance  - Attendance report for a date range
GET /reports/production  - Production report for a date range
GET /reports/leave       - Leave report for a date range

All endpoints support ?export_format=csv to download a CSV file.
"""

from datetime import date
from io import StringIO
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.api.deps import require_role
from backend.app.models.user import User
from backend.app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


def _maybe_csv(
    data: List[Dict[str, Any]],
    export_format: Optional[str],
    filename: str,
    service: ReportService,
):
    """Return JSON list or a StreamingResponse CSV depending on export_format."""
    if export_format and export_format.lower() == "csv":
        csv_content = service.export_csv(data)
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"},
        )
    return data


@router.get("/attendance")
def attendance_report(
    start_date: date = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: date = Query(..., description="End date (YYYY-MM-DD)"),
    floor_id: Optional[UUID] = Query(None, description="Filter by floor ID"),
    export_format: Optional[str] = Query(None, description="'csv' to download as CSV"),
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Generate attendance report for a date range."""
    service = ReportService(db)
    data = service.generate_attendance_report(start_date, end_date, floor_id)
    return _maybe_csv(data, export_format, "attendance_report", service)


@router.get("/production")
def production_report(
    start_date: date = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: date = Query(..., description="End date (YYYY-MM-DD)"),
    worker_id: Optional[UUID] = Query(None, description="Filter by worker ID"),
    export_format: Optional[str] = Query(None, description="'csv' to download as CSV"),
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Generate production report for a date range."""
    service = ReportService(db)
    data = service.generate_production_report(start_date, end_date, worker_id)
    return _maybe_csv(data, export_format, "production_report", service)


@router.get("/leave")
def leave_report(
    start_date: date = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: date = Query(..., description="End date (YYYY-MM-DD)"),
    export_format: Optional[str] = Query(None, description="'csv' to download as CSV"),
    current_user: User = Depends(require_role(["ADMIN", "OWNER", "MANAGER"])),
    db: Session = Depends(get_db),
):
    """Generate leave report for a date range."""
    service = ReportService(db)
    data = service.generate_leave_report(start_date, end_date)
    return _maybe_csv(data, export_format, "leave_report", service)
