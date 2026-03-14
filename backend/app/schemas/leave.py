"""
Pydantic schemas for Leave Request operations.
"""

from datetime import date, datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class LeaveRequestBase(BaseModel):
    leave_type: str = Field(..., description="ANNUAL_LEAVE, SICK_LEAVE, CASUAL_LEAVE, etc.")
    start_date: date
    end_date: date
    reason: Optional[str] = None


class LeaveRequestCreate(LeaveRequestBase):
    worker_id: UUID


class LeaveRequestUpdate(BaseModel):
    status: str = Field(..., description="APPROVED, REJECTED, CANCELLED")
    review_comment: Optional[str] = None


class LeaveRequestResponse(LeaveRequestBase):
    id: UUID
    worker_id: UUID
    total_days: int
    status: str
    reviewed_by: Optional[UUID] = None
    reviewed_at: Optional[datetime] = None
    review_comment: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
