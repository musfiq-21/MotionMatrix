"""
Pydantic schemas for Worker operations.
"""

from datetime import date, datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class WorkerBase(BaseModel):
    employee_id: str = Field(..., max_length=50, description="Unique employee ID")
    designation: Optional[str] = Field(None, max_length=100)
    join_date: date = Field(default_factory=date.today)
    floor_id: Optional[UUID] = None
    workstation_id: Optional[UUID] = None
    shift_id: Optional[UUID] = None
    notes: Optional[str] = None


class WorkerCreate(WorkerBase):
    user_id: UUID = Field(..., description="Associated user ID")


class WorkerUpdate(BaseModel):
    designation: Optional[str] = Field(None, max_length=100)
    floor_id: Optional[UUID] = None
    workstation_id: Optional[UUID] = None
    shift_id: Optional[UUID] = None
    notes: Optional[str] = None


class WorkerResponse(WorkerBase):
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
