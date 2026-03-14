"""
Pydantic schemas for Shift operations.
"""

from datetime import datetime, time
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ShiftBase(BaseModel):
    shift_name: str = Field(..., max_length=100)
    start_time: time
    end_time: time
    lunch_start: Optional[time] = None
    lunch_end: Optional[time] = None
    is_active: bool = True
    description: Optional[str] = None


class ShiftCreate(ShiftBase):
    pass


class ShiftUpdate(BaseModel):
    shift_name: Optional[str] = Field(None, max_length=100)
    start_time: Optional[time] = None
    end_time: Optional[time] = None
    lunch_start: Optional[time] = None
    lunch_end: Optional[time] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None


class ShiftResponse(ShiftBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
