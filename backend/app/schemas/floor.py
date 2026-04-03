"""
Pydantic schemas for Floor operations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class FloorBase(BaseModel):
    floor_name: str = Field(..., max_length=100)
    floor_number: int
    description: Optional[str] = None


class FloorCreate(FloorBase):
    pass


class FloorUpdate(BaseModel):
    floor_name: Optional[str] = Field(None, max_length=100)
    floor_number: Optional[int] = None
    description: Optional[str] = None


class FloorResponse(FloorBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
