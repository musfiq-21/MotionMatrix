"""
Pydantic schemas for Workstation operations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class WorkstationBase(BaseModel):
    workstation_name: str = Field(..., max_length=100)
    description: Optional[str] = None
    floor_id: UUID


class WorkstationCreate(WorkstationBase):
    pass


class WorkstationUpdate(BaseModel):
    workstation_name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None
    floor_id: Optional[UUID] = None


class WorkstationResponse(WorkstationBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
