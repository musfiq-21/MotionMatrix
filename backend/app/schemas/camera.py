"""
Pydantic schemas for Camera operations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class CameraBase(BaseModel):
    camera_name: str = Field(..., max_length=100)
    stream_url: str = Field(..., max_length=500)
    is_active: bool = True
    description: Optional[str] = None
    workstation_id: Optional[UUID] = None


class CameraCreate(CameraBase):
    pass


class CameraUpdate(BaseModel):
    camera_name: Optional[str] = Field(None, max_length=100)
    stream_url: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None
    description: Optional[str] = None
    workstation_id: Optional[UUID] = None


class CameraResponse(CameraBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
