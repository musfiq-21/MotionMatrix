"""
Pydantic schemas for Message operations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class MessageCreate(BaseModel):
    receiver_id: UUID
    subject: Optional[str] = Field(None, max_length=255)
    body: str = Field(..., min_length=1)


class MessageResponse(BaseModel):
    id: UUID
    sender_id: UUID
    receiver_id: UUID
    subject: Optional[str] = None
    body: str
    is_read: bool
    read_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
