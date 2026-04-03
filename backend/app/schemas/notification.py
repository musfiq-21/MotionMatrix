"""
Pydantic schemas for Notification operations.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class NotificationCreate(BaseModel):
    user_id: UUID
    notification_type: str = Field(..., description="Notification type")
    title: str = Field(..., max_length=255)
    body: Optional[str] = None


class NotificationResponse(BaseModel):
    id: UUID
    user_id: UUID
    notification_type: str
    title: str
    body: Optional[str] = None
    is_read: bool
    read_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
