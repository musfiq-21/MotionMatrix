"""
Idle time database model.

Tracks worker activity/inactivity detected via ML-based hand movement analysis.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class IdleTime(Base):
    __tablename__ = "idle_time_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    worker_id = Column(UUID(as_uuid=True), ForeignKey("workers.id", ondelete="CASCADE"), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    detection_source = Column(String(50), nullable=True, default="ML_MODEL")
    remarks = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    worker = relationship("Worker", back_populates="idle_time_records")

    def __repr__(self):
        return f"<IdleTime(worker_id='{self.worker_id}', start='{self.start_time}')>"
