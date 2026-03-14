"""
Overtime database model.

Tracks overtime hours for workers.
"""

import uuid
from datetime import datetime, date

from sqlalchemy import Column, Date, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Overtime(Base):
    __tablename__ = "overtime_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    worker_id = Column(UUID(as_uuid=True), ForeignKey("workers.id", ondelete="CASCADE"), nullable=False, index=True)
    date = Column(Date, nullable=False, default=date.today, index=True)
    hours = Column(Float, nullable=False)
    reason = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="PENDING", index=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    worker = relationship("Worker", back_populates="overtime_records")
    approver = relationship("User", foreign_keys=[approved_by])

    def __repr__(self):
        return f"<Overtime(worker_id='{self.worker_id}', date='{self.date}', hours={self.hours})>"
