"""
Attendance database model.

Tracks manual attendance records for workers.
Attendance is entered by floor managers.
"""

import uuid
from datetime import datetime, date

from sqlalchemy import Column, Date, DateTime, ForeignKey, String, Text, Time
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Attendance(Base):
    __tablename__ = "attendance"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    worker_id = Column(UUID(as_uuid=True), ForeignKey("workers.id", ondelete="CASCADE"), nullable=False, index=True)
    attendance_date = Column(Date, nullable=False, default=date.today, index=True)
    clock_in = Column(Time, nullable=True)
    clock_out = Column(Time, nullable=True)
    status = Column(String(50), nullable=False, default="PRESENT", index=True)
    remarks = Column(Text, nullable=True)
    recorded_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    worker = relationship("Worker", back_populates="attendance_records")
    recorder = relationship("User", foreign_keys=[recorded_by])

    def __repr__(self):
        return f"<Attendance(worker_id='{self.worker_id}', date='{self.attendance_date}', status='{self.status}')>"
