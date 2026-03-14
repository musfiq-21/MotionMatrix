"""
Worker database model.

Extends User with worker-specific data like floor assignment,
workstation, and shift information.
"""

import uuid
from datetime import datetime, date

from sqlalchemy import Column, Date, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Worker(Base):
    __tablename__ = "workers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    employee_id = Column(String(50), unique=True, nullable=False, index=True)
    designation = Column(String(100), nullable=True)
    join_date = Column(Date, nullable=False, default=date.today)
    floor_id = Column(UUID(as_uuid=True), ForeignKey("floors.id", ondelete="SET NULL"), nullable=True, index=True)
    workstation_id = Column(UUID(as_uuid=True), ForeignKey("workstations.id", ondelete="SET NULL"), nullable=True, index=True)
    shift_id = Column(UUID(as_uuid=True), ForeignKey("shifts.id", ondelete="SET NULL"), nullable=True, index=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="worker")
    floor = relationship("Floor", back_populates="workers")
    workstation = relationship("Workstation", back_populates="workers")
    shift = relationship("Shift", back_populates="workers")
    attendance_records = relationship("Attendance", back_populates="worker", lazy="dynamic")
    production_records = relationship("Production", back_populates="worker", lazy="dynamic")
    overtime_records = relationship("Overtime", back_populates="worker", lazy="dynamic")
    leave_requests = relationship("LeaveRequest", back_populates="worker", lazy="dynamic")
    idle_time_records = relationship("IdleTime", back_populates="worker", lazy="dynamic")

    def __repr__(self):
        return f"<Worker(employee_id='{self.employee_id}')>"
