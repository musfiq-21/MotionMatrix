"""
Shift database model.

Represents shift configurations for workers.
"""

import uuid
from datetime import datetime, time

from sqlalchemy import Boolean, Column, DateTime, String, Text, Time
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Shift(Base):
    __tablename__ = "shifts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    shift_name = Column(String(100), unique=True, nullable=False)
    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)
    lunch_start = Column(Time, nullable=True)
    lunch_end = Column(Time, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    workers = relationship("Worker", back_populates="shift", lazy="dynamic")

    def __repr__(self):
        return f"<Shift(shift_name='{self.shift_name}', start={self.start_time}, end={self.end_time})>"
