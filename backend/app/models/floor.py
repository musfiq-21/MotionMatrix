"""
Floor database model.

Represents factory floors in the garment factory.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Floor(Base):
    __tablename__ = "floors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    floor_name = Column(String(100), unique=True, nullable=False)
    floor_number = Column(Integer, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    workstations = relationship("Workstation", back_populates="floor", lazy="dynamic")
    workers = relationship("Worker", back_populates="floor", lazy="dynamic")

    def __repr__(self):
        return f"<Floor(floor_name='{self.floor_name}', floor_number={self.floor_number})>"
