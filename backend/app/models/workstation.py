"""
Workstation database model.

Represents individual work stations on factory floors.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Workstation(Base):
    __tablename__ = "workstations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workstation_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    floor_id = Column(UUID(as_uuid=True), ForeignKey("floors.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    floor = relationship("Floor", back_populates="workstations")
    camera = relationship("Camera", back_populates="workstation", uselist=False)
    workers = relationship("Worker", back_populates="workstation", lazy="dynamic")

    def __repr__(self):
        return f"<Workstation(workstation_name='{self.workstation_name}')>"
