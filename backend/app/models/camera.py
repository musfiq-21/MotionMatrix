"""
Camera database model.

Represents CCTV cameras assigned to workstations for activity monitoring.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Camera(Base):
    __tablename__ = "cameras"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    camera_name = Column(String(100), nullable=False)
    stream_url = Column(String(500), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    description = Column(Text, nullable=True)
    workstation_id = Column(UUID(as_uuid=True), ForeignKey("workstations.id", ondelete="SET NULL"), nullable=True, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    workstation = relationship("Workstation", back_populates="camera")

    def __repr__(self):
        return f"<Camera(camera_name='{self.camera_name}', is_active={self.is_active})>"
