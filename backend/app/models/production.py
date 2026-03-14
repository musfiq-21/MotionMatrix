"""
Production database model.

Tracks production records for workers in the garment factory.
"""

import uuid
from datetime import datetime, date

from sqlalchemy import Column, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class Production(Base):
    __tablename__ = "production_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    worker_id = Column(UUID(as_uuid=True), ForeignKey("workers.id", ondelete="CASCADE"), nullable=False, index=True)
    date = Column(Date, nullable=False, default=date.today, index=True)
    target_quantity = Column(Integer, nullable=True)
    achieved_quantity = Column(Integer, nullable=False, default=0)
    defect_quantity = Column(Integer, nullable=False, default=0)
    efficiency = Column(Float, nullable=True)
    product_type = Column(String(100), nullable=True)
    remarks = Column(Text, nullable=True)
    recorded_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    worker = relationship("Worker", back_populates="production_records")
    recorder = relationship("User", foreign_keys=[recorded_by])

    def __repr__(self):
        return f"<Production(worker_id='{self.worker_id}', date='{self.date}', achieved={self.achieved_quantity})>"
