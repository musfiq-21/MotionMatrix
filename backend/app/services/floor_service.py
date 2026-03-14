"""
Floor service layer.

Business logic for factory floor management.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.floor import Floor
from backend.app.schemas.floor import FloorCreate, FloorUpdate


class FloorService:
    def __init__(self, db: Session):
        self.db = db

    def create_floor(self, data: FloorCreate) -> Floor:
        floor = Floor(
            floor_name=data.floor_name,
            floor_number=data.floor_number,
            description=data.description,
        )
        self.db.add(floor)
        self.db.commit()
        self.db.refresh(floor)
        return floor

    def get_floor_by_id(self, floor_id: UUID) -> Optional[Floor]:
        return self.db.query(Floor).filter(Floor.id == floor_id).first()

    def get_all_floors(self) -> List[Floor]:
        return self.db.query(Floor).order_by(Floor.floor_number).all()

    def update_floor(self, floor_id: UUID, data: FloorUpdate) -> Optional[Floor]:
        floor = self.get_floor_by_id(floor_id)
        if not floor:
            return None
        for field, value in data.dict(exclude_unset=True).items():
            setattr(floor, field, value)
        self.db.commit()
        self.db.refresh(floor)
        return floor

    def delete_floor(self, floor_id: UUID) -> bool:
        floor = self.get_floor_by_id(floor_id)
        if not floor:
            return False
        self.db.delete(floor)
        self.db.commit()
        return True
