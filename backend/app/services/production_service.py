"""
Production service layer.

Business logic for production record management.
"""

from datetime import date
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.production import Production
from backend.app.schemas.production import ProductionCreate, ProductionUpdate


class ProductionService:
    def __init__(self, db: Session):
        self.db = db

    def create_production(self, data: ProductionCreate, recorded_by: UUID) -> Production:
        record = Production(
            worker_id=data.worker_id,
            date=data.date,
            target_quantity=data.target_quantity,
            achieved_quantity=data.achieved_quantity,
            defect_quantity=data.defect_quantity,
            efficiency=data.efficiency,
            product_type=data.product_type,
            remarks=data.remarks,
            recorded_by=recorded_by,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def get_production_by_id(self, production_id: UUID) -> Optional[Production]:
        return self.db.query(Production).filter(Production.id == production_id).first()

    def get_production_by_worker(self, worker_id: UUID, target_date: Optional[date] = None) -> List[Production]:
        query = self.db.query(Production).filter(Production.worker_id == worker_id)
        if target_date:
            query = query.filter(Production.date == target_date)
        return query.order_by(Production.date.desc()).all()

    def update_production(self, production_id: UUID, data: ProductionUpdate) -> Optional[Production]:
        record = self.get_production_by_id(production_id)
        if not record:
            return None
        for field, value in data.dict(exclude_unset=True).items():
            setattr(record, field, value)
        self.db.commit()
        self.db.refresh(record)
        return record

    def delete_production(self, production_id: UUID) -> bool:
        record = self.get_production_by_id(production_id)
        if not record:
            return False
        self.db.delete(record)
        self.db.commit()
        return True
