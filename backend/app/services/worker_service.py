"""
Worker service layer.

Business logic for worker management.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.worker import Worker
from backend.app.schemas.worker import WorkerCreate, WorkerUpdate


class WorkerService:
    def __init__(self, db: Session):
        self.db = db

    def create_worker(self, data: WorkerCreate) -> Worker:
        worker = Worker(
            user_id=data.user_id,
            employee_id=data.employee_id,
            designation=data.designation,
            join_date=data.join_date,
            floor_id=data.floor_id,
            workstation_id=data.workstation_id,
            shift_id=data.shift_id,
            notes=data.notes,
        )
        self.db.add(worker)
        self.db.commit()
        self.db.refresh(worker)
        return worker

    def get_worker_by_id(self, worker_id: UUID) -> Optional[Worker]:
        return self.db.query(Worker).filter(Worker.id == worker_id).first()

    def get_worker_by_user_id(self, user_id: UUID) -> Optional[Worker]:
        return self.db.query(Worker).filter(Worker.user_id == user_id).first()

    def get_worker_by_employee_id(self, employee_id: str) -> Optional[Worker]:
        return self.db.query(Worker).filter(Worker.employee_id == employee_id).first()

    def get_workers_by_floor(self, floor_id: UUID) -> List[Worker]:
        return self.db.query(Worker).filter(Worker.floor_id == floor_id).all()

    def get_all_workers(self, skip: int = 0, limit: int = 50) -> List[Worker]:
        return self.db.query(Worker).offset(skip).limit(limit).all()

    def update_worker(self, worker_id: UUID, data: WorkerUpdate) -> Optional[Worker]:
        worker = self.get_worker_by_id(worker_id)
        if not worker:
            return None
        for field, value in data.dict(exclude_unset=True).items():
            setattr(worker, field, value)
        self.db.commit()
        self.db.refresh(worker)
        return worker

    def delete_worker(self, worker_id: UUID) -> bool:
        worker = self.get_worker_by_id(worker_id)
        if not worker:
            return False
        self.db.delete(worker)
        self.db.commit()
        return True
