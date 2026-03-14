"""
Pydantic schemas for Production operations.
"""

from datetime import date, dt_date
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ProductionBase(BaseModel):
    worker_id: UUID = Field(..., description="Worker ID")
    date: dt_date = Field(default_factory=date.today)
    target_quantity: Optional[int] = None
    achieved_quantity: int = Field(default=0, ge=0)
    defect_quantity: int = Field(default=0, ge=0)
    efficiency: Optional[float] = None
    product_type: Optional[str] = Field(None, max_length=100)
    remarks: Optional[str] = None


class ProductionCreate(ProductionBase):
    pass


class ProductionUpdate(BaseModel):
    target_quantity: Optional[int] = None
    achieved_quantity: Optional[int] = Field(None, ge=0)
    defect_quantity: Optional[int] = Field(None, ge=0)
    efficiency: Optional[float] = None
    product_type: Optional[str] = Field(None, max_length=100)
    remarks: Optional[str] = None


class ProductionResponse(ProductionBase):
    id: UUID
    recorded_by: Optional[UUID] = None
    created_at: dt_date
    updated_at: dt_date

    class Config:
        from_attributes = True
