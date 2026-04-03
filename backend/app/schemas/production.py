"""
Pydantic schemas for Production operations.
"""

from datetime import date as dt_date, datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class ProductionBase(BaseModel):
    worker_id: UUID = Field(..., description="Worker ID")
    date: dt_date = Field(default_factory=dt_date.today)
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
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
