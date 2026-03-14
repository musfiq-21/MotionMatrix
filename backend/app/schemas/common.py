"""
Common schemas used across the application.

Standardized API response format and pagination.
"""

from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class SuccessResponse(BaseModel):
    success: bool = True
    data: Any = None
    message: str = "Operation successful"


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail


class PaginationMeta(BaseModel):
    page: int = 1
    page_size: int = 10
    total_items: int = 0
    total_pages: int = 0


class PaginatedResponse(BaseModel):
    success: bool = True
    data: List[Any] = []
    pagination: PaginationMeta
