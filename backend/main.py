from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.config import settings
from backend.app.core.database import Base, engine
from backend.app.core.exceptions import (
    MotionMatrixException,
    motion_matrix_exception_handler,
    validation_exception_handler,
    http_exception_handler,
)

# Import ALL models so Base.metadata knows every table before create_all()
import backend.app.models  # noqa: F401  (imports __init__.py which imports all models)

# Existing routers
from backend.app.api.v1.demo import router as demo_router
from backend.app.api.v1.userCreate import router as user_create_router
from backend.app.api.v1.getAllUsers import router as get_user_router
from backend.app.api.v1.login import router as login_user_router

# New skeleton routers
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.users import router as users_router
from backend.app.api.v1.workers import router as workers_router
from backend.app.api.v1.floors import router as floors_router
from backend.app.api.v1.attendance import router as attendance_router
from backend.app.api.v1.production import router as production_router
from backend.app.api.v1.leave import router as leave_router
from backend.app.api.v1.reports import router as reports_router


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register custom exception handlers
    app.add_exception_handler(MotionMatrixException, motion_matrix_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)

    @app.on_event("startup")
    def on_startup():
        """Create all database tables on startup (idempotent)."""
        Base.metadata.create_all(bind=engine)

    # ---- Existing routes ----
    app.include_router(demo_router, prefix="/api/v1", tags=["Demo"])
    app.include_router(user_create_router, prefix="/api/v1", tags=["User"])
    app.include_router(get_user_router, prefix="/api/v1", tags=["User"])
    app.include_router(login_user_router, prefix="/api/v1/auth", tags=["User"])

    # ---- New module routes ----
    app.include_router(auth_router, prefix="/api/v1", tags=["Authentication"])
    app.include_router(users_router, prefix="/api/v1", tags=["Users"])
    app.include_router(workers_router, prefix="/api/v1", tags=["Workers"])
    app.include_router(floors_router, prefix="/api/v1", tags=["Floors"])
    app.include_router(attendance_router, prefix="/api/v1", tags=["Attendance"])
    app.include_router(production_router, prefix="/api/v1", tags=["Production"])
    app.include_router(leave_router, prefix="/api/v1", tags=["Leave"])
    app.include_router(reports_router, prefix="/api/v1", tags=["Reports"])

    return app


app = create_app()
