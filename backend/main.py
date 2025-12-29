from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.api.v1.demo import router as demo_router
from backend.app.api.v1.userCreate import router as user_router
from backend.app.api.v1.getAllUsers import router as get_user_router
from backend.app.api.v1.login import router as login_user_router

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

    app.include_router(demo_router, prefix="/api/v1", tags=["Demo"])
    app.include_router(user_router, prefix="/api/v1", tags=["User"])
    app.include_router(get_user_router, prefix="/api/v1", tags=["User"])
    app.include_router(login_user_router, prefix="/api/v1", tags=["User"])

    return app
app = create_app()
