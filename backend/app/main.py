import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError

from .api.router import api_router
from .api.web import router as web_router
from .core.config import settings
from .core.database import engine
from .models import Base

logger = logging.getLogger("web_recon_backend")


def initialize_database() -> None:
    try:
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError as exc:
        logger.warning("Database initialization unavailable: %s", exc)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.ALLOWED_ORIGINS),
    allow_credentials=settings.ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_PREFIX)
app.include_router(web_router)

frontend_directory = Path(__file__).resolve().parents[2] / "frontend" / "app"
if frontend_directory.exists():
    app.mount("/app", StaticFiles(directory=frontend_directory, html=True), name="frontend")


@app.get("/")
def root():
    return {"message": f"{settings.PROJECT_NAME} backend is running."}


@app.get("/health/db")
def database_health():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"status": "ok", "database": "available"}
    except (SQLAlchemyError, OSError):
        return {"status": "error", "database": "unavailable"}
