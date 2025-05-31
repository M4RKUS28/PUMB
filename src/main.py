"""
PUMP - A FastAPI-based project structure with centralized settings and modular routers.
"""
import logging
import secrets

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config.settings import settings  # Use the centralized settings
from .core.lifespan import lifespan
from .routers import auth_router, user_router

# Configure logging
logger = logging.getLogger(__name__)

# Create the main app instance with the lifespan manager
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json", # Standard OpenAPI path
    lifespan=lifespan,
    debug=settings.DEBUG
)


# Session Middleware for OAuth Google Flow
# Ensure SESSION_SECRET_KEY is set, otherwise generate a temporary one (unsafe for production)
_session_secret_key = settings.SESSION_SECRET_KEY
if not _session_secret_key:
    logger.warning(
        "settings.SESSION_SECRET_KEY not found. \
        Using a temporary key. This is UNSAFE for production."
    )
    _session_secret_key = secrets.token_hex(32)

app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret_key
)


# CORS Configuration
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ORIGINS], # Ensure origins are strings
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    logger.warning("CORS_ORIGINS is not set. CORS will not be configured.")


# Create a root router for the API prefix from settings
api_router = APIRouter(prefix=settings.API_V1_STR)

# Include your existing routers under this api_router
api_router.include_router(user_router.router)
api_router.include_router(auth_router.router) # Add the auth router

# Include the api_router in the main app
app.include_router(api_router)

# Root endpoint for basic health check or API info
@app.get("/", tags=["Root"])
async def read_root():
    """
    Root endpoint providing basic API information.
    """
    return {"message": f"Welcome to {settings.PROJECT_NAME}", "docs_url": "/docs", "redoc_url": "/redoc"}