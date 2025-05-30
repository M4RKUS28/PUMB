from fastapi import FastAPI, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware # Für OAuth Google Flow
import secrets # Für Session Secret Key Fallback

from .models.db_user import User as UserModel
from .schemas import user as user_schema
from .utils import auth
from .routers import users, auth_router
from .core.lifespan import lifespan
from .config import settings # Für Konfigurationen



# Create the main app instance with the lifespan manager
app = FastAPI(title="User Management API", root_path="/api", lifespan=lifespan)


_session_secret_key = getattr(settings, 'SESSION_SECRET_KEY', None)
if not _session_secret_key:
    print("WARNUNG: settings.SESSION_SECRET_KEY nicht gefunden. Verwende einen temporären Schlüssel. Dies ist unsicher für die Produktion.")
    _session_secret_key = secrets.token_hex(32)

app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret_key
)


# CORS Configuration
origins = [
    "http://localhost:3000",
    "http://localhost:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a root router for the /api prefix
api_router = APIRouter()

# Include your existing routers under this api_router
api_router.include_router(users.router)
api_router.include_router(auth_router.router) # Add the auth router

#...


@api_router.get("/users/me", response_model=user_schema.User, tags=["users"])
async def read_users_me(current_user: UserModel = Depends(auth.get_current_active_user)):
    """
    Get the current logged-in user's profile.
    This endpoint is accessible to all authenticated users.
    """
    return current_user

# Include the api_router in the main app
app.include_router(api_router)

@app.get("/")
async def root():
    """
    Root endpoint that provides a welcome message.
    This can be used to verify that the API is running.
    """
    return {"message": "Welcome to the User Management API. See /docs for API documentation."}