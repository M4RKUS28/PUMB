\
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool

from ..db.database import SessionLocal, engine, Base
from ..config.settings_loader import load_settings_from_db, initialize_db_with_default_settings
from ..config.settings import SETTINGS_RELOAD_INTERVAL_SECONDS

async def periodic_settings_reload():
    """Periodically reloads settings from the database."""
    while True:
        await asyncio.sleep(SETTINGS_RELOAD_INTERVAL_SECONDS)
        db_session = SessionLocal()
        try:
            print(f"Background task: Reloading settings from DB (interval: {SETTINGS_RELOAD_INTERVAL_SECONDS}s)...")
            # load_settings_from_db is synchronous, run it in a thread pool
            await run_in_threadpool(load_settings_from_db, db_session)
            print("Background task: Settings reloaded successfully.")
        except Exception as e:
            print(f"Background task: Error during periodic settings reload: {e}")
        finally:
            db_session.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI application to handle startup and shutdown events."""
    
    # Create tables first, ensuring all models are registered with Base
    # This needs to happen after all model modules are imported.
    print("Application startup: Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Application startup: Database tables created.")
    
    # Load settings on startup
    db_session_startup = SessionLocal()
    try:
        print("Application startup: Initializing and loading database settings...")
        initialize_db_with_default_settings(db_session_startup) # Populate defaults if missing
        load_settings_from_db(db_session_startup) # Load all settings into cache
        print("Application startup: Database settings initialized and loaded.")
    finally:
        db_session_startup.close()
    
    # Start the background task for periodic settings reload
    print(f"Application startup: Starting periodic settings reload task (interval: {SETTINGS_RELOAD_INTERVAL_SECONDS}s).")
    asyncio.create_task(periodic_settings_reload())
    print(f"Application startup: Periodic settings reload task started.")
    
    yield
    # On shutdown (if needed)
    print("Application shutdown.")
