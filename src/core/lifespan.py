\
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI

from src.db.database import SessionLocal, engine, Base
from src.config.settings_loader import load_settings_from_db, initialize_db_with_default_settings
from src.config.settings import settings # Use centralized settings

logger = logging.getLogger(__name__)

async def periodic_settings_reload():
    """Periodically reloads settings from the database if dynamic settings are enabled."""
    if not settings.SETTINGS_RELOAD_INTERVAL_SECONDS > 0:
        logger.info("Periodic settings reload is disabled (interval <= 0).")
        return

    while True:
        await asyncio.sleep(settings.SETTINGS_RELOAD_INTERVAL_SECONDS)
        logger.info("Attempting to reload settings from database...")
        db_session = SessionLocal()
        try:
            await asyncio.to_thread(load_settings_from_db, db_session)
            logger.info("Settings reloaded from database successfully.")
        except Exception as e: # Keep Exception for now, can be refined if specific exceptions are known
            logger.error(f"Error reloading settings from database: {e}", exc_info=True)
        finally:
            db_session.close()

@asynccontextmanager
async def lifespan(app: FastAPI): # app argument is used by FastAPI for lifespan context
    """Lifespan manager for FastAPI application to handle startup and shutdown events."""
    logger.info("Application startup sequence initiated...")

    logger.info("Creating database tables if they don't exist...")
    try:
        await asyncio.to_thread(Base.metadata.create_all, bind=engine)
        logger.info("Database tables checked/created.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}", exc_info=True)

    logger.info("Initializing/loading settings from database...")
    db_session_startup = SessionLocal()
    try:
        await asyncio.to_thread(initialize_db_with_default_settings, db_session_startup)
        await asyncio.to_thread(load_settings_from_db, db_session_startup)
        logger.info("Settings initialized/loaded from database.")
    except Exception as e:
        logger.error(f"Error initializing/loading settings from database: {e}", exc_info=True)
    finally:
        db_session_startup.close()

    if settings.SETTINGS_RELOAD_INTERVAL_SECONDS > 0:
        logger.info(f"Starting periodic settings reload task (interval: {settings.SETTINGS_RELOAD_INTERVAL_SECONDS}s).")
        # Store the task on app.state for potential access during shutdown
        app.state.settings_reload_task = asyncio.create_task(periodic_settings_reload())
    else:
        logger.info("Periodic settings reload task is disabled.")
        app.state.settings_reload_task = None

    yield

    logger.info("Application shutdown sequence initiated...")
    if hasattr(app.state, 'settings_reload_task') and app.state.settings_reload_task and not app.state.settings_reload_task.done():
        logger.info("Cancelling periodic settings reload task...")
        app.state.settings_reload_task.cancel()
        try:
            await app.state.settings_reload_task
        except asyncio.CancelledError:
            logger.info("Periodic settings reload task cancelled successfully.")
        except Exception as e:
            logger.error(f"Error during settings_reload_task cancellation: {e}", exc_info=True)

    logger.info("Application shutdown complete.")
