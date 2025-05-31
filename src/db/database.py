from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config.settings import settings  # Use the centralized settings

# Ensure SQLALCHEMY_DATABASE_URL is available
if not settings.SQLALCHEMY_DATABASE_URL:
    raise ValueError("SQLALCHEMY_DATABASE_URL is not set in the environment or .env file")

engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    pool_recycle=settings.DB_POOL_RECYCLE,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    connect_args={"connect_timeout": settings.DB_CONNECT_TIMEOUT} if settings.DB_CONNECT_TIMEOUT else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get a DB session
def get_db():
    """
    Dependency that provides a SQLAlchemy database session.
    Ensures the session is closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()