from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

DB_USER = os.getenv("DB_USER", "your_db_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "your_db_password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306") # Default MySQL port
DB_NAME = os.getenv("DB_NAME", "your_app_db")

SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
# For SQLite (testing):
# SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
# For PostgreSQL:
# SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_recycle=3600,  # Recycle connections every hour (3600 seconds). Adjust as needed.
                       # Helps prevent `wait_timeout` issues from the DB side.
    pool_pre_ping=True, # Enable "pre-ping" to test connections before checkout.
                       # Adds a small overhead but increases resilience.
    pool_size=5,        # Default, number of connections to keep open in the pool.
    max_overflow=10,    # Default, number of connections that can be opened beyond pool_size if needed.
    # connect_args={"connect_timeout": 10} # Optional: timeout for establishing a new connection
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()