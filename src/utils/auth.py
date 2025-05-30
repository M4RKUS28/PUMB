import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from src.models.db_user import User as UserModel # Explicitly import the SQLAlchemy model class
from src.schemas import token as token_schema # Pydantic schema
from src.db.database import get_db
from src.config.settings import settings # Use centralized settings

logger = logging.getLogger(__name__)

# Password-Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 with Password Flow
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str) -> Optional[UserModel]:
    """
    Authenticates a user by username and password.
    Returns the UserModel instance if authentication is successful, otherwise None.
    """
    user: Optional[UserModel] = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        logger.debug(f"Authentication failed: User '{username}' not found.")
        return None
    # When 'user' is an instance of UserModel, user.hashed_password is a string.
    if not verify_password(password, user.hashed_password):
        logger.debug(f"Authentication failed: Invalid password for user '{username}'.")
        return None
    logger.info(f"User '{username}' authenticated successfully.")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a new access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access", "sub": to_encode.get("sub")})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a new refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "refresh", "sub": to_encode.get("sub")})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserModel:
    """
    Decodes the JWT token to get the current user (UserModel instance).
    Raises HTTPException if the token is invalid or the user is not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")
        if username is None or token_type != "access":
            logger.warning(f"Invalid token: username missing or not an access token. Payload: {payload}")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWTError while decoding token: {e}", exc_info=True)
        raise credentials_exception from e

    user: Optional[UserModel] = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        logger.warning(f"User '{username}' from token not found in database.")
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    """
    Checks if the current user (UserModel instance) is active.
    Raises HTTPException if the user is inactive.
    """
    # current_user is an instance of UserModel. Its 'is_active' attribute is a Python bool.
    if not current_user.is_active:
        logger.warning(f"Inactive user attempt: User ID {current_user.id}, Username '{current_user.username}'.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user: UserModel = Depends(get_current_active_user)) -> UserModel:
    """
    Checks if the current active user (UserModel instance) is an admin.
    Raises HTTPException if the user is not an admin.
    """
    # current_user is an instance of UserModel. Its 'is_admin' attribute is a Python bool.
    if not current_user.is_admin:
        logger.warning(f"Admin access denied: User ID {current_user.id}, Username '{current_user.username}' is not an admin.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn\'t have enough privileges"
        )
    return current_user

async def get_current_user_from_refresh_token(token: str, db: Session) -> UserModel:
    """
    Decodes a refresh token to get the user (UserModel instance).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer refresh"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")
        if username is None or token_type != "refresh":
            logger.warning(f"Invalid refresh token: username missing or not a refresh token. Payload: {payload}")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWTError while decoding refresh token: {e}", exc_info=True)
        raise credentials_exception from e

    user: Optional[UserModel] = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        logger.warning(f"User '{username}' from refresh token not found in database.")
        raise credentials_exception
    # user is an instance of UserModel. Its 'is_active' attribute is a Python bool.
    if not user.is_active:
        logger.warning(f"Inactive user attempt with refresh token: User ID {user.id}, Username '{user.username}'.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user