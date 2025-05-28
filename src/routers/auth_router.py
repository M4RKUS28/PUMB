\
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..config.settings_loader import get_setting
from ..db.database import get_db
from ..models.db_user import User as UserModel
from ..schemas import token as token_schema
from ..schemas import user as user_schema
from ..utils import auth

router = APIRouter(
    tags=["Authentication"]
)

@router.post("/token", response_model=token_schema.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login endpoint to authenticate a user and return an access token.
    """
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "user_id": user.id, "is_admin": user.is_admin},
        expires_delta=access_token_expires,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "is_admin": user.is_admin
    }

@router.post("/register", response_model=user_schema.User, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: user_schema.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    if not get_setting("REGISTER_ENDPOINT_ENABLED"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User registration is currently disabled."
        )

    db_user_by_username = db.query(UserModel).filter(UserModel.username == user_data.username).first()
    if db_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    db_user_by_email = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if db_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = auth.get_password_hash(user_data.password)
    db_user = UserModel(
        username=user_data.username, 
        email=user_data.email, 
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
