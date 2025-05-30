
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm # Ensure this import is present
from sqlalchemy.orm import Session
from datetime import timedelta
import secrets
import uuid
import requests # Für Google OAuth Bild-Download
import base64   # Für Google OAuth Bild-Download

from authlib.integrations.starlette_client import OAuth, OAuthError

from ..config.settings_loader import get_setting
from ..config import settings # Import settings for Google OAuth
from ..db.database import get_db
from ..models.db_user import User as user_model
from ..schemas import token as token_schema
from ..schemas import user as user_schema
from ..utils import auth

router = APIRouter(
    prefix="/auth", # Add prefix for consistency
    tags=["Authentication"]
)

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
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
    refresh_token_expires = timedelta(minutes=auth.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = auth.create_refresh_token(
        data={"sub": user.username, "user_id": user.id, "is_admin": user.is_admin}, # Add is_admin here too
        expires_delta=refresh_token_expires,
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
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

    db_user_by_username = db.query(user_model).filter(user_model.username == user_data.username).first()
    if db_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    db_user_by_email = db.query(user_model).filter(user_model.email == user_data.email).first()
    if db_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = auth.get_password_hash(user_data.password)
    db_user = user_model(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/login/google")
async def login_google(request: Request):

    if not get_setting("GOOGLE_OAUTH20_ENABLED"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Google OAuth2.0 is currently disabled."
        )

    # GOOGLE_REDIRECT_URI muss auf /api/auth/google/callback zeigen
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="Google redirect URI not configured")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    print("Google callback received at /api/auth/google/callback")
    try:
        token_oauth = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        print(f"OAuthError in google_callback: {error.error} - {error.description}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'Could not validate credentials via Google: {error.description or error.error}',
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    
    user_info = token_oauth.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not fetch user info from Google.")

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not found in Google user info.")
        
    name = user_info.get("name")
    picture_url = user_info.get("picture")
    db_user = db.query(user_model.User).filter(user_model.User.email == email).first()
    profile_image_base64_data = None
    
    if picture_url:
        try:
            response = requests.get(picture_url)
            response.raise_for_status() 
            profile_image_base64_data = base64.b64encode(response.content).decode('utf-8')
        except requests.exceptions.RequestException as e:
            print(f"Could not download image from {picture_url}: {e}")
            profile_image_base64_data = None

    if not db_user:
        if name:
            base_username = name.lower().replace(" ", ".")[:35] # Kürzer für Suffix
        else:
            base_username = email.split("@")[0][:35] # Kürzer für Suffix
        
        username_candidate = base_username
        # Limit username length to fit DB schema (String(50))
        max_len_for_base_with_suffix = 50 - 8 # Max length for base_username part to allow for suffix like ".abc123" (7 chars)
        if len(username_candidate) > max_len_for_base_with_suffix:
            username_candidate = username_candidate[:max_len_for_base_with_suffix]

        final_username = username_candidate
        # Check for collision and append suffix if needed
        suffix_counter = 0
        while db.query(user_model.User).filter(user_model.User.username == final_username).first():
            suffix_counter += 1
            suffix = secrets.token_hex(3) if suffix_counter < 5 else secrets.token_hex(4) # Längerer Suffix bei vielen Kollisionen
            temp_username = f"{username_candidate}.{suffix}"
            if len(temp_username) > 50: # Sicherstellen, dass es nicht zu lang wird
                base_part_len = 50 - len(suffix) - 1 
                final_username = f"{username_candidate[:base_part_len]}.{suffix}"
            else:
                final_username = temp_username
            if suffix_counter > 10: # Schutz vor Endlosschleife
                raise HTTPException(status_code=500, detail="Could not generate unique username.")


        random_password = secrets.token_urlsafe(16)
        hashed_password = auth.get_password_hash(random_password)
        
        user_id_val = str(uuid.uuid4())
        db_user = user_model.User(
            id=user_id_val, 
            email=email,
            username=final_username,
            hashed_password=hashed_password,
            is_active=True,
            is_admin=False 
        )
        if profile_image_base64_data:
            setattr(db_user, 'profile_image_base64', profile_image_base64_data)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    else: 
        current_db_image = getattr(db_user, 'profile_image_base64', None)
        if profile_image_base64_data and current_db_image != profile_image_base64_data:
            setattr(db_user, 'profile_image_base64', profile_image_base64_data)
            db.commit()
            db.refresh(db_user)
    
    if not db_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is inactive.")

    access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    access_token = auth.create_access_token(
        data={"sub": db_user.username, "user_id": str(db_user.id), "is_admin": db_user.is_admin, "email": db_user.email},
        expires_delta=access_token_expires_delta
    )
    refresh_token = auth.create_refresh_token(
        data={"sub": db_user.username, "user_id": str(db_user.id)},
        expires_delta=refresh_token_expires_delta
    )
    
    frontend_base_url = settings.FRONTEND_BASE_URL
    frontend_callback_path = "/auth/google/callback" # Dies ist der Pfad im Frontend
    
    redirect_url_with_fragment = (
        f"{frontend_base_url.rstrip('/')}{frontend_callback_path}"
        f"#access_token={access_token}"
        f"&token_type=bearer"
        f"&refresh_token={refresh_token}" # Refresh-Token hinzufügen
        f"&access_token_expires_in={int(access_token_expires_delta.total_seconds())}" # Ablaufzeit hinzufügen
        f"&user_id={str(db_user.id)}" # User-Infos für das Frontend
        f"&username={db_user.username}"
        f"&email={db_user.email}"
        f"&is_admin={'true' if db_user.is_admin else 'false'}"
    )
    print(f"Google Callback: Redirecting to frontend: {redirect_url_with_fragment}")
    return RedirectResponse(url=redirect_url_with_fragment)



@router.post("/token/refresh", response_model=token_schema.Token)
async def refresh_access_token(
    current_user: user_model = Depends(auth.get_current_user_from_refresh_token),
):
    """
    Refresh an access token using a refresh token.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = auth.create_access_token(
        data={"sub": current_user.username, "user_id": current_user.id, "is_admin": current_user.is_admin},
        expires_delta=access_token_expires
    )
    
    # Note: Typically, a new refresh token is also issued upon refresh for better security (rotation).
    # For simplicity, we are re-using the existing logic for creating a new refresh token if needed.
    # If you want to implement refresh token rotation, you would generate a new refresh_token here as well.
    # For this example, we will return the *new* access token and the *original* refresh token is expected to be re-used by the client
    # until it expires. Or, if you want to issue a new refresh token each time:
    
    refresh_token_expires = timedelta(minutes=auth.REFRESH_TOKEN_EXPIRE_MINUTES)
    new_refresh_token = auth.create_refresh_token(
        data={"sub": current_user.username, "user_id": current_user.id, "is_admin": current_user.is_admin},
        expires_delta=refresh_token_expires
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token, # Or the original refresh token if not rotating
        "token_type": "bearer",
        "user_id": current_user.id,
        "username": current_user.username,
        "is_admin": current_user.is_admin
    }
