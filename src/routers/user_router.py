"""
Endpoints for managing users in the application.
"""
import os
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from config.settings import Settings as settings
from db.database import get_db
from models import user_models
from schemas import user_schemas
from utils import auth
from utils.file_utils import (delete_profile_picture_file,
                              generate_unique_filename, save_uploaded_file,
                              validate_image_file)

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", response_model=List[user_schemas.User], dependencies=[Depends(auth.get_current_admin_user)])
async def read_users(
    skip: int = 0,
    limit: int = 300,
    db: Session = Depends(get_db)
):
    """
    Retrieve all users. Only accessible by admin users.
    """
    users = db.query(user_models.DBUser).offset(skip).limit(limit).all()
    return users

@router.get("/{user_id}", response_model=user_schemas.User)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: user_models.DBUser = Depends(auth.get_current_active_user)
):
    """
    Retrieve a specific user by ID.
    Admin users can retrieve any user. Regular users can only retrieve their own profile.
    """
    if not current_user.is_admin and current_user.id != user_id: # type: ignore
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Not authorized to access this user")

    user = db.query(user_models.DBUser).filter(user_models.DBUser.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@router.put("/{user_id}", response_model=user_schemas.User)
async def update_user(
    user_id: int,
    user_update: user_schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: user_models.DBUser = Depends(auth.get_current_active_user)
):
    """
    Update a user's details.
    Admin users can update any user. Regular users can only update their own profile.
    Admin status can only be changed by other admins.
    """
    db_user = db.query(user_models.DBUser).filter(user_models.DBUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not current_user.is_admin and current_user.id != user_id: # type: ignore
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Not authorized to update this user")

    update_data = user_update.model_dump(exclude_unset=True) # Pydantic V2

    if "username" in update_data:
        existing_user = db.query(user_models.DBUser).filter(
            user_models.DBUser.username == update_data["username"]).first()
        if existing_user and existing_user.id != user_id: # type: ignore
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Username already registered")
        db_user.username = update_data["username"]

    if "email" in update_data:
        existing_user = db.query(user_models.DBUser).filter(
            user_models.DBUser.email == update_data["email"]).first()
        if existing_user and existing_user.id != user_id: # type: ignore
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Email already registered")
        db_user.email = update_data["email"]

    if "password" in update_data and update_data["password"]:
        db_user.hashed_password = auth.get_password_hash(update_data["password"]) # type: ignore

    if "is_active" in update_data and current_user.is_admin: # type: ignore
        db_user.is_active = update_data["is_active"]

    elif "is_active" in update_data and not current_user.is_admin: # type: ignore
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only admins can change active status")

    if "is_admin" in update_data and current_user.is_admin: # type: ignore
        # Prevent admin from accidentally removing their
        # own admin status if they are the only admin
        if db_user.id == current_user.id and not update_data["is_admin"]: # type: ignore
            admin_count = db.query(user_models.DBUser).filter(
                user_models.DBUser.is_admin.is_(True)
                ).count()
            if admin_count <= 1:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                     detail="Cannot remove the last admin's privileges")
        db_user.is_admin = update_data["is_admin"]
    elif "is_admin" in update_data and not current_user.is_admin: # type: ignore
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only admins can change admin status")

    db.commit()
    db.refresh(db_user)
    return db_user


@router.delete("/{user_id}", response_model=user_schemas.User,
               dependencies=[Depends(auth.get_current_admin_user)])
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: user_models.DBUser = Depends(auth.get_current_admin_user)
):
    """
    Delete a user. Only accessible by admin users.
    Admins cannot delete themselves.
    """
    db_user = db.query(user_models.DBUser).filter(user_models.DBUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if db_user.id == current_user.id: # type: ignore
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Admins cannot delete themselves")

    db.delete(db_user)
    db.commit()
    return db_user

@router.post("/{user_id}/profile-picture", response_model=user_schemas.ProfilePictureResponse)
async def upload_profile_picture(
    user_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: user_models.DBUser = Depends(auth.get_current_active_user)
):
    """
    Upload or replace a user's profile picture.
    Admin users can update any user's picture. Regular users can only update their own.
    """
    # Authorization check
    if not current_user.is_admin and current_user.id != user_id: # type: ignore
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user's profile picture"
        )

    # Get user from database
    db_user = db.query(user_models.DBUser).filter(user_models.DBUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Validate uploaded file
    validate_image_file(file)

    # Delete existing profile picture if exists
    if db_user.profile_picture: # type: ignore
        delete_profile_picture_file(db_user.profile_picture) # type: ignore

    # Generate unique filename and save
    filename = generate_unique_filename(file.filename, user_id) # type: ignore
    file_path = settings.MEDIA_DIR / filename
    
    try:
        await save_uploaded_file(file, file_path)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save file: {str(e)}"
        ) from e

    # Update user profile picture URL
    profile_picture_url = f"/media/profile_pictures/{filename}"
    db_user.profile_picture = profile_picture_url # type: ignore
    
    db.commit()
    db.refresh(db_user)

    return user_schemas.ProfilePictureResponse(
        message="Profile picture uploaded successfully",
        profile_picture_url=profile_picture_url,
        user_id=user_id
    )


@router.delete("/{user_id}/profile-picture", response_model=user_schemas.ProfilePictureResponse)
async def delete_profile_picture(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: user_models.DBUser = Depends(auth.get_current_active_user)
):
    """
    Delete a user's profile picture.
    Admin users can delete any user's picture. Regular users can only delete their own.
    """
    # Authorization check
    if not current_user.is_admin and current_user.id != user_id: # type: ignore
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this user's profile picture"
        )

    # Get user from database
    db_user = db.query(user_models.DBUser).filter(user_models.DBUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not db_user.profile_picture: # type: ignore
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User has no profile picture to delete"
        )

    # Delete file from disk
    delete_profile_picture_file(db_user.profile_picture) # type: ignore

    # Update database
    db_user.profile_picture = None # type: ignore
    db.commit()
    db.refresh(db_user)

    return user_schemas.ProfilePictureResponse(
        message="Profile picture deleted successfully",
        profile_picture_url=None,
        user_id=user_id
    )

@router.get("/media/profile_pictures/{filename}")
async def get_profile_picture(filename: str):
    """
    Serve profile picture files.
    This endpoint serves the actual image files.
    """
    file_path = settings.MEDIA_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
    
    # Security check: ensure the file is within the allowed directory
    try:
        abs_file_path = os.path.abspath(file_path)
        abs_media_dir = os.path.abspath(settings.MEDIA_DIR)
        os.path.relpath(abs_file_path, abs_media_dir)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied") from exc
    
    return FileResponse(
        path=file_path,
        media_type=f"image/{file_path.suffix[1:]}",  # Remove the dot from extension
        filename=filename
    )