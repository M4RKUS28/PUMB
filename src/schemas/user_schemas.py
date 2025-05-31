"""
Schemas for user management, including creation and updates with password complexity validation.
"""
import re
from typing import List, Optional
from pydantic import (BaseModel, EmailStr, Field, field_validator)
from config.settings import settings


class UserBase(BaseModel):
    """Base schema for user data, used for both creation and updates."""
    username: str
    email: EmailStr


class User(UserBase): # Your existing User schema for responses
    """Represents a user in the system with all fields."""
    id: int
    is_active: bool
    is_admin: bool
    profile_picture: Optional[str] = None
    
    class Config:
        """Pydantic configuration."""
        from_attributes = True

class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(
        ..., # Ellipsis means the field is required
        # min_length=settings.MIN_PASSWORD_LENGTH, # This will be implicitly checked by our validator too
        description=f"Password must be at least {settings.MIN_PASSWORD_LENGTH}\
            characters long and meet complexity requirements."
    )

    @field_validator('password')
    @classmethod
    def password_complexity_checks(cls, v: str) -> str:
        """Validates the password for complexity requirements."""
        # Pydantic's Field(min_length=...) would handle this,
        # but we include it here for a unified error message if preferred.
        if len(v) < settings.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters long.")

        errors: List[str] = []
        if settings.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", v):
            errors.append("must contain at least one uppercase letter")
        if settings.REQUIRE_LOWERCASE and not re.search(r"[a-z]", v):
            errors.append("must contain at least one lowercase letter")
        if settings.REQUIRE_DIGIT and not re.search(r"\\d", v):
            errors.append("must contain at least one digit")
        if settings.REQUIRE_SPECIAL_CHAR and not re.search(settings.SPECIAL_CHARACTERS_REGEX_PATTERN, v):
            errors.append("must contain at least one special character (e.g., !@#$%")
        
        if errors:
            # Pydantic expects a ValueError to be raised for validation failures
            # The message will be part of the 422 response detail.
            error_summary = "; ".join(errors)
            raise ValueError(f"Password does not meet complexity requirements: {error_summary}.")
        return v


class UserUpdate(BaseModel):
    """Schema for updating user information."""
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(
        default=None, # Password is optional on update
        description="New password (if changing) must meet complexity requirements."
    )
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None # Only updatable by admins

    @field_validator('password')
    @classmethod
    def update_password_complexity_checks(cls, v: Optional[str]) -> Optional[str]:
        """Validates the new password for complexity requirements."""

        if v is None: # If password is not being updated, skip validation
            return v

        # If password is provided (not None), it must meet all complexity rules.
        if len(v) < settings.MIN_PASSWORD_LENGTH:
            raise ValueError(f"New password must be at least {settings.MIN_PASSWORD_LENGTH} characters long.")
        errors: List[str] = []
        if settings.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", v):
            errors.append("must contain at least one uppercase letter")
        if settings.REQUIRE_LOWERCASE and not re.search(r"[a-z]", v):
            errors.append("must contain at least one lowercase letter")
        if settings.REQUIRE_DIGIT and not re.search(r"\\d", v):
            errors.append("must contain at least one digit")
        if settings.REQUIRE_SPECIAL_CHAR and not re.search(
            settings.SPECIAL_CHARACTERS_REGEX_PATTERN, v):
            errors.append("must contain at least one special character (e.g., !@#$%")
        if errors:
            error_summary = "; ".join(errors)
            raise ValueError(f"New password does not meet complexity requirements:{error_summary}.")
        return v


class ProfilePictureResponse(BaseModel):
    """Response schema for profile picture operations."""
    message: str = Field(..., description="Success or error message")
    profile_picture_url: Optional[str] = Field(
        None, 
        description="URL to the profile picture, null if deleted"
    )
    user_id: int = Field(..., description="ID of the user")
    
    class Config:
        """Pydantic configuration."""
        json_schema_extra = {
            "examples": [
                {
                    "message": "Profile picture uploaded successfully",
                    "profile_picture_url": "/media/profile_pictures/user_123_abc123.jpg",
                    "user_id": 123
                },
                {
                    "message": "Profile picture deleted successfully",
                    "profile_picture_url": None,
                    "user_id": 123
                }
            ]
        }