"""
Schemas for user management, including creation and updates with password complexity validation.
"""
from typing import Optional
from pydantic import BaseModel, model_validator


class RefreshToken(BaseModel):
    """Schema for refresh token data."""
    refresh_token: str
    expires_in: int

class AccessToken(BaseModel):
    """Schema for access token data."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class Token(BaseModel):
    """Schema for access and refresh tokens."""
    access: AccessToken
    refresh: RefreshToken
    user_id: int
    username: str
    email: str
    is_admin: bool

class TokenRefreshRequest(BaseModel):
    """Schema for refresh token request."""
    refresh_token: str

class LoginForm(BaseModel):
    """Schema for user login form data."""
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

    @model_validator(mode="after")
    @classmethod
    def check_username_or_email(cls, values):
        """Ensure either username or email is provided, but not both."""
        if not (values.username or values.email):
            raise ValueError("Either 'username' or 'email' must be provided.")
        if values.username and values.email:
            raise ValueError("Provide only one of 'username' or 'email', not both.")
        return values