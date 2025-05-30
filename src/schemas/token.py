from typing import Optional
from pydantic import BaseModel

# Token Schemas (remain the same)
class Token(BaseModel):
    access_token: str
    refresh_token: str # Added refresh_token
    token_type: str
    user_id: int
    username: str
    #email: str
    is_admin: bool

class TokenData(BaseModel):
    username: Optional[str] = None
    #email: Optional[str] = None
    user_id: Optional[int] = None
    is_admin: Optional[bool] = None
    is_refresh: Optional[bool] = False # Added to distinguish refresh tokens

class LoginForm(BaseModel):
    username: str
    password: str