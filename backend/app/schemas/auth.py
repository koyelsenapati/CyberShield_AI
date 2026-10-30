"""
CyberShield AI
Authentication Schemas
"""

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

from app.core.security import password_problem

def _check_password(value: str) -> str:
    # The message is static and never echoes the submitted value.
    problem = password_problem(value)

    if problem:
        raise ValueError(problem)

    return value

class RegisterRequest(BaseModel):

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username"
    )

    full_name: str = Field(
        ...,
        min_length=2,
        max_length=100
    )

    email: EmailStr

    # max_length bounds characters cheaply; the validator enforces bcrypt's
    # 72-BYTE limit (multi-byte characters count for more than one byte).
    password: str = Field(
        ...,
        min_length=8,
        max_length=72,
        description="User password (8-72 characters, at most 72 UTF-8 bytes)"
    )

    @field_validator("password")
    @classmethod
    def password_must_fit_bcrypt(cls, value: str) -> str:
        return _check_password(value)

class LoginRequest(BaseModel):

    email: EmailStr

    # No minimum beyond "not empty": a wrong short password should receive
    # the same generic 401 as any other wrong password, not reveal the
    # registration policy.
    password: str = Field(
        ...,
        min_length=1,
        max_length=72,
    )

    @field_validator("password")
    @classmethod
    def password_must_fit_bcrypt(cls, value: str) -> str:
        return _check_password(value)

class TokenResponse(BaseModel):

    access_token: str

    token_type: str = "bearer"

class RegisterResponse(BaseModel):

    message: str

    user_id: int

class UserResponse(BaseModel):

    id: int

    username: str

    full_name: str

    email: EmailStr

    role: str

    is_active: bool

    is_verified: bool

    model_config = ConfigDict(
        from_attributes=True
    )

class LoginResponse(BaseModel):

    message: str

    access_token: str

    token_type: str = "bearer"

    user: UserResponse
