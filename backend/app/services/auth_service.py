from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.security import (
    PasswordTooLongError,
    hash_password,
    verify_password,
)

from app.core.jwt import create_access_token

from app.crud.user import (
    create_user,
    get_user_by_email,
    get_user_by_username,
)

from app.schemas.auth import RegisterRequest

def register(
    db: Session,
    request: RegisterRequest,
):
    if get_user_by_email(db, request.email):
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    if get_user_by_username(db, request.username):
        raise HTTPException(
            status_code=400,
            detail="Username already taken",
        )

    try:
        hashed_password = hash_password(request.password)
    except PasswordTooLongError as exc:
        # Schemas already reject this; kept as defence in depth.
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    user = create_user(
        db,
        {
            "username": request.username,
            "full_name": request.full_name,
            "email": request.email,
            "hashed_password": hashed_password,
            "role": "user",
            "is_active": True,
            "is_verified": False,
        },
    )

    return {
        "message": "Registration successful",
        "user_id": user.id,
    }

def login(
    db: Session,
    request,
):
    user = get_user_by_email(
        db,
        request.email,
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not verify_password(
        request.password,
        user.hashed_password,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    token = create_access_token(
        {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
        }
    )

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
        },
    }
