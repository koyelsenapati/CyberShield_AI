from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import admin_required, get_current_user
from app.database.database import get_db
from app.schemas.user import UserResponse
from app.services.user_service import (
    get_all_users,
    get_user,
    delete_user,
)

router = APIRouter(
    prefix="/users",
    tags=["Users"],
)

@router.get(
    "/",
    response_model=list[UserResponse],
)
def users(
    db: Session = Depends(get_db),
    admin=Depends(admin_required),
):
    """Admin only: list every user."""
    return get_all_users(db)

@router.get(
    "/{user_id}",
    response_model=UserResponse,
)
def user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Admins may view any user; everyone else may only view themselves.

    Other users' IDs return 404 (not 403) so the endpoint cannot be used to
    enumerate which user IDs exist. The check happens before any lookup.
    """
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return get_user(db, user_id)

@router.delete("/{user_id}")
def remove_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin=Depends(admin_required),
):
    """Admin only: delete a user. Admins cannot delete themselves."""
    if admin.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot delete their own account.",
        )

    delete_user(db, user_id)

    return {
        "message": "User deleted successfully",
    }
