from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.database.database import get_db
from app.models.user import User
from app.schemas.file_integrity import FileIntegrityResponse
from app.services.file_integrity_service import start_file_scan

router = APIRouter(prefix="/file-integrity", tags=["File Integrity"])

@router.post("/", response_model=FileIntegrityResponse)
def file_integrity(
    file_path: str = Query(
        ...,
        min_length=1,
        max_length=400,
        description="Path relative to your monitored directory.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return start_file_scan(db, file_path, current_user.id)
