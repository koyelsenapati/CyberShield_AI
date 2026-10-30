from sqlalchemy.orm import Session

from app.models.file_integrity import FileIntegrity

def create_file_scan(db: Session, data: dict):

    scan = FileIntegrity(**data)

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan

def get_file_scan(db: Session, scan_id: int, user_id: int):
    """Fetch a scan, but only if it belongs to ``user_id``."""

    return (
        db.query(FileIntegrity)
        .filter(
            FileIntegrity.id == scan_id,
            FileIntegrity.user_id == user_id,
        )
        .first()
    )

def get_latest_scan_for_path(
    db: Session,
    user_id: int,
    file_path: str,
):
    """Most recent scan of the same (user, path), used as the comparison baseline."""

    return (
        db.query(FileIntegrity)
        .filter(
            FileIntegrity.user_id == user_id,
            FileIntegrity.file_path == file_path,
        )
        .order_by(FileIntegrity.id.desc())
        .first()
    )
