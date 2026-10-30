import json
import logging

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.crud.file_integrity import (
    create_file_scan,
    get_latest_scan_for_path,
)
from app.engines.security_engine.file_integrity import (
    calculate_hash,
    resolve_user_file,
)

logger = logging.getLogger("cybershield")

def start_file_scan(
    db: Session,
    file_path: str,
    user_id: int,
):
    """
    Hash a file inside the user's own monitored directory and compare it with
    the user's previous scan of the same path.

    Status values (all derived from stored data, nothing assumed):
      * Baseline  - first time this path was scanned; nothing to compare to
      * Unchanged - hash equals the previous scan's hash
      * Modified  - hash differs from the previous scan's hash
    """
    try:
        user_root, resolved = resolve_user_file(
            settings.file_integrity_base_dir,
            user_id,
            file_path,
        )
        result = calculate_hash(str(resolved))
        relative_path = resolved.relative_to(user_root).as_posix()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="File not found.",
        ) from exc
    except ValueError as exc:
        # resolve_user_file / calculate_hash raise static, input-free messages.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.warning("File integrity read failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Unable to read file.",
        ) from exc

    previous = get_latest_scan_for_path(db, user_id, relative_path)

    if previous is None:
        status = "Baseline"
    elif previous.file_hash == result["hash"]:
        status = "Unchanged"
    else:
        status = "Modified"

    scan = create_file_scan(
        db,
        {
            "user_id": user_id,
            "file_path": relative_path,
            "file_hash": result["hash"],
            "algorithm": result["algorithm"],
            "status": status,
            "result": json.dumps(
                {
                    "size_bytes": result["size"],
                    "previous_scan_id": previous.id if previous else None,
                    "previous_hash": previous.file_hash if previous else None,
                }
            ),
        },
    )

    return {"message": "File Integrity Scan Completed", "scan": scan}
