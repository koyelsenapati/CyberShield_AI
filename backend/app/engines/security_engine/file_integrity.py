"""
CyberShield AI
File Integrity Checker Engine

Calculates SHA-256 hashes for files and resolves user-supplied paths safely.
"""

import hashlib
import os
from pathlib import Path

MAX_PATH_LENGTH = 400

def resolve_user_file(
    base_dir: Path,
    user_id: int,
    relative_path: str,
) -> tuple[Path, Path]:
    """
    Resolve ``relative_path`` inside ``<base_dir>/<user_id>/``.

    Returns ``(user_root, resolved_file)``. Raises ``ValueError`` (with a
    static message) for empty, absolute, NUL-containing or over-long paths and
    for anything that resolves outside the user's directory - including ``..``
    traversal and symlinks pointing elsewhere.
    """
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise ValueError("File path cannot be empty.")

    if "\x00" in relative_path or len(relative_path) > MAX_PATH_LENGTH:
        raise ValueError("Invalid file path.")

    candidate = Path(relative_path)

    if candidate.is_absolute() or candidate.root or candidate.drive:
        raise ValueError(
            "Path must be relative to your monitored directory."
        )

    user_root = (Path(base_dir) / str(int(user_id))).resolve()
    resolved = (user_root / candidate).resolve()

    if not resolved.is_relative_to(user_root):
        raise ValueError("Path is outside your monitored directory.")

    return user_root, resolved

def calculate_hash(file_path: str) -> dict:
    """
    Calculate SHA-256 hash for a file.

    Callers that accept user input must resolve the path with
    ``resolve_user_file`` first.
    """

    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be empty.")

    file_path = os.path.abspath(file_path)

    if not os.path.isfile(file_path):
        raise FileNotFoundError("File not found.")

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return {
        "file": file_path,
        "hash": sha256.hexdigest(),
        "algorithm": "SHA256",
        "status": "Success",
        "size": os.path.getsize(file_path),
    }

def check_file_exists(file_path: str) -> bool:
    """
    Check whether a file exists.
    """

    if not file_path:
        return False

    return os.path.isfile(
        os.path.abspath(file_path)
    )
