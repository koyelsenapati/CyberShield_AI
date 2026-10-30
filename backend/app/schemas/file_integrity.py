from datetime import datetime

from pydantic import BaseModel, ConfigDict

class FileIntegrityScanResponse(BaseModel):
    id: int
    user_id: int
    file_path: str
    file_hash: str
    algorithm: str
    status: str
    result: str | None = None
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

class FileIntegrityResponse(BaseModel):
    message: str
    scan: FileIntegrityScanResponse
