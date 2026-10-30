from pathlib import Path
from urllib.parse import quote_plus

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"

class Settings(BaseSettings):
    # DATABASE_URL is supported for CI/tests/deployment platforms.
    # When it is absent, the MySQL fields below are used.
    DATABASE_URL: str | None = None

    DB_HOST: str | None = None
    DB_PORT: int | None = None
    DB_USER: str | None = None
    DB_PASSWORD: str | None = None
    DB_NAME: str | None = None

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Root directory for the file-integrity feature. Each user may only hash
    # files inside <FILE_INTEGRITY_BASE_DIR>/<their user id>/. Defaults to
    # backend/file_integrity_data.
    FILE_INTEGRITY_BASE_DIR: str | None = None

    VT_API_KEY: str | None = None
    VT_TIMEOUT_SECONDS: int = 15

    OPENAI_API_KEY: str | None = None
    OPENAI_MODEL: str = "gpt-5"
    OPENAI_TIMEOUT_SECONDS: int = 60
    OPENAI_MAX_OUTPUT_TOKENS: int = 800

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_database_configuration(self):
        if self.DATABASE_URL:
            return self

        required = {
            "DB_HOST": self.DB_HOST,
            "DB_PORT": self.DB_PORT,
            "DB_USER": self.DB_USER,
            "DB_PASSWORD": self.DB_PASSWORD,
            "DB_NAME": self.DB_NAME,
        }
        missing = [name for name, value in required.items() if value in (None, "")]
        if missing:
            raise ValueError(
                "Database configuration missing. Set DATABASE_URL or: "
                + ", ".join(missing)
            )
        return self

    @property
    def file_integrity_base_dir(self) -> Path:
        return Path(
            self.FILE_INTEGRITY_BASE_DIR
            or (BASE_DIR / "file_integrity_data")
        )

    @property
    def database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL

        password = quote_plus(self.DB_PASSWORD or "")
        return (
            "mysql+pymysql://"
            f"{self.DB_USER}:{password}"
            f"@{self.DB_HOST}:{self.DB_PORT}"
            f"/{self.DB_NAME}"
        )

    # ব্যাকওয়ার্ড কম্প্যাটিবিলিটির জন্য প্রপার্টি যোগ করা হলো 
    # যাতে কোডের অন্য কোথাও VIRUSTOTAL_API_KEY কল করলে তা VT_API_KEY রিটার্ন করে
    @property
    def VIRUSTOTAL_API_KEY(self) -> str | None:
        return self.VT_API_KEY

settings = Settings()