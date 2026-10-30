"""
CyberShield AI
Global Exception Handlers
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

logger = logging.getLogger("cybershield")

# Only these keys are ever returned or logged. Pydantic's "input" and "ctx"
# keys can contain the submitted value (e.g. a password) or exception
# objects, so they are dropped.
_SAFE_ERROR_KEYS = ("type", "loc", "msg")

def _sanitize_errors(errors: list[dict]) -> list[dict]:
    return [
        {key: error[key] for key in _SAFE_ERROR_KEYS if key in error}
        for error in errors
    ]

def register_exception_handlers(app: FastAPI):
    """
    Register global exception handlers.
    """

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ):
        errors = _sanitize_errors(exc.errors())

        # Log field locations and error types only - never messages or input.
        logger.warning(
            "Validation error on %s %s: %s",
            request.method,
            request.url.path,
            [(error.get("loc"), error.get("type")) for error in errors],
        )

        return JSONResponse(
            status_code=422,
            content={
                "success": False,
                "message": "ValidationError",
                "errors": errors,
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ):
        logger.exception(
            "Unhandled exception on %s %s",
            request.method,
            request.url.path,
        )

        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Internal Server Error",
                "detail": "An unexpected error occurred.",
            },
        )
