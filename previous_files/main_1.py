"""
main.py
────────────────────────────────────────────────────────────────────────────────
Production-ready FastAPI server for the APK Security Analysis pipeline.

Exposes a single POST /analyze endpoint that:
  1. Accepts an APK file upload
  2. Streams it safely to a temp file (no full-file RAM buffering)
  3. Delegates analysis to apk_extractor.run_extraction_async()
  4. Returns the structured JSON report
  5. Guarantees temp file deletion via BackgroundTasks

Run with:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from apk_extractor import run_extraction_async

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# Maximum accepted upload size: 150 MB. Enforced before any disk write.
MAX_UPLOAD_BYTES: int = 150 * 1024 * 1024

# Read chunk size when streaming UploadFile to disk.
# 1 MB keeps memory overhead flat regardless of file size.
STREAM_CHUNK_SIZE: int = 1024 * 1024  # 1 MB

# Only accept files that claim to be APKs. A motivated attacker can spoof this,
# but it stops accidental mis-uploads immediately.
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.android.package-archive",
        "application/octet-stream",  # many HTTP clients send this for .apk
        "application/zip",           # APKs are ZIP archives; some clients detect this
    }
)


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan (startup / shutdown hooks)
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Log startup and shutdown events for operational visibility."""
    logger.info("APK Analyzer API starting up …")
    yield
    logger.info("APK Analyzer API shut down cleanly.")


# ──────────────────────────────────────────────────────────────────────────────
# Application factory
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="APK Security Analyzer",
    description=(
        "Statically decompiles an Android APK and returns a structured "
        "security report covering permissions, exported components, and "
        "hardcoded secrets."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Permissive for local development / mobile app connectivity.
# Tighten allow_origins to specific domains before deploying to production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# Background cleanup helper
# ──────────────────────────────────────────────────────────────────────────────

def _delete_temp_file(path: Path) -> None:
    """
    Silently remove *path* from disk.

    Registered as a BackgroundTask so it runs after the HTTP response has been
    sent to the client — the client never waits for the filesystem operation.
    Errors are logged but never re-raised, as the response has already been
    committed at this point.
    """
    try:
        path.unlink(missing_ok=True)
        logger.info("Temp file deleted: %s", path)
    except OSError as exc:
        # Non-fatal: log and move on. The OS will eventually reclaim tmp space.
        logger.warning("Could not delete temp file %s: %s", path, exc)


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health", status_code=status.HTTP_200_OK, tags=["ops"])
async def health_check() -> dict[str, str]:
    """Lightweight liveness probe for load balancers and container orchestrators."""
    return {"status": "ok"}


@app.post(
    "/analyze",
    status_code=status.HTTP_200_OK,
    tags=["analysis"],
    summary="Upload an APK file and receive a security analysis report.",
    response_description="Structured JSON report from the extraction pipeline.",
)
async def analyze_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile,
) -> JSONResponse:
    """
    Accept an APK upload, run static security analysis, and return the report.

    ### Flow
    1. **Validate** content-type and filename extension.
    2. **Stream** the upload to a named temp file in chunks — memory usage is
       capped at `STREAM_CHUNK_SIZE` (1 MB) regardless of APK size.
    3. **Enforce** the `MAX_UPLOAD_BYTES` size limit during streaming so
       oversized files are rejected before they fully land on disk.
    4. **Analyze** via `run_extraction_async()` (runs in a thread pool so the
       event loop is never blocked).
    5. **Schedule** temp file deletion as a `BackgroundTask` — guaranteed to
       run after the response is sent, even if analysis raised an exception.
    6. **Return** the extractor's JSON report verbatim.
    """

    # ── 1. Validate filename / extension ─────────────────────────────────────
    filename = file.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .apk files are accepted.",
        )

    # ── 2. Validate declared content-type ────────────────────────────────────
    # file.content_type may be None for some clients — treat None as permissive.
    if file.content_type and file.content_type not in ALLOWED_CONTENT_TYPES:
        logger.warning(
            "Unexpected content-type '%s' for upload '%s' — proceeding cautiously.",
            file.content_type,
            filename,
        )
        # Warn but don't reject: many clients (e.g. curl) send wrong MIME types.

    logger.info("Received upload: filename=%s content_type=%s", filename, file.content_type)

    # ── 3. Stream upload to a named temp file ─────────────────────────────────
    # NamedTemporaryFile with delete=False gives us a stable path we control.
    # The file is created with a .apk suffix so apktool infers format correctly.
    tmp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".apk",
            delete=False,          # we manage deletion ourselves via BackgroundTasks
            prefix="apk_upload_",
        ) as tmp:
            tmp_path = Path(tmp.name)
            bytes_written = 0

            # Stream in chunks — never loads the full file into RAM
            while True:
                chunk = await file.read(STREAM_CHUNK_SIZE)
                if not chunk:
                    break

                bytes_written += len(chunk)

                # Enforce upload size cap mid-stream to avoid filling the disk
                if bytes_written > MAX_UPLOAD_BYTES:
                    # Register cleanup before raising so the partial file is removed
                    background_tasks.add_task(_delete_temp_file, tmp_path)
                    logger.warning(
                        "Upload '%s' exceeded size limit (%d MB). Aborting.",
                        filename,
                        MAX_UPLOAD_BYTES // (1024 * 1024),
                    )
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"File exceeds the maximum allowed size of "
                            f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
                        ),
                    )

                tmp.write(chunk)

        logger.info(
            "Upload streamed to disk: path=%s size_bytes=%d",
            tmp_path,
            bytes_written,
        )

    except HTTPException:
        # Re-raise HTTP exceptions (size limit, etc.) without wrapping them
        raise

    except Exception as exc:
        # Unexpected I/O error during streaming
        if tmp_path:
            background_tasks.add_task(_delete_temp_file, tmp_path)
        logger.exception("Failed to write upload to disk: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file. Please try again.",
        )

    # ── 4. Register cleanup BEFORE analysis — runs regardless of outcome ──────
    # BackgroundTasks are executed after the response is sent, so this covers:
    #   • Successful analysis
    #   • Extractor raising an exception (caught below and turned into 500)
    background_tasks.add_task(_delete_temp_file, tmp_path)

    # ── 5. Run extraction ─────────────────────────────────────────────────────
    try:
        logger.info("Starting extraction for: %s", tmp_path)
        report: dict = await run_extraction_async(tmp_path)
        logger.info(
            "Extraction complete for '%s' — %d permissions, %d secrets found.",
            filename,
            len(report.get("permissions", [])),
            len(report.get("secrets", [])),
        )

    except Exception as exc:
        logger.exception("Extraction pipeline failed for '%s': %s", filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Extraction failed: {exc!s}",
        )

    # ── 6. Return the report verbatim ─────────────────────────────────────────
    # JSONResponse avoids a second Pydantic serialization pass on an already-
    # typed dict, keeping the response payload exactly as the extractor emits it.
    return JSONResponse(content=report, status_code=status.HTTP_200_OK)


# ──────────────────────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    """
    Catch-all for any exception not already converted to an HTTPException.
    Prevents raw tracebacks from leaking to the client in production.
    """
    logger.exception("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal error occurred."},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Dev entry-point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,           # auto-reload on code change (dev only)
        log_level="info",
    )
