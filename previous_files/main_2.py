"""
main.py
────────────────────────────────────────────────────────────────────────────────
Production-ready FastAPI server for the APK Security Analysis pipeline.

Exposes a single POST /analyze endpoint that:
  1. Accepts an APK file upload
  2. Streams it safely to a temp file (no full-file RAM buffering)
  3. Delegates static analysis to apk_extractor.run_extraction_async()
  4. Maps the raw extraction data to a structured UI report via
     vulnerability_mapper.generate_report()
  5. Returns the mapped vulnerability report as JSON
  6. Guarantees temp file deletion via BackgroundTasks

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
from vulnerability_mapper import generate_report

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
        "Statically decompiles an Android APK, extracts permissions, exported "
        "components, hardcoded secrets, insecure code patterns, and signing "
        "certificate metadata, then maps all findings to a structured "
        "vulnerability report ready for frontend rendering."
    ),
    version="2.0.0",
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
    summary="Upload an APK file and receive a structured vulnerability report.",
    response_description="Mapped vulnerability report from the extraction + mapper pipeline.",
)
async def analyze_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile,
) -> JSONResponse:
    """
    Accept an APK upload, run static security analysis, map findings to a
    structured vulnerability report, and return it.

    ### Pipeline
    1. **Validate** content-type and filename extension.
    2. **Stream** the upload to a named temp file in chunks — memory usage is
       capped at `STREAM_CHUNK_SIZE` (1 MB) regardless of APK size.
    3. **Enforce** the `MAX_UPLOAD_BYTES` size limit during streaming so
       oversized files are rejected before they fully land on disk.
    4. **Extract** via `run_extraction_async()` — runs in a thread pool so the
       event loop is never blocked. Produces a raw `ExtractionReport` dict
       containing permissions, exported components, secrets, insecure code
       patterns, endpoints, and signing certificate metadata.
    5. **Map** the raw report via `generate_report()` — groups findings by
       rule, enriches each with KB metadata (title, severity, description,
       remediation), synthesises compound vulnerabilities for exported
       components and dangerous permissions, and computes summary counts.
    6. **Schedule** temp file deletion as a `BackgroundTask` — guaranteed to
       run after the response is sent, even if any stage raised an exception.
    7. **Return** the mapped `ui_report` as a `JSONResponse`.
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
    #   • Successful analysis + mapping
    #   • Any exception in either stage (caught below and turned into 500)
    background_tasks.add_task(_delete_temp_file, tmp_path)

    # ── 5. Run extraction (async, non-blocking) ───────────────────────────────
    try:
        logger.info("Starting extraction for: %s", tmp_path)
        raw_report: dict = await run_extraction_async(tmp_path)
        logger.info(
            "Extraction complete for '%s' — %d permissions, %d secrets, "
            "%d insecure patterns, %d endpoints found.",
            filename,
            len(raw_report.get("permissions", [])),
            len(raw_report.get("secrets", [])),
            len(raw_report.get("insecure_code_patterns", [])),
            len(raw_report.get("endpoints", [])),
        )

    except Exception as exc:
        logger.exception("Extraction pipeline failed for '%s': %s", filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Extraction failed: {exc!s}",
        )

    # ── 6. Map raw extraction data → structured vulnerability report ──────────
    # generate_report() is synchronous and CPU-bound (dict traversal + KB
    # lookups). It is fast enough (~milliseconds) to run directly on the event
    # loop without offloading to a thread pool.  If profiling shows it becomes
    # a bottleneck (e.g., extremely large APKs with thousands of findings),
    # wrap it in: await asyncio.to_thread(generate_report, raw_report)
    try:
        logger.info("Mapping extraction report to vulnerability report for '%s'.", filename)
        ui_report: dict = generate_report(raw_report)
        summary = ui_report.get("summary", {})
        logger.info(
            "Mapping complete for '%s' — %d vulnerabilities "
            "(CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d).",
            filename,
            summary.get("total_vulnerabilities", 0),
            summary.get("by_severity", {}).get("CRITICAL", 0),
            summary.get("by_severity", {}).get("HIGH", 0),
            summary.get("by_severity", {}).get("MEDIUM", 0),
            summary.get("by_severity", {}).get("LOW", 0),
        )

    except Exception as exc:
        logger.exception("Vulnerability mapping failed for '%s': %s", filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vulnerability mapping failed: {exc!s}",
        )

    # ── 7. Return the mapped report ───────────────────────────────────────────
    # JSONResponse bypasses Pydantic's serialisation pass — the dict is already
    # JSON-safe (all values are str / int / float / bool / list / dict).
    return JSONResponse(content=ui_report, status_code=status.HTTP_200_OK)


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
