"""Scan CRUD endpoints — create, list, detail, start, cancel, delete."""
from __future__ import annotations

import asyncio
import os
import shutil
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.config import settings
from backend.core.scanner import ScanEngine
from backend.database import get_db
from backend.models import (
    Asset,
    Correlation,
    Finding,
    ModuleResult,
    Scan,
    ScanStatus,
    TargetType,
)
from backend.schemas import ScanCreate, ScanDetail, ScanResponse
from backend.api.ws import progress_callback_for

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

# Track running engines so we can cancel them
_running_engines: dict[int, ScanEngine] = {}


def _scan_or_404(scan_id: int, db: Session) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return scan


# ── POST /api/scans ─────────────────────────────────────────────────────
@router.post("", response_model=ScanResponse, status_code=201)
@router.post("/", response_model=ScanResponse, status_code=201, include_in_schema=False)
async def create_scan(
    # JSON body fields (for url/ip/ad targets)
    name: str | None = Form(default=None),
    target_type: str | None = Form(default=None),
    target_value: str | None = Form(default=None),
    enabled_modules: str | None = Form(default=None),   # JSON string list
    config_overrides: str | None = Form(default=None),   # JSON string dict
    # File upload (for apk / thick_client)
    file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    """Create a new scan.

    For URL/IP/AD: send form fields (or JSON body via separate endpoint).
    For APK/thick_client: send multipart with file + target_type.
    """
    import json as _json

    if not target_type:
        raise HTTPException(422, "target_type is required")

    try:
        tt = TargetType(target_type)
    except ValueError:
        raise HTTPException(422, f"Invalid target_type: {target_type}")

    file_path: str | None = None

    # Handle file upload for APK / thick client
    if tt in (TargetType.APK, TargetType.THICK_CLIENT):
        if not file:
            raise HTTPException(422, f"File upload required for target_type={tt.value}")
        # Save uploaded file
        ext = Path(file.filename or "upload").suffix or ".bin"
        fname = f"{uuid.uuid4().hex}{ext}"
        upload_path = Path(settings.uploads_dir) / fname
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        content = await file.read()
        if len(content) > settings.max_upload_size_mb * 1024 * 1024:
            raise HTTPException(413, f"File exceeds {settings.max_upload_size_mb}MB limit")
        upload_path.write_bytes(content)
        file_path = str(upload_path)
        tv = file.filename or fname
    else:
        if not target_value:
            raise HTTPException(422, "target_value is required for non-file targets")
        tv = target_value

    # Parse JSON list/dict from form
    modules_list: list[str] = []
    if enabled_modules:
        try:
            modules_list = _json.loads(enabled_modules)
        except Exception:
            modules_list = [m.strip() for m in enabled_modules.split(",") if m.strip()]

    overrides: dict = {}
    if config_overrides:
        try:
            overrides = _json.loads(config_overrides)
        except Exception:
            overrides = {}

    scan = Scan(
        name=name or f"Scan: {tv[:80]}",
        target_type=tt,
        target_value=tv,
        file_path=file_path,
        status=ScanStatus.PENDING,
        enabled_modules=modules_list,
        config_overrides=overrides,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/json", response_model=ScanResponse, status_code=201)
async def create_scan_json(body: ScanCreate, db: Session = Depends(get_db)):
    """Create scan from JSON body (URL/IP/AD only — no file upload)."""
    if body.target_type in (TargetType.APK, TargetType.THICK_CLIENT):
        raise HTTPException(422, "Use multipart upload for APK/thick_client targets")

    scan = Scan(
        name=body.name or f"Scan: {body.target_value[:80]}",
        target_type=body.target_type,
        target_value=body.target_value,
        status=ScanStatus.PENDING,
        enabled_modules=body.enabled_modules,
        config_overrides=body.config_overrides,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ── GET /api/scans ───────────────────────────────────────────────────────
@router.get("", response_model=list[ScanResponse])
@router.get("/", response_model=list[ScanResponse], include_in_schema=False)
def list_scans(
    offset: int = 0,
    limit: int = 50,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Scan)
    if status:
        try:
            q = q.filter(Scan.status == ScanStatus(status))
        except ValueError:
            pass
    return q.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()


# ── GET /api/scans/{id} ─────────────────────────────────────────────────
@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = _scan_or_404(scan_id, db)
    return scan


# ── POST /api/scans/{id}/start ───────────────────────────────────────────
@router.post("/{scan_id}/start", response_model=ScanResponse)
async def start_scan(scan_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = _scan_or_404(scan_id, db)
    if scan.status not in (ScanStatus.PENDING, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(409, f"Cannot start scan in {scan.status.value} state")

    scan.status = ScanStatus.PENDING
    scan.error_message = None
    scan.progress_pct = 0
    db.commit()
    db.refresh(scan)

    engine = ScanEngine()
    _running_engines[scan_id] = engine

    async def _run():
        cb = await progress_callback_for(scan_id)
        try:
            await engine.run_scan(scan_id, progress_callback=cb)
        finally:
            _running_engines.pop(scan_id, None)

    background_tasks.add_task(_run)
    return scan


# ── POST /api/scans/{id}/cancel ──────────────────────────────────────────
@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = _scan_or_404(scan_id, db)
    engine = _running_engines.get(scan_id)
    if engine:
        engine.cancel()
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


# ── DELETE /api/scans/{id} ───────────────────────────────────────────────
@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = _scan_or_404(scan_id, db)
    # Cancel if running
    engine = _running_engines.pop(scan_id, None)
    if engine:
        engine.cancel()
    # Remove uploaded file
    if scan.file_path and os.path.exists(scan.file_path):
        try:
            os.remove(scan.file_path)
        except OSError:
            pass
    # Remove report files
    report_dir = Path(settings.reports_dir) / str(scan_id)
    if report_dir.exists():
        shutil.rmtree(report_dir, ignore_errors=True)
    # Remove saved result files
    results_dir = Path(settings.results_dir) / str(scan_id)
    if results_dir.exists():
        shutil.rmtree(results_dir, ignore_errors=True)
    # Cascade delete handles findings, assets, module_results, correlations
    db.delete(scan)
    db.commit()
