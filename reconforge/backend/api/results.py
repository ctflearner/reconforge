"""Results management — list, browse, download, and delete saved scan results."""
from __future__ import annotations

import json
import logging
import shutil
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/results", tags=["results"])


class ResultFolder(BaseModel):
    scan_id: int
    path: str
    files: list[str]
    total_size_bytes: int
    scan_name: str | None = None
    target: str | None = None
    risk_score: float | None = None
    findings_count: int | None = None
    scan_date: str | None = None


class ResultFile(BaseModel):
    name: str
    size_bytes: int
    is_json: bool
    is_markdown: bool


def _results_root() -> Path:
    return Path(settings.results_dir)


def _scan_dir(scan_id: int) -> Path:
    d = _results_root() / str(scan_id)
    if not d.exists():
        raise HTTPException(404, f"No results for scan {scan_id}")
    return d


def _read_scan_info(scan_dir: Path) -> dict | None:
    info_file = scan_dir / "scan_info.json"
    if info_file.exists():
        try:
            return json.loads(info_file.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


@router.get("", response_model=list[ResultFolder])
def list_results():
    """List all saved scan result folders."""
    root = _results_root()
    if not root.exists():
        return []

    folders = []
    for d in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not d.is_dir():
            continue
        try:
            scan_id = int(d.name)
        except ValueError:
            continue

        files = [f.name for f in d.iterdir() if f.is_file()]
        total_size = sum(f.stat().st_size for f in d.iterdir() if f.is_file())

        info = _read_scan_info(d)

        folders.append(ResultFolder(
            scan_id=scan_id,
            path=str(d),
            files=sorted(files),
            total_size_bytes=total_size,
            scan_name=info.get("name") if info else None,
            target=info.get("target_value") if info else None,
            risk_score=info.get("risk_score") if info else None,
            findings_count=info.get("total_findings") if info else None,
            scan_date=info.get("completed_at") if info else None,
        ))

    return folders


@router.get("/{scan_id}", response_model=list[ResultFile])
def list_result_files(scan_id: int):
    """List files in a scan's result folder."""
    d = _scan_dir(scan_id)
    files = []
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        files.append(ResultFile(
            name=f.name,
            size_bytes=f.stat().st_size,
            is_json=f.suffix == ".json",
            is_markdown=f.suffix == ".md",
        ))
    return files


@router.get("/{scan_id}/{filename}")
def get_result_file(scan_id: int, filename: str):
    """Download or view a specific result file."""
    d = _scan_dir(scan_id)
    fpath = d / filename

    if not fpath.exists() or not fpath.is_file():
        raise HTTPException(404, f"File not found: {filename}")

    # Prevent path traversal
    if not fpath.resolve().is_relative_to(d.resolve()):
        raise HTTPException(403, "Access denied")

    if fpath.suffix == ".json":
        return FileResponse(str(fpath), media_type="application/json", filename=filename)
    elif fpath.suffix == ".md":
        return FileResponse(str(fpath), media_type="text/markdown", filename=filename)
    else:
        return FileResponse(str(fpath), filename=filename)


@router.get("/{scan_id}/download/zip")
def download_results_zip(scan_id: int):
    """Download all result files as a ZIP archive."""
    d = _scan_dir(scan_id)

    info = _read_scan_info(d)
    zip_name = f"reconforge_scan_{scan_id}"
    if info and info.get("name"):
        safe_name = info["name"][:40].replace(" ", "_").replace("/", "_")
        zip_name = f"reconforge_{safe_name}_{scan_id}"

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in d.iterdir():
            if f.is_file():
                zf.write(f, arcname=f"{zip_name}/{f.name}")
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={zip_name}.zip"},
    )


@router.delete("/{scan_id}", status_code=204)
def delete_results(scan_id: int):
    """Delete a scan's result folder permanently."""
    d = _scan_dir(scan_id)
    shutil.rmtree(d, ignore_errors=True)
    logger.info("Deleted results for scan %d", scan_id)


@router.delete("/{scan_id}/{filename}", status_code=204)
def delete_result_file(scan_id: int, filename: str):
    """Delete a single file from a scan's result folder."""
    d = _scan_dir(scan_id)
    fpath = d / filename

    if not fpath.exists() or not fpath.is_file():
        raise HTTPException(404, f"File not found: {filename}")
    if not fpath.resolve().is_relative_to(d.resolve()):
        raise HTTPException(403, "Access denied")

    fpath.unlink()
    logger.info("Deleted result file %s for scan %d", filename, scan_id)

    # Remove folder if empty
    remaining = list(d.iterdir())
    if not remaining:
        d.rmdir()
