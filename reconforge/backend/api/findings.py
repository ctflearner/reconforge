"""Findings endpoints — list, detail, validate, stats."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Finding, Severity, ValidationStatus
from backend.schemas import FindingResponse

router = APIRouter(prefix="/api/findings", tags=["findings"])


# ── GET /api/findings ────────────────────────────────────────────────────
@router.get("", response_model=list[FindingResponse])
@router.get("/", response_model=list[FindingResponse], include_in_schema=False)
def list_findings(
    scan_id: int | None = None,
    severity: str | None = None,
    category: str | None = None,
    module_name: str | None = None,
    validation_status: str | None = None,
    sort_by: str = "severity",
    offset: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if scan_id is not None:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        try:
            q = q.filter(Finding.severity == Severity(severity))
        except ValueError:
            pass
    if category:
        q = q.filter(Finding.category == category)
    if module_name:
        q = q.filter(Finding.module_name == module_name)
    if validation_status:
        try:
            q = q.filter(Finding.validation_status == ValidationStatus(validation_status))
        except ValueError:
            pass

    # Sort
    severity_order = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    if sort_by == "severity":
        # SQLite doesn't support FIELD(), so order by created_at desc as proxy
        # and do severity ordering in code for better results
        q = q.order_by(Finding.created_at.desc())
        results = q.offset(offset).limit(limit).all()
        results.sort(key=lambda f: severity_order.get(f.severity.value, 5))
        return results
    elif sort_by == "cvss":
        q = q.order_by(Finding.cvss_score.desc().nullslast())
    else:
        q = q.order_by(Finding.created_at.desc())

    return q.offset(offset).limit(limit).all()


# ── GET /api/findings/stats ──────────────────────────────────────────────
@router.get("/stats")
def finding_stats(scan_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(Finding)
    if scan_id is not None:
        q = q.filter(Finding.scan_id == scan_id)

    total = q.count()

    # By severity
    by_severity = {}
    for sev in Severity:
        by_severity[sev.value] = q.filter(Finding.severity == sev).count()

    # By category
    cat_rows = (
        q.with_entities(Finding.category, func.count(Finding.id))
        .group_by(Finding.category)
        .all()
    )
    by_category = {cat: cnt for cat, cnt in cat_rows}

    # By module
    mod_rows = (
        q.with_entities(Finding.module_name, func.count(Finding.id))
        .group_by(Finding.module_name)
        .all()
    )
    by_module = {mod: cnt for mod, cnt in mod_rows}

    # By validation status
    val_rows = (
        q.with_entities(Finding.validation_status, func.count(Finding.id))
        .group_by(Finding.validation_status)
        .all()
    )
    by_validation = {v.value if v else "unknown": cnt for v, cnt in val_rows}

    # Top CWEs
    cwe_rows = (
        q.filter(Finding.cwe_id.isnot(None))
        .with_entities(Finding.cwe_id, func.count(Finding.id))
        .group_by(Finding.cwe_id)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
        .all()
    )
    top_cwes = {cwe: cnt for cwe, cnt in cwe_rows}

    return {
        "total": total,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_module": by_module,
        "by_validation": by_validation,
        "top_cwes": top_cwes,
    }


# ── GET /api/findings/{id} ──────────────────────────────────────────────
@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, f"Finding {finding_id} not found")
    return f


# ── PATCH /api/findings/{id}/validate ────────────────────────────────────
@router.patch("/{finding_id}/validate", response_model=FindingResponse)
def validate_finding(
    finding_id: int,
    status: str = Query(..., description="confirmed or false_positive"),
    reason: str = Query(default="", description="Reason for validation decision"),
    db: Session = Depends(get_db),
):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, f"Finding {finding_id} not found")

    try:
        vs = ValidationStatus(status)
    except ValueError:
        raise HTTPException(422, f"Invalid status: {status}. Use: confirmed, false_positive, uncertain")

    f.validation_status = vs
    f.validation_details = reason or f"Manually set to {vs.value}"
    if vs == ValidationStatus.FALSE_POSITIVE:
        f.false_positive_reason = reason

    db.commit()
    db.refresh(f)

    # Update scan counts
    scan = f.scan
    if scan:
        confirmed = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .filter(Finding.validation_status != ValidationStatus.FALSE_POSITIVE)
            .all()
        )
        scan.total_findings = len(confirmed)
        scan.critical_count = sum(1 for x in confirmed if x.severity == Severity.CRITICAL)
        scan.high_count = sum(1 for x in confirmed if x.severity == Severity.HIGH)
        scan.medium_count = sum(1 for x in confirmed if x.severity == Severity.MEDIUM)
        scan.low_count = sum(1 for x in confirmed if x.severity == Severity.LOW)
        scan.info_count = sum(1 for x in confirmed if x.severity == Severity.INFO)
        db.commit()

    return f
