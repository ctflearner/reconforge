"""Dashboard and module info endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Finding, Scan, ScanStatus, Severity
from backend.modules import ALL_MODULES
from backend.schemas import DashboardStats, ModuleInfo, ScanResponse

router = APIRouter(tags=["dashboard"])


@router.get("/api/dashboard", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()
    active_scans = (
        db.query(Scan)
        .filter(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.VALIDATING, ScanStatus.CORRELATING]))
        .count()
    )

    total_findings = db.query(Finding).count()
    critical_findings = db.query(Finding).filter(Finding.severity == Severity.CRITICAL).count()
    high_findings = db.query(Finding).filter(Finding.severity == Severity.HIGH).count()

    recent = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return DashboardStats(
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        recent_scans=recent,
    )


@router.get("/api/modules", response_model=list[ModuleInfo])
def list_modules():
    result = []
    for name, cls in ALL_MODULES.items():
        inst = cls()
        info = inst.info()
        result.append(ModuleInfo(
            name=info["name"],
            display_name=info["display_name"],
            description=info["description"],
            target_types=info["target_types"],
            category=info["category"],
            requires_api_key=info.get("requires_api_key"),
            api_key_configured=info.get("api_key_configured", True),
            enabled=True,
        ))
    return result
