"""Pydantic schemas for API request/response."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.models import ScanStatus, Severity, TargetType, ValidationStatus


# --- Scan ---
class ScanCreate(BaseModel):
    name: str = ""
    target_type: TargetType
    target_value: str
    enabled_modules: list[str] = []
    config_overrides: dict[str, Any] = {}


class ScanResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    target_type: TargetType
    target_value: str
    status: ScanStatus
    progress_pct: int
    current_module: str | None
    risk_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ScanDetail(ScanResponse):
    enabled_modules: list[str]
    config_overrides: dict[str, Any]
    error_message: str | None
    findings: list[FindingResponse] = []
    assets: list[AssetResponse] = []
    module_results: list[ModuleResultResponse] = []
    correlations: list[CorrelationResponse] = []


# --- Finding ---
class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_id: int
    module_name: str
    title: str
    description: str
    severity: Severity
    category: str
    evidence: str | None
    raw_data: dict[str, Any]
    impact: str | None
    remediation: str | None
    cwe_id: str | None
    cvss_score: float | None
    owasp_category: str | None
    validation_status: ValidationStatus
    validation_details: str | None
    confidence: float
    created_at: datetime


# --- Asset ---
class AssetResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_id: int
    asset_type: str
    value: str
    metadata_: dict[str, Any] = Field(default_factory=dict, alias="metadata_")
    source_module: str | None
    is_alive: bool


# --- Module Result ---
class ModuleResultResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_id: int
    module_name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    duration_secs: float | None
    findings_count: int
    assets_count: int
    error: str | None


# --- Correlation ---
class CorrelationResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_id: int
    title: str
    description: str
    source_findings: list[int]
    chain_type: str | None
    combined_severity: Severity | None
    combined_cvss: float | None


# --- Module Info ---
class ModuleInfo(BaseModel):
    name: str
    display_name: str
    description: str
    target_types: list[TargetType]
    category: str
    requires_api_key: str | None = None
    api_key_configured: bool = True
    enabled: bool = True


# --- Report ---
class ReportRequest(BaseModel):
    scan_id: int
    format: str = "html"
    include_raw: bool = False
    include_screenshots: bool = True
    branding: dict[str, str] = {}


# --- Progress (WebSocket) ---
class ScanProgress(BaseModel):
    scan_id: int
    status: str
    progress_pct: int
    current_module: str | None
    message: str = ""
    findings_so_far: int = 0


# --- Dashboard Stats ---
class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    recent_scans: list[ScanResponse]
