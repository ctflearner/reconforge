"""ORM models for ReconForge."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from backend.database import Base


class TargetType(str, enum.Enum):
    URL = "url"
    IP = "ip"
    APK = "apk"
    THICK_CLIENT = "thick_client"
    AD = "active_directory"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    VALIDATING = "validating"
    CORRELATING = "correlating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(500), nullable=False)
    target_type = Column(Enum(TargetType), nullable=False)
    target_value = Column(String(2000), nullable=False)
    file_path = Column(String(2000), nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress_pct = Column(Integer, default=0)
    current_module = Column(String(200), nullable=True)
    enabled_modules = Column(JSON, default=list)
    config_overrides = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    module_results = relationship("ModuleResult", back_populates="scan", cascade="all, delete-orphan")
    correlations = relationship("Correlation", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module_name = Column(String(200), nullable=False)
    title = Column(String(1000), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    category = Column(String(200), nullable=False)
    evidence = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe_id = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    owasp_category = Column(String(200), nullable=True)
    validation_status = Column(Enum(ValidationStatus), default=ValidationStatus.PENDING)
    validation_details = Column(Text, nullable=True)
    false_positive_reason = Column(String(500), nullable=True)
    confidence = Column(Float, default=0.8)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_type = Column(String(100), nullable=False)
    value = Column(String(2000), nullable=False)
    metadata_ = Column("metadata", JSON, default=dict)
    source_module = Column(String(200), nullable=True)
    is_alive = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="assets")


class ModuleResult(Base):
    __tablename__ = "module_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module_name = Column(String(200), nullable=False)
    status = Column(String(50), default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_secs = Column(Float, nullable=True)
    findings_count = Column(Integer, default=0)
    assets_count = Column(Integer, default=0)
    raw_output = Column(JSON, default=dict)
    error = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="module_results")


class Correlation(Base):
    __tablename__ = "correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(1000), nullable=False)
    description = Column(Text, nullable=False)
    source_findings = Column(JSON, default=list)
    chain_type = Column(String(100), nullable=True)
    combined_severity = Column(Enum(Severity), nullable=True)
    combined_cvss = Column(Float, nullable=True)

    scan = relationship("Scan", back_populates="correlations")
