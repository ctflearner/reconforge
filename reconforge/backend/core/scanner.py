"""Scan orchestrator — runs modules, collects results, triggers validation + correlation."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.config import settings
from backend.core.validator import Validator
from backend.core.correlator import Correlator
from backend.database import SessionLocal
from backend.models import (
    Asset,
    Finding,
    ModuleResult,
    Scan,
    ScanStatus,
    Severity,
    ValidationStatus,
)
from backend.modules import ALL_MODULES, get_modules_for_target
from backend.modules.base import BaseModule, ModuleFinding, ModuleAsset

logger = logging.getLogger(__name__)


class ScanEngine:
    def __init__(self) -> None:
        self.validator = Validator()
        self.correlator = Correlator()
        self._cancel_event: asyncio.Event | None = None

    async def run_scan(
        self,
        scan_id: int,
        progress_callback: Callable | None = None,
    ) -> None:
        db = SessionLocal()
        self._cancel_event = asyncio.Event()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

            await self._notify(progress_callback, scan_id, "running", 0, None, "Starting scan...")

            # Determine modules to run
            if scan.enabled_modules:
                modules_to_run = {
                    name: ALL_MODULES[name]
                    for name in scan.enabled_modules
                    if name in ALL_MODULES
                }
            else:
                modules_to_run = get_modules_for_target(scan.target_type.value)

            total = len(modules_to_run)
            if total == 0:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            # Build scan context shared across modules
            scan_context: dict[str, Any] = {
                "scan_id": scan_id,
                "target_type": scan.target_type.value,
                "target_value": scan.target_value,
                "file_path": scan.file_path,
                "config": scan.config_overrides or {},
                "discovered_assets": [],
            }

            # Run modules with concurrency limit
            sem = asyncio.Semaphore(settings.max_concurrent_modules)
            completed = 0
            all_findings: list[tuple[str, ModuleFinding]] = []
            all_assets: list[ModuleAsset] = []

            async def _run_module(name: str, cls: type[BaseModule]) -> None:
                nonlocal completed
                if self._cancel_event.is_set():
                    return

                async with sem:
                    module = cls()

                    # Skip if API key required but not configured
                    if not module.api_key_available():
                        logger.info("Skipping %s — API key %s not configured", name, module.requires_api_key)
                        self._save_module_result(db, scan_id, name, "skipped",
                                                  error=f"API key '{module.requires_api_key}' not configured")
                        completed += 1
                        return

                    scan.current_module = module.display_name
                    db.commit()

                    await self._notify(
                        progress_callback, scan_id, "running",
                        int(completed / total * 80),
                        module.display_name,
                        f"Running {module.display_name}...",
                    )

                    start = time.time()
                    try:
                        result = await asyncio.wait_for(
                            module.run(scan.target_value, scan_context, progress_callback),
                            timeout=module.timeout,
                        )
                    except asyncio.TimeoutError:
                        logger.warning("Module %s timed out after %ds", name, module.timeout)
                        self._save_module_result(db, scan_id, name, "timeout",
                                                  duration=time.time() - start,
                                                  error=f"Timed out after {module.timeout}s")
                        completed += 1
                        return
                    except Exception as exc:
                        logger.exception("Module %s failed", name)
                        self._save_module_result(db, scan_id, name, "error",
                                                  duration=time.time() - start,
                                                  error=str(exc)[:2000])
                        completed += 1
                        return

                    duration = time.time() - start

                    # Store module result
                    self._save_module_result(
                        db, scan_id, name, "completed",
                        duration=duration,
                        findings_count=len(result.findings),
                        assets_count=len(result.assets),
                        raw_output=result.raw_output,
                    )

                    for f in result.findings:
                        all_findings.append((name, f))
                    all_assets.extend(result.assets)

                    # Feed discovered assets back to context for later modules
                    for a in result.assets:
                        scan_context["discovered_assets"].append({
                            "type": a.asset_type.value,
                            "value": a.value,
                            "metadata": a.metadata,
                        })

                    completed += 1
                    logger.info("Module %s completed in %.1fs — %d findings, %d assets",
                                name, duration, len(result.findings), len(result.assets))

            # Execute all modules concurrently (bounded by semaphore)
            tasks = [_run_module(name, cls) for name, cls in modules_to_run.items()]
            await asyncio.gather(*tasks, return_exceptions=True)

            if self._cancel_event.is_set():
                scan.status = ScanStatus.CANCELLED
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            # --- Phase 2: Validation ---
            scan.status = ScanStatus.VALIDATING
            db.commit()
            await self._notify(progress_callback, scan_id, "validating", 82, None, "Validating findings...")

            validated_findings = []
            if settings.enable_validation:
                for module_name, finding in all_findings:
                    is_valid = await self.validator.validate(
                        finding, scan.target_value, scan.target_type.value, module_name
                    )
                    validated_findings.append((module_name, finding, is_valid))
            else:
                validated_findings = [(m, f, True) for m, f in all_findings]

            # Save findings to DB
            for module_name, finding, is_valid in validated_findings:
                db_finding = Finding(
                    scan_id=scan_id,
                    module_name=module_name,
                    title=finding.title,
                    description=finding.description,
                    severity=Severity(finding.severity.value),
                    category=finding.category,
                    evidence=finding.evidence,
                    raw_data=finding.raw_data,
                    impact=finding.impact,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id,
                    cvss_score=finding.cvss_score,
                    owasp_category=finding.owasp_category,
                    confidence=finding.confidence,
                    validation_status=(
                        ValidationStatus.CONFIRMED if is_valid
                        else ValidationStatus.FALSE_POSITIVE
                    ),
                    validation_details=(
                        "Validated by automated checks"
                        if is_valid
                        else "Flagged as potential false positive by validation engine"
                    ),
                )
                db.add(db_finding)

            # Save assets
            for asset in all_assets:
                db.add(Asset(
                    scan_id=scan_id,
                    asset_type=asset.asset_type.value,
                    value=asset.value,
                    metadata_=asset.metadata,
                    source_module="multi",
                ))

            db.commit()

            # --- Phase 3: Correlation ---
            scan.status = ScanStatus.CORRELATING
            db.commit()
            await self._notify(progress_callback, scan_id, "correlating", 92, None, "Cross-correlating findings...")

            await self.correlator.correlate(scan_id, db)

            # --- Finalize ---
            confirmed = (
                db.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .filter(Finding.validation_status != ValidationStatus.FALSE_POSITIVE)
                .all()
            )
            scan.total_findings = len(confirmed)
            scan.critical_count = sum(1 for f in confirmed if f.severity == Severity.CRITICAL)
            scan.high_count = sum(1 for f in confirmed if f.severity == Severity.HIGH)
            scan.medium_count = sum(1 for f in confirmed if f.severity == Severity.MEDIUM)
            scan.low_count = sum(1 for f in confirmed if f.severity == Severity.LOW)
            scan.info_count = sum(1 for f in confirmed if f.severity == Severity.INFO)
            scan.risk_score = self._calculate_risk_score(confirmed)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress_pct = 100
            scan.current_module = None
            db.commit()

            # --- Phase 4: Save results to disk ---
            await self._notify(progress_callback, scan_id, "saving", 98, None, "Saving results to disk...")
            self._save_results_to_disk(scan_id, db)

            await self._notify(progress_callback, scan_id, "completed", 100, None,
                               f"Scan complete — {scan.total_findings} confirmed findings")
            logger.info("Scan %d completed — %d findings", scan_id, scan.total_findings)

        except Exception as exc:
            logger.exception("Scan %d failed", scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)[:2000]
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def cancel(self) -> None:
        if self._cancel_event:
            self._cancel_event.set()

    def _save_module_result(self, db: Session, scan_id: int, name: str, status: str, *,
                            duration: float = 0, findings_count: int = 0, assets_count: int = 0,
                            raw_output: dict | None = None, error: str | None = None) -> None:
        db.add(ModuleResult(
            scan_id=scan_id,
            module_name=name,
            status=status,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_secs=duration,
            findings_count=findings_count,
            assets_count=assets_count,
            raw_output=raw_output or {},
            error=error,
        ))
        db.commit()

    def _save_results_to_disk(self, scan_id: int, db: Session) -> None:
        """Save all scan results as JSON/MD files to data/results/{scan_id}/."""
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return

            result_dir = Path(settings.results_dir) / str(scan_id)
            result_dir.mkdir(parents=True, exist_ok=True)

            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
            modules = db.query(ModuleResult).filter(ModuleResult.scan_id == scan_id).all()
            from backend.models import Correlation
            correlations = db.query(Correlation).filter(Correlation.scan_id == scan_id).all()

            confirmed = [f for f in findings if f.validation_status != ValidationStatus.FALSE_POSITIVE]
            false_pos = [f for f in findings if f.validation_status == ValidationStatus.FALSE_POSITIVE]

            # 1. scan_info.json — scan metadata
            scan_info = {
                "scan_id": scan.id,
                "name": scan.name,
                "target_type": scan.target_type.value,
                "target_value": scan.target_value,
                "status": scan.status.value,
                "risk_score": scan.risk_score,
                "total_findings": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count,
                "false_positives": len(false_pos),
                "total_assets": len(assets),
                "started_at": str(scan.started_at) if scan.started_at else None,
                "completed_at": str(scan.completed_at) if scan.completed_at else None,
                "created_at": str(scan.created_at),
            }
            (result_dir / "scan_info.json").write_text(
                json.dumps(scan_info, indent=2), encoding="utf-8"
            )

            # 2. findings.json — all confirmed findings
            findings_data = []
            for f in confirmed:
                findings_data.append({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category,
                    "module": f.module_name,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "owasp_category": f.owasp_category,
                    "confidence": f.confidence,
                    "validation_status": f.validation_status.value,
                    "raw_data": f.raw_data,
                })
            (result_dir / "findings.json").write_text(
                json.dumps(findings_data, indent=2, default=str), encoding="utf-8"
            )

            # 3. false_positives.json — rejected findings for review
            if false_pos:
                fp_data = [{
                    "id": f.id, "title": f.title, "severity": f.severity.value,
                    "module": f.module_name, "reason": f.validation_details,
                } for f in false_pos]
                (result_dir / "false_positives.json").write_text(
                    json.dumps(fp_data, indent=2, default=str), encoding="utf-8"
                )

            # 4. assets.json — all discovered assets
            assets_data = {}
            for a in assets:
                assets_data.setdefault(a.asset_type, []).append({
                    "value": a.value,
                    "source": a.source_module,
                    "alive": a.is_alive,
                    "metadata": a.metadata_,
                })
            (result_dir / "assets.json").write_text(
                json.dumps(assets_data, indent=2, default=str), encoding="utf-8"
            )

            # 5. correlations.json — attack chains
            if correlations:
                corr_data = [{
                    "title": c.title,
                    "description": c.description,
                    "chain_type": c.chain_type,
                    "severity": c.combined_severity.value if c.combined_severity else None,
                    "cvss": c.combined_cvss,
                    "finding_ids": c.source_findings,
                } for c in correlations]
                (result_dir / "correlations.json").write_text(
                    json.dumps(corr_data, indent=2, default=str), encoding="utf-8"
                )

            # 6. modules.json — module execution details
            mod_data = [{
                "name": m.module_name,
                "status": m.status,
                "duration_secs": m.duration_secs,
                "findings_count": m.findings_count,
                "assets_count": m.assets_count,
                "error": m.error,
                "raw_output": m.raw_output if m.raw_output else None,
            } for m in modules]
            (result_dir / "modules.json").write_text(
                json.dumps(mod_data, indent=2, default=str), encoding="utf-8"
            )

            # 7. summary.md — human-readable summary
            lines = [
                f"# ReconForge Scan Results — {scan.name}",
                "",
                f"**Target:** `{scan.target_value}`  ",
                f"**Type:** {scan.target_type.value}  ",
                f"**Risk Score:** {scan.risk_score:.0f}/100  ",
                f"**Scan Date:** {scan.completed_at}  ",
                "",
                "## Findings Summary",
                "",
                f"| Severity | Count |",
                f"|----------|-------|",
                f"| Critical | {scan.critical_count} |",
                f"| High     | {scan.high_count} |",
                f"| Medium   | {scan.medium_count} |",
                f"| Low      | {scan.low_count} |",
                f"| Info     | {scan.info_count} |",
                f"| **Total** | **{scan.total_findings}** |",
                f"| False Positives (filtered) | {len(false_pos)} |",
                "",
                "## Top Findings",
                "",
            ]
            for i, f in enumerate(confirmed[:20], 1):
                lines.append(f"{i}. **[{f.severity.value.upper()}]** {f.title}")
                lines.append(f"   - Module: {f.module_name} | Category: {f.category}")
                if f.cvss_score:
                    lines.append(f"   - CVSS: {f.cvss_score}")
                lines.append("")

            if correlations:
                lines.append("## Attack Chains")
                lines.append("")
                for c in correlations:
                    sev = c.combined_severity.value.upper() if c.combined_severity else "N/A"
                    lines.append(f"- **[{sev}]** {c.title}: {c.description}")
                lines.append("")

            lines.append("## Files in This Directory")
            lines.append("")
            lines.append("| File | Description |")
            lines.append("|------|-------------|")
            lines.append("| `scan_info.json` | Scan metadata and summary |")
            lines.append("| `findings.json` | All confirmed findings with evidence |")
            lines.append("| `assets.json` | All discovered assets grouped by type |")
            lines.append("| `correlations.json` | Attack chain correlations |")
            lines.append("| `modules.json` | Module execution details + raw output |")
            lines.append("| `false_positives.json` | Rejected findings for manual review |")
            lines.append("| `summary.md` | This file |")
            lines.append("")
            lines.append(f"*Generated by ReconForge on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")

            (result_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")

            logger.info("Scan %d results saved to %s", scan_id, result_dir)

        except Exception as exc:
            logger.warning("Failed to save results to disk for scan %d: %s", scan_id, exc)

    def _calculate_risk_score(self, findings: list[Finding]) -> float:
        if not findings:
            return 0.0
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        score = sum(weights.get(f.severity.value, 0) * f.confidence for f in findings)
        return min(100.0, round(score, 1))

    async def _notify(self, cb: Callable | None, scan_id: int, status: str,
                      pct: int, module: str | None, msg: str) -> None:
        if cb:
            try:
                await cb({
                    "scan_id": scan_id,
                    "status": status,
                    "progress_pct": pct,
                    "current_module": module,
                    "message": msg,
                })
            except Exception:
                pass
