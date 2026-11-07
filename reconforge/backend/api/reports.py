"""Report generation endpoint — HTML, PDF, JSON, Markdown, CSV."""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import Asset, Correlation, Finding, ModuleResult, Scan, Severity, ValidationStatus
from backend.schemas import ReportRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _gather_report_data(scan_id: int, db: Session, include_raw: bool = False) -> dict:
    """Collect all data needed for a report."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.value, 5))

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    modules = db.query(ModuleResult).filter(ModuleResult.scan_id == scan_id).all()
    correlations = db.query(Correlation).filter(Correlation.scan_id == scan_id).all()

    confirmed = [f for f in findings if f.validation_status != ValidationStatus.FALSE_POSITIVE]
    false_positives = [f for f in findings if f.validation_status == ValidationStatus.FALSE_POSITIVE]

    # Group findings by severity
    by_severity: dict[str, list] = {s.value: [] for s in Severity}
    for f in confirmed:
        by_severity[f.severity.value].append(f)

    # Group assets by type
    by_asset_type: dict[str, list] = {}
    for a in assets:
        by_asset_type.setdefault(a.asset_type, []).append(a)

    # Module stats
    module_stats = []
    for m in modules:
        module_stats.append({
            "name": m.module_name,
            "status": m.status,
            "duration": m.duration_secs or 0,
            "findings_count": m.findings_count,
            "assets_count": m.assets_count,
            "error": m.error,
        })

    total_duration = sum(m.duration_secs or 0 for m in modules)

    return {
        "scan": scan,
        "findings": confirmed,
        "all_findings": findings,
        "false_positives": false_positives,
        "by_severity": by_severity,
        "assets": assets,
        "by_asset_type": by_asset_type,
        "modules": module_stats,
        "correlations": correlations,
        "total_duration": total_duration,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "include_raw": include_raw,
    }


def _generate_html(data: dict) -> str:
    """Generate HTML report using inline template."""
    scan = data["scan"]
    findings = data["findings"]
    by_severity = data["by_severity"]
    assets = data["assets"]
    correlations = data["correlations"]
    modules = data["modules"]

    def _severity_color(sev: str) -> str:
        return {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#16a34a", "info": "#6b7280",
        }.get(sev, "#6b7280")

    def _risk_color(score: float) -> str:
        if score >= 75:
            return "#dc2626"
        if score >= 50:
            return "#ea580c"
        if score >= 25:
            return "#d97706"
        return "#16a34a"

    def _esc(s: str | None) -> str:
        if not s:
            return ""
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev_color = _severity_color(f.severity.value)
        evidence_block = ""
        if f.evidence:
            evidence_block = f'<div class="evidence"><h4>Evidence</h4><pre><code>{_esc(f.evidence)}</code></pre></div>'
        raw_block = ""
        if data["include_raw"] and f.raw_data:
            raw_block = f'<div class="evidence"><h4>Raw Data</h4><pre><code>{_esc(json.dumps(f.raw_data, indent=2))}</code></pre></div>'

        findings_html += f"""
        <div class="finding" id="finding-{f.id}">
            <div class="finding-header">
                <span class="severity-badge" style="background:{sev_color}">{f.severity.value.upper()}</span>
                <span class="finding-title">{i}. {_esc(f.title)}</span>
                <span class="finding-meta">{_esc(f.module_name)} | {_esc(f.category)}{f' | CVSS {f.cvss_score}' if f.cvss_score else ''}{f' | {f.cwe_id}' if f.cwe_id else ''}</span>
            </div>
            <div class="finding-body">
                <p>{_esc(f.description)}</p>
                {evidence_block}
                {'<div class="impact"><h4>Impact</h4><p>' + _esc(f.impact) + '</p></div>' if f.impact else ''}
                {'<div class="remediation"><h4>Remediation</h4><p>' + _esc(f.remediation) + '</p></div>' if f.remediation else ''}
                {raw_block}
                <div class="finding-footer">
                    <span>Confidence: {f.confidence:.0%}</span>
                    <span>Status: {f.validation_status.value}</span>
                </div>
            </div>
        </div>"""

    # Correlations HTML
    corr_html = ""
    for c in correlations:
        sev_color = _severity_color(c.combined_severity.value) if c.combined_severity else "#6b7280"
        corr_html += f"""
        <div class="correlation">
            <div class="finding-header">
                <span class="severity-badge" style="background:{sev_color}">{c.combined_severity.value.upper() if c.combined_severity else 'N/A'}</span>
                <span class="finding-title">{_esc(c.title)}</span>
                {f'<span class="finding-meta">CVSS {c.combined_cvss}</span>' if c.combined_cvss else ''}
            </div>
            <p>{_esc(c.description)}</p>
            <p class="chain-info">Chain type: {_esc(c.chain_type or 'N/A')} | Related findings: {len(c.source_findings or [])}</p>
        </div>"""

    # Assets HTML
    asset_html = ""
    for atype, alist in data["by_asset_type"].items():
        rows = ""
        for a in alist[:100]:
            meta = json.dumps(a.metadata_ or {}, indent=0) if a.metadata_ else ""
            rows += f"<tr><td>{_esc(a.value)}</td><td>{_esc(a.source_module or 'N/A')}</td><td>{'Alive' if a.is_alive else 'Dead'}</td><td class='meta'>{_esc(meta[:200])}</td></tr>"
        asset_html += f"""
        <h3>{_esc(atype)} ({len(alist)})</h3>
        <table><thead><tr><th>Value</th><th>Source</th><th>Status</th><th>Metadata</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    # Modules HTML
    mod_rows = ""
    for m in modules:
        status_class = "completed" if m["status"] == "completed" else ("error" if m["status"] in ("error", "timeout") else "skipped")
        mod_rows += f"<tr class='{status_class}'><td>{_esc(m['name'])}</td><td>{m['status']}</td><td>{m['duration']:.1f}s</td><td>{m['findings_count']}</td><td>{m['assets_count']}</td><td>{_esc(m['error'] or '')}</td></tr>"

    risk_color = _risk_color(scan.risk_score)

    # Load template
    template_path = Path(__file__).parent.parent / "templates" / "report.html"
    if template_path.exists():
        template = template_path.read_text()
    else:
        template = _FALLBACK_TEMPLATE

    # Replace placeholders
    html = template
    html = html.replace("{{scan_name}}", _esc(scan.name))
    html = html.replace("{{target_type}}", scan.target_type.value)
    html = html.replace("{{target_value}}", _esc(scan.target_value))
    html = html.replace("{{scan_status}}", scan.status.value)
    html = html.replace("{{risk_score}}", f"{scan.risk_score:.0f}")
    html = html.replace("{{risk_color}}", risk_color)
    html = html.replace("{{total_findings}}", str(len(findings)))
    html = html.replace("{{critical_count}}", str(len(by_severity.get("critical", []))))
    html = html.replace("{{high_count}}", str(len(by_severity.get("high", []))))
    html = html.replace("{{medium_count}}", str(len(by_severity.get("medium", []))))
    html = html.replace("{{low_count}}", str(len(by_severity.get("low", []))))
    html = html.replace("{{info_count}}", str(len(by_severity.get("info", []))))
    html = html.replace("{{false_positive_count}}", str(len(data["false_positives"])))
    html = html.replace("{{total_assets}}", str(len(assets)))
    html = html.replace("{{total_modules}}", str(len(modules)))
    html = html.replace("{{total_duration}}", f"{data['total_duration']:.1f}")
    html = html.replace("{{started_at}}", str(scan.started_at or "N/A"))
    html = html.replace("{{completed_at}}", str(scan.completed_at or "N/A"))
    html = html.replace("{{generated_at}}", data["generated_at"])
    html = html.replace("{{findings_html}}", findings_html)
    html = html.replace("{{correlations_html}}", corr_html)
    html = html.replace("{{assets_html}}", asset_html)
    html = html.replace("{{modules_html}}", mod_rows)
    html = html.replace("{{correlation_count}}", str(len(correlations)))

    return html


def _generate_markdown(data: dict) -> str:
    """Generate Markdown report."""
    scan = data["scan"]
    lines = [
        f"# Security Assessment Report: {scan.name}",
        "",
        f"**Target:** {scan.target_value}  ",
        f"**Type:** {scan.target_type.value}  ",
        f"**Risk Score:** {scan.risk_score:.0f}/100  ",
        f"**Status:** {scan.status.value}  ",
        f"**Generated:** {data['generated_at']}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This assessment identified **{len(data['findings'])}** confirmed findings ",
        f"across **{len(data['modules'])}** analysis modules in **{data['total_duration']:.1f}s**.",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.capitalize()} | {len(data['by_severity'].get(sev, []))} |")

    lines += ["", "---", "", "## Findings", ""]
    for i, f in enumerate(data["findings"], 1):
        lines.append(f"### {i}. [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f"**Module:** {f.module_name} | **Category:** {f.category}")
        if f.cvss_score:
            lines.append(f"**CVSS:** {f.cvss_score}")
        if f.cwe_id:
            lines.append(f"**CWE:** {f.cwe_id}")
        lines.append("")
        lines.append(f.description)
        if f.evidence:
            lines += ["", "**Evidence:**", "```", f.evidence, "```"]
        if f.impact:
            lines += ["", f"**Impact:** {f.impact}"]
        if f.remediation:
            lines += ["", f"**Remediation:** {f.remediation}"]
        lines.append("")

    if data["correlations"]:
        lines += ["---", "", "## Attack Chains / Correlations", ""]
        for c in data["correlations"]:
            sev = c.combined_severity.value.upper() if c.combined_severity else "N/A"
            lines.append(f"### [{sev}] {c.title}")
            lines.append(f"{c.description}")
            if c.combined_cvss:
                lines.append(f"**CVSS:** {c.combined_cvss}")
            lines.append("")

    lines += ["---", "", "## Asset Inventory", ""]
    for atype, alist in data["by_asset_type"].items():
        lines.append(f"### {atype} ({len(alist)})")
        for a in alist[:50]:
            lines.append(f"- `{a.value}` (source: {a.source_module or 'N/A'})")
        lines.append("")

    lines += ["---", "", "## Module Execution Details", ""]
    lines.append("| Module | Status | Duration | Findings | Assets |")
    lines.append("|--------|--------|----------|----------|--------|")
    for m in data["modules"]:
        lines.append(f"| {m['name']} | {m['status']} | {m['duration']:.1f}s | {m['findings_count']} | {m['assets_count']} |")

    lines += [
        "", "---", "",
        "## Methodology", "",
        "This assessment was conducted using ReconForge, a multi-module OSINT and static analysis platform. ",
        "Modules executed automated reconnaissance, vulnerability analysis, and validation passes. ",
        "Findings were cross-correlated to identify attack chains. False positives were filtered ",
        "through multi-strategy validation including confidence thresholding, re-verification, ",
        "and known false-positive pattern matching.",
        "",
        "---",
        f"*Report generated by ReconForge on {data['generated_at']}*",
    ]
    return "\n".join(lines)


def _generate_json_report(data: dict) -> dict:
    """Generate JSON report."""
    scan = data["scan"]
    return {
        "report_metadata": {
            "generated_at": data["generated_at"],
            "tool": "ReconForge",
            "version": "1.0.0",
        },
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target_type": scan.target_type.value,
            "target_value": scan.target_value,
            "status": scan.status.value,
            "risk_score": scan.risk_score,
            "started_at": str(scan.started_at) if scan.started_at else None,
            "completed_at": str(scan.completed_at) if scan.completed_at else None,
        },
        "summary": {
            "total_findings": len(data["findings"]),
            "false_positives": len(data["false_positives"]),
            "total_assets": len(data["assets"]),
            "by_severity": {k: len(v) for k, v in data["by_severity"].items()},
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "module": f.module_name,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
                "owasp_category": f.owasp_category,
                "confidence": f.confidence,
                "validation_status": f.validation_status.value,
                "raw_data": f.raw_data if data["include_raw"] else None,
            }
            for f in data["findings"]
        ],
        "correlations": [
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "chain_type": c.chain_type,
                "combined_severity": c.combined_severity.value if c.combined_severity else None,
                "combined_cvss": c.combined_cvss,
                "source_findings": c.source_findings,
            }
            for c in data["correlations"]
        ],
        "assets": [
            {
                "id": a.id,
                "type": a.asset_type,
                "value": a.value,
                "source": a.source_module,
                "is_alive": a.is_alive,
                "metadata": a.metadata_,
            }
            for a in data["assets"]
        ],
        "modules": data["modules"],
    }


def _generate_csv(data: dict) -> str:
    """Generate CSV of findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Severity", "Category", "Module", "CVSS",
        "CWE", "Confidence", "Validation", "Description", "Evidence",
        "Impact", "Remediation",
    ])
    for f in data["findings"]:
        writer.writerow([
            f.id, f.title, f.severity.value, f.category, f.module_name,
            f.cvss_score or "", f.cwe_id or "", f"{f.confidence:.0%}",
            f.validation_status.value, f.description,
            (f.evidence or "")[:500], f.impact or "", f.remediation or "",
        ])
    return output.getvalue()


# ── POST /api/reports/generate ───────────────────────────────────────────
@router.post("/generate")
def generate_report(req: ReportRequest, db: Session = Depends(get_db)):
    data = _gather_report_data(req.scan_id, db, include_raw=req.include_raw)
    scan = data["scan"]
    fmt = req.format.lower()

    # Ensure report output dir
    report_dir = Path(settings.reports_dir) / str(req.scan_id)
    report_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        content = _generate_html(data)
        out = report_dir / f"{scan.name[:60].replace(' ', '_')}_report.html"
        out.write_text(content, encoding="utf-8")
        return FileResponse(str(out), media_type="text/html", filename=out.name)

    elif fmt == "md" or fmt == "markdown":
        content = _generate_markdown(data)
        out = report_dir / f"{scan.name[:60].replace(' ', '_')}_report.md"
        out.write_text(content, encoding="utf-8")
        return FileResponse(str(out), media_type="text/markdown", filename=out.name)

    elif fmt == "json":
        report_json = _generate_json_report(data)
        content = json.dumps(report_json, indent=2, default=str)
        out = report_dir / f"{scan.name[:60].replace(' ', '_')}_report.json"
        out.write_text(content, encoding="utf-8")
        return FileResponse(str(out), media_type="application/json", filename=out.name)

    elif fmt == "csv":
        content = _generate_csv(data)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=findings_{req.scan_id}.csv"},
        )

    elif fmt == "pdf":
        # Generate HTML first, return as HTML (PDF conversion requires wkhtmltopdf or weasyprint)
        content = _generate_html(data)
        out = report_dir / f"{scan.name[:60].replace(' ', '_')}_report.html"
        out.write_text(content, encoding="utf-8")
        # Try weasyprint if available
        try:
            import weasyprint
            pdf_path = report_dir / f"{scan.name[:60].replace(' ', '_')}_report.pdf"
            weasyprint.HTML(string=content).write_pdf(str(pdf_path))
            return FileResponse(str(pdf_path), media_type="application/pdf", filename=pdf_path.name)
        except ImportError:
            logger.warning("weasyprint not installed — returning HTML instead of PDF")
            return FileResponse(str(out), media_type="text/html", filename=out.name)

    else:
        raise HTTPException(422, f"Unsupported format: {fmt}. Use: html, pdf, json, md, csv")


# Fallback template if the template file doesn't exist
_FALLBACK_TEMPLATE = """<!DOCTYPE html><html><head><title>ReconForge Report</title></head>
<body><h1>{{scan_name}}</h1><p>Target: {{target_value}}</p>
<p>Risk: {{risk_score}}</p>{{findings_html}}{{correlations_html}}{{assets_html}}</body></html>"""
