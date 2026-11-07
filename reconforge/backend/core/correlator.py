"""Cross-correlation engine — links findings across modules into attack chains."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from backend.models import Asset, Correlation, Finding, Severity

logger = logging.getLogger(__name__)


CORRELATION_RULES: list[dict[str, Any]] = [
    {
        "name": "secret_to_endpoint",
        "title": "Exposed Secret + Accessible Endpoint",
        "description": "API key or credential found alongside an accessible API endpoint — attacker can use the key directly.",
        "match": lambda findings: [
            (s, e)
            for s in findings if "secret" in s.category.lower()
            for e in findings if "endpoint" in e.category.lower()
            if _domains_overlap(s.evidence, e.evidence)
        ],
        "severity": Severity.CRITICAL,
        "cvss": 9.1,
    },
    {
        "name": "subdomain_takeover",
        "title": "Dangling Subdomain + Cloud Service",
        "description": "Subdomain points to unclaimed cloud resource — full takeover possible.",
        "match": lambda findings: [
            (s, c)
            for s in findings if s.category == "subdomain" and "NXDOMAIN" in (s.evidence or "")
            for c in findings if "cloud" in c.category.lower()
        ],
        "severity": Severity.HIGH,
        "cvss": 8.2,
    },
    {
        "name": "debug_exposed",
        "title": "Debug Mode + Public Endpoint",
        "description": "Application running in debug mode on publicly accessible endpoint — stack traces, config, and source code may be exposed.",
        "match": lambda findings: [
            (d, e)
            for d in findings if "debug" in d.title.lower() or "debuggable" in d.title.lower()
            for e in findings if e.category in ("endpoint", "port", "service")
        ],
        "severity": Severity.HIGH,
        "cvss": 7.5,
    },
    {
        "name": "weak_crypto_secret",
        "title": "Weak Cryptography + Stored Secret",
        "description": "Application uses weak crypto (MD5/DES/ECB) alongside stored secrets — encrypted data may be recoverable.",
        "match": lambda findings: [
            (c, s)
            for c in findings if "crypto" in c.category.lower() and c.severity in (Severity.HIGH, Severity.CRITICAL)
            for s in findings if "secret" in s.category.lower() or "credential" in s.category.lower()
        ],
        "severity": Severity.HIGH,
        "cvss": 7.8,
    },
    {
        "name": "exported_component_deeplink",
        "title": "Exported Component + Deep Link Handler",
        "description": "Exported Android component handles deep links — attacker can trigger internal functionality via crafted URI.",
        "match": lambda findings: [
            (e, d)
            for e in findings if e.category == "component" and "exported" in e.title.lower()
            for d in findings if e.category == "deeplink" or "scheme" in d.title.lower()
        ],
        "severity": Severity.MEDIUM,
        "cvss": 6.5,
    },
    {
        "name": "cleartext_traffic_endpoint",
        "title": "Cleartext Traffic + Sensitive Endpoint",
        "description": "Application allows cleartext HTTP traffic to endpoints handling sensitive data — MITM interception possible.",
        "match": lambda findings: [
            (c, e)
            for c in findings if "cleartext" in c.title.lower() or "http://" in (c.evidence or "")
            for e in findings if any(kw in (e.evidence or "").lower()
                                     for kw in ("auth", "login", "token", "user", "password", "payment"))
        ],
        "severity": Severity.HIGH,
        "cvss": 7.4,
    },
    {
        "name": "backup_secret",
        "title": "Backup Allowed + Sensitive Data Storage",
        "description": "Application allows backup and stores sensitive data — attacker with physical access can extract credentials.",
        "match": lambda findings: [
            (b, s)
            for b in findings if "backup" in b.title.lower() and "allow" in b.title.lower()
            for s in findings if "storage" in s.category.lower() or "secret" in s.category.lower()
        ],
        "severity": Severity.MEDIUM,
        "cvss": 5.5,
    },
    {
        "name": "spf_dmarc_email",
        "title": "Weak Email Security + Harvested Emails",
        "description": "SPF/DMARC misconfigured alongside discovered employee emails — phishing and spoofing risk.",
        "match": lambda findings: [
            (s, e)
            for s in findings if "spf" in s.title.lower() or "dmarc" in s.title.lower()
            for e in findings if e.category == "email"
            if s.severity in (Severity.MEDIUM, Severity.HIGH)
        ],
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
    },
    {
        "name": "outdated_service_cve",
        "title": "Outdated Service + Known CVE",
        "description": "Service running outdated version with known vulnerabilities — exploitation possible.",
        "match": lambda findings: [
            (s, c)
            for s in findings if s.category == "service" and "version" in s.raw_data
            for c in findings if "cve" in c.category.lower() or "CVE-" in (c.evidence or "")
        ],
        "severity": Severity.CRITICAL,
        "cvss": 9.0,
    },
    {
        "name": "webview_js_interface",
        "title": "WebView JavaScript Interface + File Access",
        "description": "WebView exposes JavaScript interface with file access enabled — potential for local file exfiltration.",
        "match": lambda findings: [
            (w, f)
            for w in findings if "javascriptinterface" in w.title.lower() or "webview" in w.category.lower()
            for f in findings if "file" in f.title.lower() and "access" in f.title.lower()
        ],
        "severity": Severity.HIGH,
        "cvss": 7.7,
    },
    {
        "name": "open_port_no_auth",
        "title": "Open Service + No Authentication",
        "description": "Network service accessible without authentication — unauthorized access possible.",
        "match": lambda findings: [
            (p, a)
            for p in findings if p.category in ("port", "service")
            for a in findings if "no auth" in a.title.lower() or "anonymous" in a.title.lower()
            if _same_host(p, a)
        ],
        "severity": Severity.HIGH,
        "cvss": 8.0,
    },
]


def _domains_overlap(ev1: str | None, ev2: str | None) -> bool:
    if not ev1 or not ev2:
        return False
    import re
    domains1 = set(re.findall(r'[\w.-]+\.[\w]+', ev1.lower()))
    domains2 = set(re.findall(r'[\w.-]+\.[\w]+', ev2.lower()))
    return bool(domains1 & domains2)


def _same_host(f1: Finding, f2: Finding) -> bool:
    h1 = f1.raw_data.get("host", "")
    h2 = f2.raw_data.get("host", "")
    return bool(h1 and h2 and h1 == h2)


class Correlator:
    async def correlate(self, scan_id: int, db: Session) -> list[Correlation]:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        if len(findings) < 2:
            return []

        correlations: list[Correlation] = []

        for rule in CORRELATION_RULES:
            try:
                matches = rule["match"](findings)
                if matches:
                    finding_ids = set()
                    for pair in matches[:10]:  # cap at 10 pairs per rule
                        for f in pair:
                            finding_ids.add(f.id)

                    corr = Correlation(
                        scan_id=scan_id,
                        title=rule["title"],
                        description=f"{rule['description']} ({len(matches)} instance(s) found)",
                        source_findings=list(finding_ids),
                        chain_type=rule["name"],
                        combined_severity=rule["severity"],
                        combined_cvss=rule["cvss"],
                    )
                    db.add(corr)
                    correlations.append(corr)
                    logger.info("Correlation found: %s (%d instances)", rule["title"], len(matches))
            except Exception as exc:
                logger.warning("Correlation rule %s failed: %s", rule["name"], exc)

        # Asset-based correlation: find assets discovered by multiple modules
        assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        asset_values: dict[str, list[Asset]] = {}
        for a in assets:
            asset_values.setdefault(a.value, []).append(a)

        multi_source = {v: lst for v, lst in asset_values.items() if len(lst) > 1}
        if multi_source:
            corr = Correlation(
                scan_id=scan_id,
                title="Cross-Module Asset Confirmation",
                description=(
                    f"{len(multi_source)} assets discovered by multiple independent modules, "
                    "increasing confidence in their validity."
                ),
                source_findings=[],
                chain_type="asset_confirmation",
                combined_severity=Severity.INFO,
                combined_cvss=None,
            )
            db.add(corr)
            correlations.append(corr)

        db.commit()
        return correlations
