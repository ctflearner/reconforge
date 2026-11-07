"""Domain intelligence modules — WHOIS, subdomain enumeration, live host probing."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from backend.modules.base import (
    AssetType,
    BaseModule,
    FindingSeverity,
    ModuleAsset,
    ModuleFinding,
    ModuleResult,
)
from backend.config import settings

logger = logging.getLogger(__name__)


def _extract_domain(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/")[0].split(":")[0]


def _base_domain(domain: str) -> str:
    """Return the registrable domain (simple heuristic)."""
    parts = domain.split(".")
    if len(parts) > 2 and parts[-1] in ("uk", "au", "jp", "br", "za") and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


# ---------------------------------------------------------------------------
# WhoisModule
# ---------------------------------------------------------------------------

class WhoisModule(BaseModule):
    @property
    def name(self) -> str:
        return "whois"

    @property
    def display_name(self) -> str:
        return "WHOIS Lookup"

    @property
    def description(self) -> str:
        return "WHOIS lookup — registrar, dates, nameservers, registrant info; flags new/expiring domains"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Domain Intelligence"

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _base_domain(_extract_domain(target))
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}

        whois_data = await self._whois_lookup(domain)
        if whois_data is None:
            return ModuleResult(error=f"WHOIS lookup failed for {domain}")

        raw["whois"] = whois_data

        assets.append(ModuleAsset(
            asset_type=AssetType.DOMAIN,
            value=domain,
            metadata=whois_data,
        ))

        # Registrar
        registrar = whois_data.get("registrar", "Unknown")
        nameservers = whois_data.get("nameservers", [])
        for ns in nameservers:
            assets.append(ModuleAsset(
                asset_type=AssetType.DNS_RECORD,
                value=ns,
                metadata={"type": "NS", "domain": domain},
            ))

        # Registrant info
        registrant_name = whois_data.get("registrant_name", "")
        registrant_org = whois_data.get("registrant_org", "")
        registrant_email = whois_data.get("registrant_email", "")
        if registrant_email and "@" in registrant_email:
            assets.append(ModuleAsset(
                asset_type=AssetType.EMAIL,
                value=registrant_email,
                metadata={"source": "whois", "role": "registrant"},
            ))
        if registrant_name:
            assets.append(ModuleAsset(
                asset_type=AssetType.PERSON,
                value=registrant_name,
                metadata={"source": "whois", "org": registrant_org},
            ))

        # Check domain age
        creation_date = whois_data.get("creation_date")
        if creation_date:
            try:
                if isinstance(creation_date, str):
                    # Try common formats
                    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                        try:
                            creation_date = datetime.strptime(creation_date, fmt)
                            break
                        except ValueError:
                            continue
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
                    if age_days < 90:
                        findings.append(ModuleFinding(
                            title="Newly Registered Domain",
                            description=f"{domain} was registered {age_days} days ago ({creation_date.strftime('%Y-%m-%d')}). New domains are often used for phishing or fraud.",
                            severity=FindingSeverity.MEDIUM,
                            category="Domain Intelligence",
                            evidence=f"Creation date: {creation_date}, Age: {age_days} days",
                            impact="New domains have little reputation and may indicate phishing or transient infrastructure.",
                            remediation="Verify domain legitimacy if interacting with it.",
                            confidence=0.85,
                        ))
            except Exception:
                pass

        # Check expiry
        expiry_date = whois_data.get("expiry_date") or whois_data.get("expiration_date")
        if expiry_date:
            try:
                if isinstance(expiry_date, str):
                    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                        try:
                            expiry_date = datetime.strptime(expiry_date, fmt)
                            break
                        except ValueError:
                            continue
                if isinstance(expiry_date, datetime):
                    days_left = (expiry_date.replace(tzinfo=None) - datetime.now()).days
                    if days_left < 30:
                        findings.append(ModuleFinding(
                            title="Domain Expiring Soon",
                            description=f"{domain} expires in {days_left} days ({expiry_date.strftime('%Y-%m-%d')}). Expired domains can be re-registered by attackers.",
                            severity=FindingSeverity.MEDIUM,
                            category="Domain Intelligence",
                            evidence=f"Expiry date: {expiry_date}, Days left: {days_left}",
                            impact="If the domain expires, attackers could register it to intercept traffic or impersonate the brand.",
                            remediation="Renew the domain registration promptly.",
                            confidence=0.9,
                        ))
            except Exception:
                pass

        # Privacy protection
        privacy_indicators = ("privacy", "redacted", "data protected", "whoisguard", "contact privacy")
        whois_str = json.dumps(whois_data).lower()
        if any(ind in whois_str for ind in privacy_indicators):
            findings.append(ModuleFinding(
                title="WHOIS Privacy Protection Enabled",
                description=f"{domain} uses WHOIS privacy protection — registrant info is masked.",
                severity=FindingSeverity.INFO,
                category="Domain Intelligence",
                evidence="Privacy-related keywords found in WHOIS data",
                confidence=0.85,
            ))

        # Summary
        evidence_lines = [
            f"Registrar: {registrar}",
            f"Creation: {whois_data.get('creation_date', 'N/A')}",
            f"Expiry: {whois_data.get('expiry_date', whois_data.get('expiration_date', 'N/A'))}",
            f"Nameservers: {', '.join(nameservers) if nameservers else 'N/A'}",
            f"Registrant: {registrant_org or registrant_name or 'N/A'}",
        ]
        findings.append(ModuleFinding(
            title="WHOIS Summary",
            description=f"WHOIS data retrieved for {domain}.",
            severity=FindingSeverity.INFO,
            category="Domain Intelligence",
            evidence="\n".join(evidence_lines),
            confidence=1.0,
        ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _whois_lookup(self, domain: str) -> dict[str, Any] | None:
        # Try python-whois library first
        try:
            import whois as pywhois
            w = pywhois.whois(domain)
            data: dict[str, Any] = {}
            for attr in ("registrar", "creation_date", "expiration_date", "name_servers",
                         "status", "emails", "name", "org", "country"):
                val = getattr(w, attr, None)
                if val is not None:
                    if isinstance(val, list) and val:
                        val = val[0] if len(val) == 1 else val
                    if isinstance(val, datetime):
                        val = val.strftime("%Y-%m-%d")
                    data[attr] = val
            data["registrant_name"] = getattr(w, "name", "")
            data["registrant_org"] = getattr(w, "org", "")
            data["registrant_email"] = ""
            emails = getattr(w, "emails", None)
            if emails:
                data["registrant_email"] = emails[0] if isinstance(emails, list) else emails
            ns = getattr(w, "name_servers", None)
            data["nameservers"] = [str(n).lower() for n in ns] if ns else []
            data["expiry_date"] = data.get("expiration_date", "")
            return data
        except Exception as exc:
            logger.debug("python-whois failed for %s: %s, trying CLI", domain, exc)

        # Fallback: whois CLI
        stdout, stderr, rc = await self._run_command(["whois", domain], timeout=30)
        if rc != 0 or not stdout:
            return None

        data = {"raw": stdout}
        for line in stdout.splitlines():
            lower = line.lower().strip()
            if "registrar:" in lower:
                data["registrar"] = line.split(":", 1)[1].strip()
            elif "creation date:" in lower or "created:" in lower:
                data["creation_date"] = line.split(":", 1)[1].strip()
            elif "expir" in lower and "date" in lower:
                data["expiry_date"] = line.split(":", 1)[1].strip()
            elif "name server:" in lower or "nserver:" in lower:
                ns = line.split(":", 1)[1].strip().lower()
                data.setdefault("nameservers", []).append(ns)
            elif "registrant name:" in lower:
                data["registrant_name"] = line.split(":", 1)[1].strip()
            elif "registrant organization:" in lower:
                data["registrant_org"] = line.split(":", 1)[1].strip()

        data.setdefault("nameservers", [])
        data.setdefault("registrant_name", "")
        data.setdefault("registrant_org", "")
        data.setdefault("registrant_email", "")
        return data


# ---------------------------------------------------------------------------
# SubdomainEnumModule
# ---------------------------------------------------------------------------

class SubdomainEnumModule(BaseModule):
    @property
    def name(self) -> str:
        return "subdomain_enum"

    @property
    def display_name(self) -> str:
        return "Subdomain Enumeration"

    @property
    def description(self) -> str:
        return "Multi-source passive subdomain enum — crt.sh, VirusTotal, SecurityTrails, HackerTarget, AlienVault OTX, RapidDNS"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Domain Intelligence"

    @property
    def timeout(self) -> int:
        return 300

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _base_domain(_extract_domain(target))
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain, "sources": {}}

        all_subs: set[str] = set()

        # Run all sources concurrently
        tasks = [
            self._crtsh(domain),
            self._hackertarget(domain),
            self._alienvault(domain),
            self._rapiddns(domain),
        ]
        if settings.virustotal_api_key:
            tasks.append(self._virustotal(domain))
        if settings.securitytrails_api_key:
            tasks.append(self._securitytrails(domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        source_names = ["crt.sh", "hackertarget", "alienvault", "rapiddns"]
        if settings.virustotal_api_key:
            source_names.append("virustotal")
        if settings.securitytrails_api_key:
            source_names.append("securitytrails")

        for src_name, result in zip(source_names, results):
            if isinstance(result, Exception):
                raw["sources"][src_name] = {"error": str(result)}
                continue
            subs = result or set()
            raw["sources"][src_name] = {"count": len(subs)}
            all_subs.update(subs)
            if progress_callback:
                await progress_callback(f"{src_name}: {len(subs)} subdomains")

        # Deduplicate and normalize
        normalized: set[str] = set()
        for sub in all_subs:
            sub = sub.strip().lower().rstrip(".")
            if sub and sub.endswith(domain) and len(sub) <= 253:
                normalized.add(sub)

        # Enforce max
        normalized = set(list(normalized)[:settings.max_subdomains])

        for sub in sorted(normalized):
            assets.append(ModuleAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=sub,
                metadata={"domain": domain, "source": "passive_enum"},
            ))

        raw["total_unique"] = len(normalized)

        findings.append(ModuleFinding(
            title=f"Subdomain Enumeration — {len(normalized)} Subdomains Found",
            description=f"Passive enumeration discovered {len(normalized)} unique subdomains for {domain} across {len(source_names)} sources.",
            severity=FindingSeverity.INFO,
            category="Domain Intelligence",
            evidence="\n".join(sorted(normalized)[:50]) + (f"\n... and {len(normalized)-50} more" if len(normalized) > 50 else ""),
            impact="Subdomains expand the attack surface and may host vulnerable or forgotten services.",
            confidence=0.9,
        ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _crtsh(self, domain: str) -> set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await self._http_get(url, timeout=30)
        subs: set[str] = set()
        if resp.get("status") != 200:
            return subs
        try:
            entries = json.loads(resp["body"])
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        subs.add(name)
        except Exception:
            pass
        return subs

    async def _virustotal(self, domain: str) -> set[str]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
        headers = {"x-apikey": settings.virustotal_api_key}
        subs: set[str] = set()
        resp = await self._http_get(url, headers=headers)
        if resp.get("status") != 200:
            return subs
        try:
            data = json.loads(resp["body"])
            for item in data.get("data", []):
                sub = item.get("id", "")
                if sub:
                    subs.add(sub)
        except Exception:
            pass
        return subs

    async def _securitytrails(self, domain: str) -> set[str]:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": settings.securitytrails_api_key}
        subs: set[str] = set()
        resp = await self._http_get(url, headers=headers)
        if resp.get("status") != 200:
            return subs
        try:
            data = json.loads(resp["body"])
            for sub in data.get("subdomains", []):
                subs.add(f"{sub}.{domain}")
        except Exception:
            pass
        return subs

    async def _hackertarget(self, domain: str) -> set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subs: set[str] = set()
        resp = await self._http_get(url, timeout=20)
        if resp.get("status") != 200:
            return subs
        for line in resp["body"].splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                subs.add(parts[0].strip().lower())
        return subs

    async def _alienvault(self, domain: str) -> set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subs: set[str] = set()
        resp = await self._http_get(url, timeout=20)
        if resp.get("status") != 200:
            return subs
        try:
            data = json.loads(resp["body"])
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(domain):
                    subs.add(hostname.lower())
        except Exception:
            pass
        return subs

    async def _rapiddns(self, domain: str) -> set[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        subs: set[str] = set()
        resp = await self._http_get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
        if resp.get("status") != 200:
            return subs
        # Parse table rows
        matches = re.findall(r"<td>([a-zA-Z0-9._-]+\." + re.escape(domain) + r")</td>", resp["body"])
        for m in matches:
            subs.add(m.lower())
        return subs


# ---------------------------------------------------------------------------
# LiveHostModule
# ---------------------------------------------------------------------------

class LiveHostModule(BaseModule):
    @property
    def name(self) -> str:
        return "live_host"

    @property
    def display_name(self) -> str:
        return "Live Host Probing"

    @property
    def description(self) -> str:
        return "Probe discovered subdomains with HTTP/HTTPS — record status, title, server, redirects"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Domain Intelligence"

    @property
    def timeout(self) -> int:
        return 600

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _base_domain(_extract_domain(target))
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}

        # Get subdomains from scan_context or just probe the target
        subdomains = scan_context.get("subdomains", [])
        if not subdomains:
            subdomains = [domain]
            # Also add www
            subdomains.append(f"www.{domain}")

        # Limit to prevent abuse
        subdomains = subdomains[:200]
        live_hosts: list[dict[str, Any]] = []

        sem = asyncio.Semaphore(20)

        async def probe(host: str) -> dict[str, Any] | None:
            async with sem:
                result: dict[str, Any] = {"host": host}
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    resp = await self._http_get(url, timeout=10)
                    if resp.get("status", 0) > 0:
                        result["scheme"] = scheme
                        result["status"] = resp["status"]
                        result["url"] = resp.get("url", url)
                        result["server"] = resp.get("headers", {}).get("server", "")
                        # Extract title
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.get("body", ""), re.IGNORECASE | re.DOTALL)
                        result["title"] = title_match.group(1).strip()[:200] if title_match else ""
                        # Check redirect
                        final_url = resp.get("url", url)
                        result["redirected"] = final_url != url
                        result["final_url"] = final_url
                        return result
                return None

        tasks = [probe(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception) or res is None:
                continue
            live_hosts.append(res)
            assets.append(ModuleAsset(
                asset_type=AssetType.URL,
                value=res["url"],
                metadata={
                    "status": res["status"],
                    "title": res["title"],
                    "server": res["server"],
                    "redirected": res["redirected"],
                },
            ))

        raw["live_hosts"] = live_hosts
        raw["total_probed"] = len(subdomains)
        raw["total_live"] = len(live_hosts)

        evidence_lines = []
        for h in live_hosts[:30]:
            line = f"[{h['status']}] {h['url']}"
            if h["title"]:
                line += f" — {h['title']}"
            if h["server"]:
                line += f" (Server: {h['server']})"
            evidence_lines.append(line)
        if len(live_hosts) > 30:
            evidence_lines.append(f"... and {len(live_hosts)-30} more")

        findings.append(ModuleFinding(
            title=f"Live Host Probing — {len(live_hosts)}/{len(subdomains)} Hosts Alive",
            description=f"Probed {len(subdomains)} subdomains and found {len(live_hosts)} responding to HTTP/HTTPS.",
            severity=FindingSeverity.INFO,
            category="Domain Intelligence",
            evidence="\n".join(evidence_lines),
            confidence=1.0,
        ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)
