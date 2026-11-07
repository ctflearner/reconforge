"""Email harvesting, SPF/DMARC/DKIM analysis, social media discovery, and breach search modules."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Callable
from urllib.parse import urlparse

from backend.config import settings
from backend.modules.base import (
    AssetType,
    BaseModule,
    FindingSeverity,
    ModuleAsset,
    ModuleFinding,
    ModuleResult,
)

logger = logging.getLogger(__name__)


def _extract_domain(target: str) -> str:
    """Extract bare domain from a URL or domain string."""
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or parsed.path.split("/")[0]
    return host.lower().strip(".")


# ---------------------------------------------------------------------------
# EmailHarvestModule
# ---------------------------------------------------------------------------

class EmailHarvestModule(BaseModule):
    """Harvest email addresses from Hunter.io, crt.sh, and on-page mailto links."""

    @property
    def name(self) -> str:
        return "email_harvest"

    @property
    def display_name(self) -> str:
        return "Email Harvesting"

    @property
    def description(self) -> str:
        return (
            "Collects email addresses from Hunter.io domain search, "
            "certificate transparency logs (crt.sh), and mailto links on the target page."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Email & Social"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}
        emails_seen: set[str] = set()
        persons_seen: set[str] = set()

        # --- Hunter.io API ---
        hunter_results: list[dict] = []
        if settings.hunter_api_key:
            if progress_callback:
                await progress_callback("Querying Hunter.io domain search...")
            try:
                url = (
                    f"https://api.hunter.io/v2/domain-search"
                    f"?domain={domain}&api_key={settings.hunter_api_key}"
                )
                resp = await self._http_get(url, timeout=30)
                if resp["status"] == 200 and not resp.get("error"):
                    body = json.loads(resp["body"])
                    hunter_emails = body.get("data", {}).get("emails", [])
                    for entry in hunter_emails:
                        email = (entry.get("value") or "").strip().lower()
                        if email and email not in emails_seen:
                            emails_seen.add(email)
                            first = entry.get("first_name", "")
                            last = entry.get("last_name", "")
                            position = entry.get("position", "")
                            meta = {"source": "hunter.io"}
                            if first or last:
                                meta["name"] = f"{first} {last}".strip()
                            if position:
                                meta["position"] = position
                            assets.append(ModuleAsset(AssetType.EMAIL, email, meta))
                            hunter_results.append(meta | {"email": email})
                            # Person asset
                            full_name = f"{first} {last}".strip()
                            if full_name and full_name not in persons_seen:
                                persons_seen.add(full_name)
                                assets.append(
                                    ModuleAsset(
                                        AssetType.PERSON,
                                        full_name,
                                        {"email": email, "position": position, "source": "hunter.io"},
                                    )
                                )
                    raw["hunter_total"] = body.get("data", {}).get("total", 0)
                else:
                    raw["hunter_error"] = resp.get("error", f"HTTP {resp['status']}")
            except Exception as exc:
                logger.warning("Hunter.io query failed: %s", exc)
                raw["hunter_error"] = str(exc)

        # --- crt.sh certificate transparency ---
        if progress_callback:
            await progress_callback("Querying crt.sh for certificate emails...")
        try:
            crt_url = f"https://crt.sh/?q=%25{domain}&output=json"
            resp = await self._http_get(crt_url, timeout=30)
            if resp["status"] == 200 and not resp.get("error"):
                crt_entries = json.loads(resp["body"])
                email_pat = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
                for entry in crt_entries if isinstance(crt_entries, list) else []:
                    for field_name in ("name_value", "common_name"):
                        text = entry.get(field_name, "")
                        for match in email_pat.findall(str(text)):
                            email = match.strip().lower()
                            if email not in emails_seen:
                                emails_seen.add(email)
                                assets.append(
                                    ModuleAsset(AssetType.EMAIL, email, {"source": "crt.sh"})
                                )
                raw["crt_entries_checked"] = len(crt_entries) if isinstance(crt_entries, list) else 0
        except Exception as exc:
            logger.warning("crt.sh query failed: %s", exc)
            raw["crt_error"] = str(exc)

        # --- Scrape page for mailto: links ---
        if progress_callback:
            await progress_callback("Scraping target page for mailto links...")
        try:
            page_url = target if "://" in target else f"https://{target}"
            resp = await self._http_get(page_url, timeout=20)
            if resp["status"] and not resp.get("error"):
                mailto_pat = re.compile(r'mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')
                for match in mailto_pat.findall(resp["body"]):
                    email = match.strip().lower()
                    if email not in emails_seen:
                        emails_seen.add(email)
                        assets.append(
                            ModuleAsset(AssetType.EMAIL, email, {"source": "mailto_link"})
                        )
                raw["page_status"] = resp["status"]
        except Exception as exc:
            logger.warning("Page scrape failed: %s", exc)
            raw["page_error"] = str(exc)

        # --- Summary finding ---
        evidence_lines = [f"Domain: {domain}", f"Total unique emails: {len(emails_seen)}"]
        if hunter_results:
            evidence_lines.append(f"Hunter.io results: {len(hunter_results)}")
            for hr in hunter_results[:20]:
                evidence_lines.append(f"  - {hr['email']} ({hr.get('name', 'N/A')}, {hr.get('position', 'N/A')})")
        if emails_seen:
            evidence_lines.append("\nAll emails:")
            for em in sorted(emails_seen):
                src = next(
                    (a.metadata.get("source", "unknown") for a in assets if a.value == em),
                    "unknown",
                )
                evidence_lines.append(f"  - {em} (source: {src})")

        findings.append(
            ModuleFinding(
                title=f"Email Addresses Discovered for {domain}",
                description=(
                    f"Identified {len(emails_seen)} unique email address(es) associated with {domain} "
                    f"via Hunter.io, certificate transparency, and page scraping."
                ),
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence="\n".join(evidence_lines),
                raw_data=raw,
                impact="Discovered emails may be used in phishing, credential stuffing, or social engineering.",
                remediation=(
                    "Limit email exposure on public pages and certificates. "
                    "Use role-based addresses (info@, support@) instead of personal addresses."
                ),
                confidence=0.9,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# SpfDmarcModule
# ---------------------------------------------------------------------------

class SpfDmarcModule(BaseModule):
    """Analyze SPF, DMARC, and DKIM records for email authentication posture."""

    @property
    def name(self) -> str:
        return "spf_dmarc"

    @property
    def display_name(self) -> str:
        return "SPF/DMARC/DKIM Analysis"

    @property
    def description(self) -> str:
        return (
            "Queries DNS for SPF, DMARC, and DKIM records and evaluates "
            "email authentication configuration strength."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Email & Social"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}

        # ---- SPF ----
        if progress_callback:
            await progress_callback("Checking SPF records...")
        spf_records = await self._resolve_dns(domain, "TXT")
        spf_txt = [r.strip('"') for r in spf_records if "v=spf1" in r.lower()]
        raw["spf_records"] = spf_txt

        if spf_txt:
            spf_value = spf_txt[0]
            assets.append(
                ModuleAsset(AssetType.DNS_RECORD, spf_value, {"type": "SPF", "domain": domain})
            )
            # Count DNS lookups (include, a, mx, ptr, exists, redirect)
            lookup_mechanisms = re.findall(
                r"\b(?:include|a|mx|ptr|exists|redirect)[:=]", spf_value.lower()
            )
            lookup_count = len(lookup_mechanisms)

            if "+all" in spf_value.lower():
                findings.append(
                    ModuleFinding(
                        title=f"SPF Record Allows All Senders ({domain})",
                        description=(
                            f"The SPF record for {domain} uses '+all', which permits any server "
                            f"to send email on behalf of the domain."
                        ),
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=f"SPF record: {spf_value}",
                        impact="Any attacker can send spoofed emails appearing to come from this domain.",
                        remediation="Change '+all' to '-all' and list only authorized senders.",
                        cwe_id="CWE-290",
                        cvss_score=7.5,
                        confidence=0.95,
                    )
                )
            elif "~all" in spf_value.lower():
                findings.append(
                    ModuleFinding(
                        title=f"SPF Softfail Policy ({domain})",
                        description=(
                            f"SPF record for {domain} uses '~all' (softfail). Some receiving servers "
                            f"may still accept spoofed mail."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=f"SPF record: {spf_value}",
                        impact="Spoofed emails may be delivered to inboxes that do not strictly enforce SPF.",
                        remediation="Upgrade to '-all' (hardfail) after verifying all legitimate senders are listed.",
                        cwe_id="CWE-290",
                        cvss_score=5.3,
                        confidence=0.9,
                    )
                )
            elif "-all" in spf_value.lower():
                findings.append(
                    ModuleFinding(
                        title=f"SPF Hardfail Configured ({domain})",
                        description=f"SPF record for {domain} uses '-all' — correctly configured.",
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        evidence=f"SPF record: {spf_value}",
                        impact="None — this is a secure configuration.",
                        remediation="No action required.",
                        confidence=0.95,
                    )
                )

            if lookup_count > 10:
                findings.append(
                    ModuleFinding(
                        title=f"SPF Record Exceeds DNS Lookup Limit ({domain})",
                        description=(
                            f"SPF record contains approximately {lookup_count} DNS lookup mechanisms, "
                            f"exceeding the RFC 7208 limit of 10. This may cause SPF validation failures."
                        ),
                        severity=FindingSeverity.LOW,
                        category=self.category,
                        evidence=f"SPF record: {spf_value}\nLookup mechanisms found: {lookup_count}",
                        impact="SPF checks may fail (PermError), causing legitimate mail to be rejected.",
                        remediation="Flatten the SPF record by replacing includes with IP ranges where possible.",
                        confidence=0.8,
                    )
                )
        else:
            findings.append(
                ModuleFinding(
                    title=f"No SPF Record Found ({domain})",
                    description=f"No SPF (TXT v=spf1) record exists for {domain}.",
                    severity=FindingSeverity.HIGH,
                    category=self.category,
                    evidence=f"DNS TXT query for {domain} returned no SPF record.",
                    impact="The domain has no sender policy; attackers can spoof emails from this domain.",
                    remediation="Publish an SPF record (e.g., 'v=spf1 include:_spf.google.com -all').",
                    cwe_id="CWE-290",
                    cvss_score=7.5,
                    confidence=0.95,
                )
            )

        # ---- DMARC ----
        if progress_callback:
            await progress_callback("Checking DMARC records...")
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = await self._resolve_dns(dmarc_domain, "TXT")
        dmarc_txt = [r.strip('"') for r in dmarc_records if "v=dmarc1" in r.lower()]
        raw["dmarc_records"] = dmarc_txt

        if dmarc_txt:
            dmarc_value = dmarc_txt[0]
            assets.append(
                ModuleAsset(AssetType.DNS_RECORD, dmarc_value, {"type": "DMARC", "domain": domain})
            )

            # Parse policy
            policy_match = re.search(r"\bp=(\w+)", dmarc_value.lower())
            policy = policy_match.group(1) if policy_match else "unknown"

            if policy == "none":
                findings.append(
                    ModuleFinding(
                        title=f"DMARC Policy Set to None ({domain})",
                        description=(
                            f"DMARC policy for {domain} is 'p=none' (monitoring only). "
                            f"Spoofed emails will still be delivered."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=f"DMARC record: {dmarc_value}",
                        impact="Email spoofing is not blocked; the policy only monitors failures.",
                        remediation="Transition to 'p=quarantine' or 'p=reject' after reviewing DMARC reports.",
                        cwe_id="CWE-290",
                        cvss_score=5.3,
                        confidence=0.9,
                    )
                )
            elif policy == "quarantine":
                findings.append(
                    ModuleFinding(
                        title=f"DMARC Quarantine Policy ({domain})",
                        description=f"DMARC policy for {domain} is 'p=quarantine' — good configuration.",
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        evidence=f"DMARC record: {dmarc_value}",
                        impact="Spoofed emails are quarantined (e.g., sent to spam).",
                        remediation="Consider upgrading to 'p=reject' for stronger enforcement.",
                        confidence=0.95,
                    )
                )
            elif policy == "reject":
                findings.append(
                    ModuleFinding(
                        title=f"DMARC Reject Policy ({domain})",
                        description=f"DMARC policy for {domain} is 'p=reject' — best practice.",
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        evidence=f"DMARC record: {dmarc_value}",
                        impact="None — spoofed emails are rejected.",
                        remediation="No action required.",
                        confidence=0.95,
                    )
                )

            # Check for reporting URIs
            has_rua = "rua=" in dmarc_value.lower()
            has_ruf = "ruf=" in dmarc_value.lower()
            if not has_rua and not has_ruf:
                findings.append(
                    ModuleFinding(
                        title=f"DMARC Missing Reporting URIs ({domain})",
                        description=(
                            f"DMARC record for {domain} has no rua or ruf reporting addresses. "
                            f"Authentication failures will not be reported."
                        ),
                        severity=FindingSeverity.LOW,
                        category=self.category,
                        evidence=f"DMARC record: {dmarc_value}",
                        impact="No visibility into email authentication failures or spoofing attempts.",
                        remediation="Add rua= and ruf= tags pointing to a DMARC reporting address.",
                        confidence=0.9,
                    )
                )
        else:
            findings.append(
                ModuleFinding(
                    title=f"No DMARC Record Found ({domain})",
                    description=f"No DMARC record exists at _dmarc.{domain}.",
                    severity=FindingSeverity.HIGH,
                    category=self.category,
                    evidence=f"DNS TXT query for _dmarc.{domain} returned no DMARC record.",
                    impact="No email authentication policy is enforced; spoofed emails will be delivered.",
                    remediation="Publish a DMARC record (e.g., 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com').",
                    cwe_id="CWE-290",
                    cvss_score=7.5,
                    confidence=0.95,
                )
            )

        # ---- DKIM ----
        if progress_callback:
            await progress_callback("Checking DKIM selectors...")
        dkim_selectors = [
            "google",
            "default",
            "selector1",
            "selector2",
        ]
        dkim_found: list[dict[str, str]] = []

        for selector in dkim_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = await self._resolve_dns(dkim_domain, "TXT")
            dkim_txt = [r.strip('"') for r in records if r.strip()]
            if dkim_txt:
                record_value = dkim_txt[0]
                dkim_found.append({"selector": selector, "record": record_value})
                assets.append(
                    ModuleAsset(
                        AssetType.DNS_RECORD,
                        record_value,
                        {"type": "DKIM", "selector": selector, "domain": domain},
                    )
                )

        raw["dkim_found"] = dkim_found

        if dkim_found:
            selector_list = ", ".join(d["selector"] for d in dkim_found)
            evidence_parts = [f"DKIM selectors found: {selector_list}"]
            for d in dkim_found:
                evidence_parts.append(f"  {d['selector']}._domainkey.{domain}: {d['record'][:120]}...")
            findings.append(
                ModuleFinding(
                    title=f"DKIM Records Found ({domain})",
                    description=(
                        f"DKIM records discovered for {len(dkim_found)} selector(s): {selector_list}."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="\n".join(evidence_parts),
                    impact="DKIM is configured, aiding email authentication.",
                    remediation="No action required.",
                    confidence=0.9,
                )
            )
        else:
            findings.append(
                ModuleFinding(
                    title=f"No DKIM Records on Common Selectors ({domain})",
                    description=(
                        f"No DKIM records found for selectors: {', '.join(dkim_selectors)}. "
                        f"The domain may use a non-standard selector."
                    ),
                    severity=FindingSeverity.LOW,
                    category=self.category,
                    evidence=f"Checked selectors: {', '.join(s + '._domainkey.' + domain for s in dkim_selectors)}",
                    impact="DKIM may not be configured, weakening email authentication.",
                    remediation="Configure DKIM signing and publish the public key in DNS.",
                    confidence=0.6,
                    validation_hint="Check additional selectors specific to the mail provider.",
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# SocialLinksModule
# ---------------------------------------------------------------------------

class SocialLinksModule(BaseModule):
    """Discover social media profiles linked from the target page."""

    @property
    def name(self) -> str:
        return "social_links"

    @property
    def display_name(self) -> str:
        return "Social Media Links"

    @property
    def description(self) -> str:
        return "Scrapes the target page for social media profile links and infers common org profiles."

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Email & Social"

    _PLATFORM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("linkedin", re.compile(r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[^\s"\'<>)]+', re.I)),
        ("twitter", re.compile(r'https?://(?:www\.)?(?:twitter|x)\.com/[^\s"\'<>)]+', re.I)),
        ("facebook", re.compile(r'https?://(?:www\.)?facebook\.com/[^\s"\'<>)]+', re.I)),
        ("github", re.compile(r'https?://(?:www\.)?github\.com/[^\s"\'<>)]+', re.I)),
        ("instagram", re.compile(r'https?://(?:www\.)?instagram\.com/[^\s"\'<>)]+', re.I)),
        ("youtube", re.compile(r'https?://(?:www\.)?youtube\.com/(?:channel/|@)[^\s"\'<>)]+', re.I)),
        ("tiktok", re.compile(r'https?://(?:www\.)?tiktok\.com/@[^\s"\'<>)]+', re.I)),
        ("medium", re.compile(r'https?://(?:www\.)?medium\.com/@[^\s"\'<>)]+', re.I)),
    ]

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}
        profiles: dict[str, set[str]] = {}

        # --- Scrape target page ---
        if progress_callback:
            await progress_callback("Fetching target page for social links...")
        page_url = target if "://" in target else f"https://{target}"
        resp = await self._http_get(page_url, timeout=20)
        html = resp.get("body", "") if resp["status"] else ""
        raw["page_status"] = resp.get("status", 0)

        if html:
            for platform, pattern in self._PLATFORM_PATTERNS:
                matches = pattern.findall(html)
                for url in matches:
                    # Normalize trailing punctuation
                    url = url.rstrip(".,;:!?")
                    profiles.setdefault(platform, set()).add(url)

        # --- Infer common org profiles ---
        orgname = domain.split(".")[0]
        inferred_urls = [
            ("github", f"https://github.com/{orgname}"),
            ("linkedin", f"https://linkedin.com/company/{orgname}"),
            ("twitter", f"https://x.com/{orgname}"),
        ]
        for platform, probe_url in inferred_urls:
            if probe_url not in profiles.get(platform, set()):
                try:
                    resp = await self._http_get(probe_url, timeout=10)
                    if resp["status"] == 200 and not resp.get("error"):
                        profiles.setdefault(platform, set()).add(probe_url)
                except Exception:
                    pass

        # --- Build assets ---
        total = 0
        evidence_lines: list[str] = []
        for platform, urls in sorted(profiles.items()):
            for url in sorted(urls):
                assets.append(
                    ModuleAsset(AssetType.SOCIAL_PROFILE, url, {"platform": platform, "domain": domain})
                )
                evidence_lines.append(f"  [{platform}] {url}")
                total += 1

        raw["profiles"] = {p: sorted(u) for p, u in profiles.items()}

        findings.append(
            ModuleFinding(
                title=f"Social Media Profiles Discovered ({domain})",
                description=(
                    f"Found {total} social media profile link(s) across "
                    f"{len(profiles)} platform(s) for {domain}."
                ),
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence=f"Domain: {domain}\nProfiles found: {total}\n" + "\n".join(evidence_lines),
                impact="Social profiles reveal organizational structure, employee names, and technology choices.",
                remediation="Review public social profiles for inadvertent information disclosure.",
                confidence=0.85,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# BreachSearchModule
# ---------------------------------------------------------------------------

class BreachSearchModule(BaseModule):
    """Check if the domain appears in known data breach databases."""

    @property
    def name(self) -> str:
        return "breach_search"

    @property
    def display_name(self) -> str:
        return "Breach Database Search"

    @property
    def description(self) -> str:
        return (
            "Checks whether the target domain appears in known data breach databases "
            "using HaveIBeenPwned and public breach APIs."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Email & Social"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}
        breaches_found: list[dict[str, Any]] = []
        api_available = False

        # --- HaveIBeenPwned public breaches list (no key required for breach list) ---
        if progress_callback:
            await progress_callback("Querying HaveIBeenPwned breach database...")
        try:
            hibp_url = "https://haveibeenpwned.com/api/v3/breaches"
            resp = await self._http_get(
                hibp_url,
                headers={"User-Agent": "ReconForge-OSINT"},
                timeout=20,
            )
            if resp["status"] == 200 and not resp.get("error"):
                api_available = True
                all_breaches = json.loads(resp["body"])
                domain_lower = domain.lower()
                for breach in all_breaches if isinstance(all_breaches, list) else []:
                    breach_domain = (breach.get("Domain") or "").lower()
                    if breach_domain == domain_lower:
                        breaches_found.append({
                            "name": breach.get("Name", "Unknown"),
                            "title": breach.get("Title", ""),
                            "date": breach.get("BreachDate", "Unknown"),
                            "pwn_count": breach.get("PwnCount", 0),
                            "data_classes": breach.get("DataClasses", []),
                            "description": breach.get("Description", ""),
                        })
                raw["hibp_total_breaches_checked"] = (
                    len(all_breaches) if isinstance(all_breaches, list) else 0
                )
            else:
                raw["hibp_error"] = resp.get("error", f"HTTP {resp['status']}")
        except Exception as exc:
            logger.warning("HIBP query failed: %s", exc)
            raw["hibp_error"] = str(exc)

        # --- BreachDirectory fallback ---
        if not api_available:
            if progress_callback:
                await progress_callback("Trying BreachDirectory API...")
            try:
                bd_url = f"https://breachdirectory.org/api/domain/{domain}"
                resp = await self._http_get(bd_url, timeout=15)
                if resp["status"] == 200 and not resp.get("error"):
                    api_available = True
                    bd_data = json.loads(resp["body"])
                    if isinstance(bd_data, dict) and bd_data.get("success"):
                        for entry in bd_data.get("result", []):
                            breaches_found.append({
                                "name": entry.get("source", "Unknown"),
                                "date": entry.get("date", "Unknown"),
                                "pwn_count": entry.get("count", 0),
                                "data_classes": entry.get("types", []),
                            })
                    raw["breachdirectory_status"] = resp["status"]
            except Exception as exc:
                logger.warning("BreachDirectory query failed: %s", exc)
                raw["breachdirectory_error"] = str(exc)

        # --- Generate findings ---
        raw["breaches_found"] = breaches_found

        if breaches_found:
            for breach in breaches_found:
                data_types = ", ".join(breach.get("data_classes", [])) or "Unknown"
                count = breach.get("pwn_count", 0)
                count_str = f"{count:,}" if count else "Unknown"
                findings.append(
                    ModuleFinding(
                        title=f"Domain Found in Data Breach: {breach.get('name', 'Unknown')}",
                        description=(
                            f"The domain {domain} appears in the '{breach.get('name', 'Unknown')}' "
                            f"data breach (date: {breach.get('date', 'Unknown')}). "
                            f"Approximately {count_str} accounts were compromised."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=(
                            f"Breach name: {breach.get('name', 'Unknown')}\n"
                            f"Breach date: {breach.get('date', 'Unknown')}\n"
                            f"Compromised accounts: {count_str}\n"
                            f"Data types exposed: {data_types}\n"
                            f"Description: {breach.get('description', 'N/A')[:300]}"
                        ),
                        impact=(
                            f"Credentials and personal data from {count_str} accounts may be circulating "
                            f"in breach databases, enabling credential stuffing and targeted phishing."
                        ),
                        remediation=(
                            "Force password resets for affected users. Enable MFA. "
                            "Monitor for credential stuffing attacks. "
                            "Notify affected users per applicable breach disclosure laws."
                        ),
                        confidence=0.85,
                    )
                )
            # Summary
            total_accounts = sum(b.get("pwn_count", 0) for b in breaches_found)
            findings.append(
                ModuleFinding(
                    title=f"Breach Summary for {domain}",
                    description=(
                        f"{domain} appears in {len(breaches_found)} known data breach(es) "
                        f"with a total of approximately {total_accounts:,} compromised accounts."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"Total breaches: {len(breaches_found)}\nTotal accounts: {total_accounts:,}",
                    impact="Aggregate breach exposure increases risk of credential reuse attacks.",
                    remediation="Conduct a comprehensive credential audit and enforce password rotation.",
                    confidence=0.85,
                )
            )
        elif api_available:
            findings.append(
                ModuleFinding(
                    title=f"No Known Breaches for {domain}",
                    description=f"The domain {domain} was not found in queried breach databases.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"Domain: {domain}\nBreaches found: 0",
                    impact="No known breach exposure detected for this domain.",
                    remediation="Continue monitoring via breach notification services.",
                    confidence=0.7,
                    validation_hint="Absence of results does not guarantee no breaches — check additional sources.",
                )
            )
        else:
            findings.append(
                ModuleFinding(
                    title=f"Breach Database Check Unavailable for {domain}",
                    description=(
                        f"Could not query breach databases for {domain}. "
                        f"Manual verification recommended."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=(
                        f"Domain: {domain}\n"
                        f"Recommended manual check: https://haveibeenpwned.com/DomainSearch\n"
                        f"Alternative: https://breachdirectory.org/"
                    ),
                    impact="Breach exposure status is unknown.",
                    remediation=(
                        "Manually search https://haveibeenpwned.com/DomainSearch for the domain. "
                        "Subscribe to breach notification services for ongoing monitoring."
                    ),
                    confidence=0.5,
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)
