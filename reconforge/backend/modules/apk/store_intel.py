"""Play Store intelligence and developer OSINT modules."""
from __future__ import annotations

import html
import logging
import re
import zipfile
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

from backend.modules.base import (
    AssetType,
    BaseModule,
    FindingSeverity,
    ModuleAsset,
    ModuleFinding,
    ModuleResult,
)

logger = logging.getLogger(__name__)

# Keywords in reviews that hint at security/privacy problems
_SECURITY_KEYWORDS = [
    "crash", "data breach", "privacy", "hack", "leaked", "malware",
    "spyware", "permission", "tracking", "unsafe", "virus", "phishing",
    "stolen", "unauthorized", "exploit", "vulnerability", "insecure",
    "surveillance", "keylogger", "backdoor", "trojan",
]


class PlayStoreModule(BaseModule):
    """Scrape Google Play Store listing for an APK's package."""

    @property
    def name(self) -> str:
        return "apk_play_store"

    @property
    def display_name(self) -> str:
        return "Play Store Intel"

    @property
    def description(self) -> str:
        return "Extract app metadata and reviews from Google Play Store"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "store_intel"

    @property
    def timeout(self) -> int:
        return 60

    # ------------------------------------------------------------------

    async def _extract_package_name(self, apk_path: str) -> str | None:
        """Get package name via aapt2, falling back to manifest XML parse."""
        stdout, _, rc = await self._run_command(
            ["aapt2", "dump", "badging", apk_path], timeout=30
        )
        if rc == 0 and stdout:
            m = re.search(r"package:\s+name='([^']+)'", stdout)
            if m:
                return m.group(1)

        # Fallback: aapt (v1)
        stdout, _, rc = await self._run_command(
            ["aapt", "dump", "badging", apk_path], timeout=30
        )
        if rc == 0 and stdout:
            m = re.search(r"package:\s+name='([^']+)'", stdout)
            if m:
                return m.group(1)

        # Fallback: unzip + parse AndroidManifest.xml with aapt
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    # Binary XML — try axmlprinter or aapt on extracted file
                    pass
        except Exception:
            pass

        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Extracting package name from APK...")

        package = await self._extract_package_name(apk_path)
        if not package:
            result.error = "Could not extract package name from APK"
            return result

        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.COMPONENT,
                value=package,
                metadata={"type": "package_name"},
            )
        )

        if progress_callback:
            await progress_callback(f"Querying Play Store for {package}...")

        url = f"https://play.google.com/store/apps/details?id={package}&hl=en&gl=US"
        resp = await self._http_get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

        if resp.get("error") or resp.get("status", 0) != 200:
            result.raw_output["play_store_error"] = resp.get("error", f"HTTP {resp.get('status')}")
            result.findings.append(
                ModuleFinding(
                    title="App Not Found on Play Store",
                    description=f"Package {package} not found on Google Play Store. "
                    "App may be delisted, region-locked, or sideload-only.",
                    severity=FindingSeverity.INFO,
                    category="store_intel",
                    evidence=f"URL: {url}\nStatus: {resp.get('status')}\n",
                    impact="Cannot gather public store intelligence; app may be distributed outside official channels.",
                    remediation="Verify package name and check alternative stores.",
                    confidence=0.9,
                )
            )
            return result

        body = resp["body"]
        result.raw_output["play_store_url"] = url

        # --- Scrape metadata ---
        meta: dict[str, Any] = {"package": package, "url": url}

        # Title
        title_m = re.search(r'<h1[^>]*itemprop="name"[^>]*><span>([^<]+)</span>', body)
        if not title_m:
            title_m = re.search(r'<title>([^<]+)\s*-\s*Apps on Google Play</title>', body)
        if title_m:
            meta["title"] = html.unescape(title_m.group(1).strip())

        # Developer
        dev_m = re.search(r'<a[^>]*href="/store/apps/dev[^"]*"[^>]*><span>([^<]+)</span>', body)
        if not dev_m:
            dev_m = re.search(r'"developer"[^}]*"name"\s*:\s*"([^"]+)"', body)
        if dev_m:
            meta["developer"] = html.unescape(dev_m.group(1).strip())

        # Rating
        rating_m = re.search(r'<div[^>]*itemprop="starRating"[^>]*>.*?(\d+\.?\d*)', body, re.S)
        if not rating_m:
            rating_m = re.search(r'"score"\s*:\s*(\d+\.?\d*)', body)
        if rating_m:
            meta["rating"] = float(rating_m.group(1))

        # Install count
        installs_m = re.search(r'(\d[\d,]+\+?)\s*(?:downloads|installs)', body, re.I)
        if not installs_m:
            installs_m = re.search(r'"numDownloads"\s*:\s*"([^"]+)"', body)
        if installs_m:
            meta["installs"] = installs_m.group(1).strip()

        # Description
        desc_m = re.search(
            r'<div[^>]*itemprop="description"[^>]*><span[^>]*>(.*?)</span></div>',
            body,
            re.S,
        )
        if not desc_m:
            desc_m = re.search(r'"description"\s*:\s*"((?:[^"\\]|\\.)*)?"', body)
        if desc_m:
            raw_desc = html.unescape(re.sub(r"<[^>]+>", " ", desc_m.group(1)))
            meta["description"] = raw_desc[:2000]

        # Content rating
        cr_m = re.search(r'"contentRating"\s*:\s*"([^"]+)"', body)
        if cr_m:
            meta["content_rating"] = cr_m.group(1)

        # Last updated
        upd_m = re.search(r'"datePublished"\s*:\s*"([^"]+)"', body)
        if not upd_m:
            upd_m = re.search(r'Updated\s*</div>\s*<span[^>]*>([^<]+)</span>', body)
        if upd_m:
            meta["last_updated"] = upd_m.group(1).strip()

        # Permissions listed on store page
        perm_matches = re.findall(r'"permission"\s*:\s*\[([^\]]*)\]', body)
        permissions: list[str] = []
        for pm in perm_matches:
            permissions.extend(re.findall(r'"([^"]+)"', pm))
        if permissions:
            meta["store_permissions"] = permissions

        # Developer email / website
        dev_email_m = re.search(r'"developerEmail"\s*:\s*"([^"]+)"', body)
        if dev_email_m:
            meta["developer_email"] = dev_email_m.group(1)
        dev_website_m = re.search(r'"developerWebsite"\s*:\s*"([^"]+)"', body)
        if dev_website_m:
            meta["developer_website"] = dev_website_m.group(1)

        result.raw_output["metadata"] = meta

        # Create assets for each piece
        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.TECHNOLOGY,
                value=meta.get("title", package),
                metadata=meta,
            )
        )

        if meta.get("developer"):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERSON,
                    value=meta["developer"],
                    metadata={"role": "app_developer", "package": package},
                )
            )

        if meta.get("developer_email"):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.EMAIL,
                    value=meta["developer_email"],
                    metadata={"source": "play_store"},
                )
            )

        if meta.get("developer_website"):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.URL,
                    value=meta["developer_website"],
                    metadata={"type": "developer_website"},
                )
            )

        # --- Scan reviews for security-relevant complaints ---
        if progress_callback:
            await progress_callback("Scanning reviews for security keywords...")

        review_texts: list[str] = []
        review_pattern = re.compile(
            r'<div[^>]*jscontroller="[^"]*"[^>]*>.*?<span[^>]*>(.{20,500}?)</span>',
            re.S,
        )
        for rm in review_pattern.finditer(body):
            text = html.unescape(re.sub(r"<[^>]+>", " ", rm.group(1))).strip()
            if text:
                review_texts.append(text)

        security_reviews: list[str] = []
        for review in review_texts:
            lower = review.lower()
            if any(kw in lower for kw in _SECURITY_KEYWORDS):
                security_reviews.append(review)

        if security_reviews:
            evidence_block = "\n---\n".join(security_reviews[:10])
            result.findings.append(
                ModuleFinding(
                    title="Security-Relevant User Complaints",
                    description=f"Found {len(security_reviews)} review(s) mentioning security/privacy "
                    f"concerns on the Play Store listing for {package}.",
                    severity=FindingSeverity.INFO,
                    category="store_intel",
                    evidence=evidence_block,
                    impact="User complaints may indicate real security issues worth investigating.",
                    remediation="Cross-reference complaints with actual code analysis findings.",
                    confidence=0.5,
                )
            )

        # --- Low rating flag ---
        if meta.get("rating") and meta["rating"] < 3.0:
            result.findings.append(
                ModuleFinding(
                    title="Low App Store Rating",
                    description=f"App has a rating of {meta['rating']}/5.0 — may indicate quality or security issues.",
                    severity=FindingSeverity.INFO,
                    category="store_intel",
                    evidence=f"Rating: {meta['rating']}",
                    impact="Low ratings sometimes correlate with buggy code and security issues.",
                    remediation="Review user feedback for patterns.",
                    confidence=0.4,
                )
            )

        # --- Old app flag ---
        if meta.get("last_updated"):
            result.findings.append(
                ModuleFinding(
                    title="App Last Updated",
                    description=f"App was last updated: {meta['last_updated']}. "
                    "Stale apps may use outdated libraries with known CVEs.",
                    severity=FindingSeverity.INFO,
                    category="store_intel",
                    evidence=f"Last updated: {meta['last_updated']}",
                    impact="Outdated apps are more likely to contain known vulnerabilities.",
                    remediation="Check dependency versions against CVE databases.",
                    confidence=0.6,
                )
            )

        return result


class DeveloperOsintModule(BaseModule):
    """OSINT on the app developer from Play Store data."""

    @property
    def name(self) -> str:
        return "apk_developer_osint"

    @property
    def display_name(self) -> str:
        return "Developer OSINT"

    @property
    def description(self) -> str:
        return "Gather OSINT on app developer from Play Store and public sources"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "store_intel"

    @property
    def timeout(self) -> int:
        return 90

    async def _extract_package_name(self, apk_path: str) -> str | None:
        stdout, _, rc = await self._run_command(
            ["aapt2", "dump", "badging", apk_path], timeout=30
        )
        if rc == 0 and stdout:
            m = re.search(r"package:\s+name='([^']+)'", stdout)
            if m:
                return m.group(1)
        stdout, _, rc = await self._run_command(
            ["aapt", "dump", "badging", apk_path], timeout=30
        )
        if rc == 0 and stdout:
            m = re.search(r"package:\s+name='([^']+)'", stdout)
            if m:
                return m.group(1)
        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        package = await self._extract_package_name(apk_path)
        if not package:
            result.error = "Could not extract package name"
            return result

        if progress_callback:
            await progress_callback("Fetching developer info from Play Store...")

        url = f"https://play.google.com/store/apps/details?id={package}&hl=en&gl=US"
        resp = await self._http_get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        )

        if resp.get("status") != 200:
            result.error = f"Play Store returned {resp.get('status')} for {package}"
            return result

        body = resp["body"]

        # Extract developer name
        dev_name = None
        dev_m = re.search(r'<a[^>]*href="(/store/apps/dev[^"]*)"[^>]*><span>([^<]+)</span>', body)
        dev_page_path = None
        if dev_m:
            dev_page_path = dev_m.group(1)
            dev_name = html.unescape(dev_m.group(2).strip())

        if not dev_name:
            dev_m2 = re.search(r'"developer"[^}]*"name"\s*:\s*"([^"]+)"', body)
            if dev_m2:
                dev_name = html.unescape(dev_m2.group(1))

        if not dev_name:
            result.error = "Could not extract developer name from Play Store"
            return result

        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.PERSON,
                value=dev_name,
                metadata={"source": "play_store", "role": "developer"},
            )
        )

        # Developer email
        dev_email_m = re.search(r'"developerEmail"\s*:\s*"([^"]+)"', body)
        if dev_email_m:
            email = dev_email_m.group(1)
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.EMAIL,
                    value=email,
                    metadata={"source": "play_store", "person": dev_name},
                )
            )

        # Developer website
        dev_website = None
        dev_web_m = re.search(r'"developerWebsite"\s*:\s*"([^"]+)"', body)
        if dev_web_m:
            dev_website = dev_web_m.group(1)
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.URL,
                    value=dev_website,
                    metadata={"type": "developer_website", "person": dev_name},
                )
            )

        # Developer address
        dev_addr_m = re.search(r'"developerAddress"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
        if dev_addr_m:
            result.raw_output["developer_address"] = dev_addr_m.group(1)

        # --- Other apps by same developer ---
        if progress_callback:
            await progress_callback(f"Looking up other apps by {dev_name}...")

        if dev_page_path:
            dev_url = f"https://play.google.com{dev_page_path}"
            dev_resp = await self._http_get(
                dev_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                },
            )
            if dev_resp.get("status") == 200:
                dev_body = dev_resp["body"]
                app_links = re.findall(
                    r'href="/store/apps/details\?id=([a-zA-Z0-9_.]+)"',
                    dev_body,
                )
                other_apps = list(set(app_links) - {package})
                if other_apps:
                    result.raw_output["other_apps"] = other_apps[:50]
                    for app_id in other_apps[:20]:
                        result.assets.append(
                            ModuleAsset(
                                asset_type=AssetType.COMPONENT,
                                value=app_id,
                                metadata={
                                    "type": "other_app",
                                    "developer": dev_name,
                                    "url": f"https://play.google.com/store/apps/details?id={app_id}",
                                },
                            )
                        )

        # --- Search for LinkedIn presence ---
        if progress_callback:
            await progress_callback("Checking social presence...")

        safe_name = dev_name.replace(" ", "+")

        # GitHub search via web
        gh_url = f"https://github.com/search?q={safe_name}&type=users"
        gh_resp = await self._http_get(
            gh_url,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if gh_resp.get("status") == 200:
            gh_body = gh_resp["body"]
            gh_users = re.findall(r'href="/([a-zA-Z0-9_-]+)"[^>]*data-hovercard-type="user"', gh_body)
            if not gh_users:
                gh_users = re.findall(r'<a[^>]*href="/([a-zA-Z0-9_-]+)"[^>]*class="[^"]*mr-1[^"]*"', gh_body)
            for ghu in list(set(gh_users))[:5]:
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SOCIAL_PROFILE,
                        value=f"https://github.com/{ghu}",
                        metadata={"platform": "github", "username": ghu, "person": dev_name},
                    )
                )

        # LinkedIn link from developer website
        if dev_website:
            site_resp = await self._http_get(
                dev_website,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if site_resp.get("status") == 200:
                site_body = site_resp["body"]
                linkedin_links = re.findall(
                    r'href="(https?://(?:www\.)?linkedin\.com/(?:in|company)/[^"]+)"',
                    site_body,
                )
                for li_link in list(set(linkedin_links))[:5]:
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SOCIAL_PROFILE,
                            value=li_link,
                            metadata={"platform": "linkedin", "person": dev_name},
                        )
                    )

                # Extract additional emails from developer website
                emails_found = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    site_body,
                )
                for em in list(set(emails_found))[:10]:
                    if not em.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                        result.assets.append(
                            ModuleAsset(
                                asset_type=AssetType.EMAIL,
                                value=em,
                                metadata={"source": "developer_website", "person": dev_name},
                            )
                        )

                # GitHub links from developer site
                gh_links = re.findall(
                    r'href="(https?://github\.com/[a-zA-Z0-9_-]+)"',
                    site_body,
                )
                for gl in list(set(gh_links))[:5]:
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SOCIAL_PROFILE,
                            value=gl,
                            metadata={"platform": "github", "source": "developer_website"},
                        )
                    )

        # Summary finding
        asset_count = len(result.assets)
        result.findings.append(
            ModuleFinding(
                title="Developer OSINT Summary",
                description=f"Gathered {asset_count} asset(s) for developer '{dev_name}' of package {package}.",
                severity=FindingSeverity.INFO,
                category="store_intel",
                evidence=f"Developer: {dev_name}\n"
                f"Website: {dev_website or 'N/A'}\n"
                f"Other apps found: {len(result.raw_output.get('other_apps', []))}\n"
                f"Social profiles: {sum(1 for a in result.assets if a.asset_type == AssetType.SOCIAL_PROFILE)}",
                impact="Developer OSINT can reveal attack surface across multiple apps and platforms.",
                remediation="Review all developer assets for potential phishing or supply-chain attack vectors.",
                confidence=0.7,
            )
        )

        return result
