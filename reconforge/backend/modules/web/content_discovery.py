"""Content discovery, fingerprinting, and passive recon modules."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

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


def _base_url(target: str) -> str:
    """Normalise target into https:// base URL."""
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def _domain(target: str) -> str:
    """Extract bare hostname from target."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target.split("/")[0]


# ---------------------------------------------------------------------------
# 1. Robots.txt & Sitemap
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_PATTERNS = re.compile(
    r"(admin|backup|bak|config|\.git|\.env|\.svn|cgi-bin|debug|private|"
    r"secret|internal|tmp|temp|install|setup|phpinfo|phpmyadmin|wp-admin|"
    r"\.sql|\.log|\.bak|\.old|\.zip|\.tar|\.gz|database|dump|migrate|"
    r"credentials|token|passwd|shadow|htpasswd|\.htaccess)",
    re.I,
)


class RobotsSitemapModule(BaseModule):
    """Fetch and parse robots.txt and sitemap.xml for recon intelligence."""

    @property
    def name(self) -> str:
        return "robots_sitemap"

    @property
    def display_name(self) -> str:
        return "Robots.txt & Sitemap"

    @property
    def description(self) -> str:
        return "Parse robots.txt directives and sitemap.xml for hidden paths and URL inventory"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        base = _base_url(target)

        # --- Robots.txt ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Fetching robots.txt...")

        robots_resp = await self._http_get(f"{base}/robots.txt")
        disallow_paths: list[str] = []
        allow_paths: list[str] = []
        sitemap_urls: list[str] = []
        user_agents: list[str] = []

        if robots_resp.get("status") == 200 and robots_resp.get("body", "").strip():
            body = robots_resp["body"]
            result.raw_output["robots_txt"] = body

            for line in body.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                lower = line.lower()
                if lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallow_paths.append(path)
                elif lower.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allow_paths.append(path)
                elif lower.startswith("sitemap:"):
                    url = line.split(":", 1)[1].strip()
                    # The split on ":" may cut the URL — rejoin
                    if not url.startswith("http"):
                        url = line[len("Sitemap:"):].strip()
                    if url:
                        sitemap_urls.append(url)
                elif lower.startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
                    if ua:
                        user_agents.append(ua)

            # Create URL assets for disallowed paths
            for path in disallow_paths:
                full_url = urljoin(base, path)
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.URL,
                        value=full_url,
                        metadata={"source": "robots.txt", "directive": "Disallow"},
                    )
                )

            # Flag sensitive disallowed paths
            sensitive_paths = [p for p in disallow_paths if _SENSITIVE_PATH_PATTERNS.search(p)]
            if sensitive_paths:
                result.findings.append(
                    ModuleFinding(
                        title=f"Sensitive Paths in robots.txt ({len(sensitive_paths)} found)",
                        description="robots.txt disallows paths that suggest sensitive resources "
                        "(admin panels, backups, config files, version control).",
                        severity=FindingSeverity.LOW,
                        category="Content Discovery",
                        evidence="Sensitive disallowed paths:\n" + "\n".join(
                            f"  Disallow: {p}" for p in sensitive_paths[:30]
                        ),
                        impact="Attackers use robots.txt as a road-map to interesting endpoints.",
                        remediation="Do not rely on robots.txt for security. Restrict access at the server level.",
                        confidence=0.85,
                    )
                )
        else:
            result.raw_output["robots_txt"] = None

        # --- Sitemaps --------------------------------------------------------------------
        if not sitemap_urls:
            # Try default sitemap location
            sitemap_urls = [f"{base}/sitemap.xml"]

        all_sitemap_urls: list[str] = []
        processed_sitemaps: set[str] = set()

        async def _fetch_sitemap(sm_url: str, depth: int = 0) -> None:
            if depth > 3 or sm_url in processed_sitemaps:
                return
            processed_sitemaps.add(sm_url)

            if progress_callback:
                await progress_callback(f"Fetching sitemap: {sm_url}")

            resp = await self._http_get(sm_url)
            if resp.get("status") != 200 or not resp.get("body"):
                return

            body = resp["body"]
            # Extract <loc> tags
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.I)
            for loc in locs:
                if loc.endswith(".xml") or "sitemap" in loc.lower():
                    await _fetch_sitemap(loc, depth + 1)
                else:
                    all_sitemap_urls.append(loc)

        for sm in sitemap_urls:
            await _fetch_sitemap(sm)

        # Create URL assets for sitemap entries
        for sm_url in all_sitemap_urls[:2000]:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.URL,
                    value=sm_url,
                    metadata={"source": "sitemap.xml"},
                )
            )

        result.raw_output["disallow_paths"] = disallow_paths
        result.raw_output["allow_paths"] = allow_paths
        result.raw_output["sitemap_urls_found"] = len(all_sitemap_urls)

        # Summary finding
        result.findings.append(
            ModuleFinding(
                title=f"Robots/Sitemap: {len(disallow_paths)} disallowed, {len(all_sitemap_urls)} sitemap URLs",
                description=(
                    f"robots.txt: {len(disallow_paths)} Disallow rules, {len(allow_paths)} Allow rules, "
                    f"{len(user_agents)} User-Agents. "
                    f"Sitemaps: {len(all_sitemap_urls)} URLs discovered across {len(processed_sitemaps)} sitemap(s)."
                ),
                severity=FindingSeverity.INFO,
                category="Content Discovery",
                evidence=(
                    f"Disallow paths: {len(disallow_paths)}\n"
                    f"Allow paths: {len(allow_paths)}\n"
                    f"Sitemap URLs: {len(all_sitemap_urls)}\n"
                    f"User-Agents: {', '.join(user_agents[:10]) or 'none'}"
                ),
                impact="Informational — provides recon surface for further testing.",
                remediation="N/A",
                confidence=1.0,
            )
        )

        return result


# ---------------------------------------------------------------------------
# 2. Wayback Machine
# ---------------------------------------------------------------------------

_INTERESTING_EXTENSIONS = re.compile(
    r"\.(sql|bak|env|git|conf|xml|json|log|zip|tar\.gz|tgz|old|backup|"
    r"swp|db|sqlite|dump|cfg|ini|yml|yaml|toml|properties|key|pem|crt|"
    r"cer|pfx|p12|asc|secret|password|credentials)(\?|$)",
    re.I,
)


class WaybackModule(BaseModule):
    """Query the Wayback Machine CDX API for historical URLs and interesting files."""

    @property
    def name(self) -> str:
        return "wayback_discovery"

    @property
    def display_name(self) -> str:
        return "Wayback Machine"

    @property
    def description(self) -> str:
        return "Discover historical URLs and sensitive files from the Wayback Machine CDX index"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    @property
    def timeout(self) -> int:
        return 60

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = _domain(target)

        if progress_callback:
            await progress_callback(f"Querying Wayback Machine for {domain}...")

        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
            f"&output=json&fl=original,timestamp,statuscode,mimetype"
            f"&collapse=urlkey&limit=5000"
        )

        resp = await self._http_get(cdx_url, timeout=45)
        if resp.get("error"):
            result.error = f"Wayback CDX request failed: {resp['error']}"
            return result

        if resp.get("status") != 200:
            result.error = f"Wayback CDX returned HTTP {resp.get('status')}"
            return result

        # Parse JSON response
        try:
            rows = json.loads(resp["body"])
        except (json.JSONDecodeError, ValueError):
            result.error = "Failed to parse Wayback CDX JSON response"
            return result

        if not rows or len(rows) < 2:
            result.findings.append(
                ModuleFinding(
                    title="No Wayback Machine Data",
                    description=f"No archived URLs found for {domain} in the Wayback Machine.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=f"CDX query for {domain}/* returned 0 results",
                    impact="N/A",
                    remediation="N/A",
                    confidence=1.0,
                )
            )
            return result

        # First row is the header
        header = rows[0]
        data_rows = rows[1:]

        unique_urls: set[str] = set()
        interesting_files: list[str] = []
        param_names: set[str] = set()

        for row in data_rows:
            if len(row) < 1:
                continue
            url = row[0]
            unique_urls.add(url)

            # Extract query parameter names
            if "?" in url:
                query_part = url.split("?", 1)[1]
                for param in query_part.split("&"):
                    pname = param.split("=", 1)[0]
                    if pname:
                        param_names.add(pname)

            # Check for interesting extensions
            if _INTERESTING_EXTENSIONS.search(url):
                interesting_files.append(url)

        # Create URL assets for interesting files
        for ifile in interesting_files[:200]:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.URL,
                    value=ifile,
                    metadata={"source": "wayback_machine", "interesting": True},
                )
            )

        result.raw_output["total_urls"] = len(unique_urls)
        result.raw_output["interesting_files_count"] = len(interesting_files)
        result.raw_output["param_names"] = sorted(param_names)[:200]
        result.raw_output["interesting_files"] = interesting_files[:200]

        # Findings for interesting files
        if interesting_files:
            # Group by extension
            ext_groups: dict[str, list[str]] = {}
            for f in interesting_files:
                m = _INTERESTING_EXTENSIONS.search(f)
                if m:
                    ext = m.group(1).lower()
                    ext_groups.setdefault(ext, []).append(f)

            evidence_lines: list[str] = []
            for ext, urls in sorted(ext_groups.items()):
                evidence_lines.append(f"  .{ext}: {len(urls)} file(s)")
                for u in urls[:3]:
                    evidence_lines.append(f"    {u}")
                if len(urls) > 3:
                    evidence_lines.append(f"    ... and {len(urls) - 3} more")

            result.findings.append(
                ModuleFinding(
                    title=f"Wayback: {len(interesting_files)} Sensitive File(s) in Archive",
                    description=f"The Wayback Machine archive contains {len(interesting_files)} URL(s) "
                    "with sensitive file extensions (backups, configs, databases, credentials).",
                    severity=FindingSeverity.LOW,
                    category="Content Discovery",
                    evidence="\n".join(evidence_lines),
                    impact="Archived sensitive files may still be accessible or reveal historical secrets.",
                    remediation="Check if files are still accessible. Rotate any exposed credentials. "
                    "Request removal from the Wayback Machine if needed.",
                    confidence=0.7,
                    validation_hint="Fetch each URL to check if still live",
                )
            )

        # Summary finding
        result.findings.append(
            ModuleFinding(
                title=f"Wayback: {len(unique_urls)} Unique URLs, {len(param_names)} Parameters",
                description=(
                    f"Discovered {len(unique_urls)} unique URLs and "
                    f"{len(param_names)} unique query parameter names from the Wayback Machine archive."
                ),
                severity=FindingSeverity.INFO,
                category="Content Discovery",
                evidence=(
                    f"Total unique URLs: {len(unique_urls)}\n"
                    f"Interesting files: {len(interesting_files)}\n"
                    f"Unique parameters: {len(param_names)}\n"
                    f"Top params: {', '.join(sorted(param_names)[:20])}"
                ),
                impact="Historical URLs provide recon surface for parameter fuzzing and hidden endpoint discovery.",
                remediation="N/A",
                confidence=1.0,
            )
        )

        return result


# ---------------------------------------------------------------------------
# 3. JavaScript Analysis
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key", "SECRET", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", "SECRET", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe Secret Key", "SECRET", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Publishable Key", "SECRET", re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Firebase Config", "SECRET", re.compile(r"firebase(?:Config|\.initializeApp)\s*\(")),
    ("Generic Secret", "SECRET", re.compile(r"""(?:password|secret|token|api[_\-]?key)\s*[:=]\s*['"][^'"]{8,}['"]""", re.I)),
]

_ENDPOINT_PATTERN = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax|\.open)\s*\(\s*['"`]([^'"`\s]{5,})['"`]""",
    re.I,
)

_API_PATH_PATTERN = re.compile(r"/api/v\d+/[a-zA-Z0-9_/\-]+")

_INTERNAL_URL_PATTERN = re.compile(
    r"""https?://[a-zA-Z0-9.\-]+\.internal\."""
    r"|//10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|//192\.168\.\d{1,3}\.\d{1,3}"
    r"|//172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
)

_SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


class JsAnalysisModule(BaseModule):
    """Fetch page scripts and scan for secrets, endpoints, and source maps."""

    @property
    def name(self) -> str:
        return "js_analysis"

    @property
    def display_name(self) -> str:
        return "JavaScript Analysis"

    @property
    def description(self) -> str:
        return "Extract and scan JavaScript files for secrets, API endpoints, internal URLs, and source maps"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    @property
    def timeout(self) -> int:
        return 90

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        url = target if "://" in target else f"https://{target}"
        base = _base_url(target)

        if progress_callback:
            await progress_callback(f"Fetching page and extracting scripts from {url}...")

        # Fetch main page
        page_resp = await self._http_get(url)
        if page_resp.get("error"):
            result.error = f"Failed to fetch page: {page_resp['error']}"
            return result

        body = page_resp.get("body", "")

        # Extract script src URLs
        script_urls: list[str] = []
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I):
            src = m.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base + src
            elif not src.startswith("http"):
                src = urljoin(url, src)
            script_urls.append(src)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_scripts: list[str] = []
        for s in script_urls:
            if s not in seen:
                seen.add(s)
                unique_scripts.append(s)

        # Limit to first 20
        scripts_to_scan = unique_scripts[:20]

        result.raw_output["total_scripts"] = len(unique_scripts)
        result.raw_output["scripts_scanned"] = len(scripts_to_scan)

        all_secrets: list[dict[str, str]] = []
        all_endpoints: set[str] = set()
        all_source_maps: list[str] = []
        all_internal_urls: set[str] = set()

        for idx, script_url in enumerate(scripts_to_scan):
            if progress_callback:
                await progress_callback(f"Scanning JS {idx + 1}/{len(scripts_to_scan)}: {script_url[-60:]}")

            js_resp = await self._http_get(script_url, timeout=15)
            if js_resp.get("error") or js_resp.get("status", 0) != 200:
                continue

            js_body = js_resp.get("body", "")
            if not js_body:
                continue

            # --- Secrets ---
            for secret_name, asset_label, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(js_body):
                    matched_text = match.group(0)
                    all_secrets.append({
                        "type": secret_name,
                        "value": matched_text[:200],
                        "file": script_url,
                    })
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SECRET,
                            value=matched_text[:200],
                            metadata={"type": secret_name, "source_file": script_url},
                        )
                    )

            # --- API endpoints ---
            for match in _ENDPOINT_PATTERN.finditer(js_body):
                ep = match.group(1)
                all_endpoints.add(ep)
            for match in _API_PATH_PATTERN.finditer(js_body):
                all_endpoints.add(match.group(0))

            # --- Internal URLs ---
            for match in _INTERNAL_URL_PATTERN.finditer(js_body):
                all_internal_urls.add(match.group(0))

            # --- Source maps ---
            for match in _SOURCEMAP_PATTERN.finditer(js_body):
                sm_url = match.group(1)
                if not sm_url.startswith("http"):
                    sm_url = urljoin(script_url, sm_url)
                all_source_maps.append(sm_url)

        # Create endpoint assets
        for ep in sorted(all_endpoints):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=ep,
                    metadata={"source": "js_analysis"},
                )
            )

        # Create source map URL assets
        for sm in all_source_maps:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.URL,
                    value=sm,
                    metadata={"source": "js_source_map"},
                )
            )

        result.raw_output["secrets_found"] = len(all_secrets)
        result.raw_output["endpoints_found"] = len(all_endpoints)
        result.raw_output["source_maps_found"] = len(all_source_maps)
        result.raw_output["internal_urls_found"] = len(all_internal_urls)

        # --- Findings ---

        # Secrets
        if all_secrets:
            # Group by type
            by_type: dict[str, list[dict[str, str]]] = {}
            for s in all_secrets:
                by_type.setdefault(s["type"], []).append(s)

            evidence_lines: list[str] = []
            for stype, items in by_type.items():
                evidence_lines.append(f"  {stype}: {len(items)} occurrence(s)")
                for item in items[:3]:
                    evidence_lines.append(f"    File: {item['file']}")
                    evidence_lines.append(f"    Match: {item['value'][:80]}")

            result.findings.append(
                ModuleFinding(
                    title=f"Secrets Found in JavaScript ({len(all_secrets)} total)",
                    description=f"Found {len(all_secrets)} potential secret(s) across "
                    f"{len(by_type)} categories in client-side JavaScript files.",
                    severity=FindingSeverity.HIGH,
                    category="Content Discovery",
                    evidence="\n".join(evidence_lines),
                    impact="Exposed API keys and secrets can be used for unauthorized access, "
                    "data exfiltration, or lateral movement.",
                    remediation="Remove secrets from client-side code. Use server-side proxies for API calls. "
                    "Rotate all exposed credentials immediately.",
                    cwe_id="CWE-798",
                    cvss_score=7.5,
                    owasp_category="A02:2021 Cryptographic Failures",
                    confidence=0.75,
                    validation_hint="Verify each key is active and not a test/placeholder value",
                )
            )

        # Internal URLs
        if all_internal_urls:
            result.findings.append(
                ModuleFinding(
                    title=f"Internal URLs Leaked in JavaScript ({len(all_internal_urls)})",
                    description="JavaScript files reference internal/private IP addresses or .internal domains.",
                    severity=FindingSeverity.MEDIUM,
                    category="Content Discovery",
                    evidence="Internal URLs:\n" + "\n".join(
                        f"  {u}" for u in sorted(all_internal_urls)[:20]
                    ),
                    impact="Reveals internal network topology, aiding further attacks.",
                    remediation="Remove internal URLs from production JavaScript bundles.",
                    cwe_id="CWE-200",
                    confidence=0.8,
                )
            )

        # Source maps
        if all_source_maps:
            result.findings.append(
                ModuleFinding(
                    title=f"Source Maps Exposed ({len(all_source_maps)})",
                    description="JavaScript source map files are referenced and may be publicly accessible. "
                    "Source maps reveal original un-minified source code.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence="Source maps:\n" + "\n".join(
                        f"  {sm}" for sm in all_source_maps[:10]
                    ),
                    impact="Attacker can reconstruct original source code, revealing business logic, "
                    "comments, and potentially hardcoded secrets.",
                    remediation="Remove source map references from production builds. "
                    "Block access to .map files on the server.",
                    cwe_id="CWE-540",
                    confidence=0.85,
                    validation_hint="Fetch each .map URL to verify accessibility",
                )
            )

        # Summary
        result.findings.append(
            ModuleFinding(
                title=f"JS Analysis: {len(scripts_to_scan)} scripts, "
                f"{len(all_endpoints)} endpoints, {len(all_secrets)} secrets",
                description=(
                    f"Scanned {len(scripts_to_scan)} of {len(unique_scripts)} JavaScript files. "
                    f"Found {len(all_endpoints)} API endpoints, {len(all_secrets)} potential secrets, "
                    f"{len(all_source_maps)} source maps, {len(all_internal_urls)} internal URLs."
                ),
                severity=FindingSeverity.INFO,
                category="Content Discovery",
                evidence=(
                    f"Scripts: {len(scripts_to_scan)}/{len(unique_scripts)}\n"
                    f"Endpoints: {len(all_endpoints)}\n"
                    f"Secrets: {len(all_secrets)}\n"
                    f"Source maps: {len(all_source_maps)}\n"
                    f"Internal URLs: {len(all_internal_urls)}"
                ),
                impact="Informational — summarises passive JS intelligence.",
                remediation="N/A",
                confidence=1.0,
            )
        )

        return result


# ---------------------------------------------------------------------------
# 4. Google Dorking
# ---------------------------------------------------------------------------


class GoogleDorkModule(BaseModule):
    """Run Google dorks via the Custom Search API or generate manual dork queries."""

    @property
    def name(self) -> str:
        return "google_dork"

    @property
    def display_name(self) -> str:
        return "Google Dorking"

    @property
    def description(self) -> str:
        return "Search for sensitive files and pages via Google Custom Search API or generate manual dork queries"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    @property
    def requires_api_key(self) -> str | None:
        return "google_api_key"

    _DORK_TEMPLATES: list[tuple[str, str]] = [
        ('site:{domain} filetype:sql', "SQL database dumps"),
        ('site:{domain} filetype:env', "Environment config files"),
        ('site:{domain} filetype:log', "Log files"),
        ('site:{domain} filetype:conf', "Configuration files"),
        ('site:{domain} filetype:bak', "Backup files"),
        ('site:{domain} inurl:admin', "Admin panels"),
        ('site:{domain} inurl:login', "Login pages"),
        ('site:{domain} intitle:"index of"', "Open directory listings"),
        ('site:{domain} filetype:xml', "XML config/data files"),
        ('site:{domain} filetype:json', "JSON config/data files"),
        ('site:{domain} filetype:pdf', "PDF documents"),
        ('site:{domain} ext:php intitle:phpinfo', "PHP info pages"),
        ('site:{domain} inurl:wp-content', "WordPress content"),
        ('site:{domain} inurl:api', "API endpoints"),
        ('site:{domain} "password" filetype:txt', "Password files"),
    ]

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = _domain(target)

        has_api = bool(settings.google_api_key and settings.google_cse_id)

        if has_api:
            return await self._run_with_api(domain, result, progress_callback)
        else:
            return self._generate_manual_dorks(domain, result)

    async def _run_with_api(
        self,
        domain: str,
        result: ModuleResult,
        progress_callback: Callable | None,
    ) -> ModuleResult:
        """Execute dorks via Google Custom Search API."""
        api_key = settings.google_api_key
        cse_id = settings.google_cse_id
        total_results: list[dict[str, Any]] = []

        for template, label in self._DORK_TEMPLATES:
            query = template.format(domain=domain)
            if progress_callback:
                await progress_callback(f"Dorking: {query[:60]}...")

            api_url = (
                f"https://www.googleapis.com/customsearch/v1"
                f"?key={api_key}&cx={cse_id}&q={query}"
            )

            resp = await self._http_get(api_url, timeout=15)
            if resp.get("error") or resp.get("status") != 200:
                continue

            try:
                data = json.loads(resp["body"])
            except (json.JSONDecodeError, ValueError):
                continue

            items = data.get("items", [])
            for item in items:
                link = item.get("link", "")
                title = item.get("title", "")
                snippet = item.get("snippet", "")

                if link:
                    total_results.append({
                        "url": link,
                        "title": title,
                        "snippet": snippet,
                        "dork": query,
                        "category": label,
                    })
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.URL,
                            value=link,
                            metadata={"source": "google_dork", "dork": query, "title": title},
                        )
                    )

        result.raw_output["total_results"] = len(total_results)
        result.raw_output["results"] = total_results[:100]

        if total_results:
            # Group by dork category
            by_cat: dict[str, int] = {}
            for r in total_results:
                cat = r.get("category", "other")
                by_cat[cat] = by_cat.get(cat, 0) + 1

            evidence_lines = [f"  {cat}: {count} result(s)" for cat, count in sorted(by_cat.items())]
            sample_lines = [f"  {r['url']}" for r in total_results[:10]]

            result.findings.append(
                ModuleFinding(
                    title=f"Google Dorks: {len(total_results)} Results for {domain}",
                    description=f"Google Custom Search returned {len(total_results)} results "
                    f"across {len(self._DORK_TEMPLATES)} dork queries.",
                    severity=FindingSeverity.LOW,
                    category="Content Discovery",
                    evidence=(
                        "Results by category:\n" + "\n".join(evidence_lines) +
                        "\n\nSample URLs:\n" + "\n".join(sample_lines)
                    ),
                    impact="Indexed sensitive files and pages are accessible to anyone via search engines.",
                    remediation="Remove sensitive content from public access. Use robots.txt noindex or "
                    "request removal from Google Search Console.",
                    confidence=0.7,
                    validation_hint="Manually verify each result for sensitivity",
                )
            )
        else:
            result.findings.append(
                ModuleFinding(
                    title=f"Google Dorks: No Sensitive Results for {domain}",
                    description="Google Custom Search returned no results for the dork queries.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=f"Ran {len(self._DORK_TEMPLATES)} dork queries, 0 results",
                    impact="N/A",
                    remediation="N/A",
                    confidence=1.0,
                )
            )

        return result

    def _generate_manual_dorks(self, domain: str, result: ModuleResult) -> ModuleResult:
        """Generate dork queries for manual use (no API key)."""
        dork_list: list[str] = []
        for template, label in self._DORK_TEMPLATES:
            query = template.format(domain=domain)
            dork_list.append(f"  {query}  # {label}")

        result.raw_output["manual_dorks"] = [
            template.format(domain=domain) for template, _ in self._DORK_TEMPLATES
        ]

        result.findings.append(
            ModuleFinding(
                title=f"Google Dork Queries Generated ({len(dork_list)})",
                description="No Google API key configured. Generated dork queries for manual execution.",
                severity=FindingSeverity.INFO,
                category="Content Discovery",
                evidence="Dork queries:\n" + "\n".join(dork_list),
                impact="Manual testing required to determine exposure.",
                remediation="Configure google_api_key and google_cse_id for automated dorking.",
                confidence=1.0,
            )
        )

        return result


# ---------------------------------------------------------------------------
# 5. Technology Fingerprint
# ---------------------------------------------------------------------------

_JS_FRAMEWORKS: list[tuple[str, str, re.Pattern]] = [
    ("React", "", re.compile(r"(?:react(?:\.production|\.development|dom)|__REACT_DEVTOOLS|_reactRoot)", re.I)),
    ("Angular", "", re.compile(r"(?:ng-app|ng-controller|angular\.(?:module|bootstrap)|__ng_)", re.I)),
    ("Vue.js", "", re.compile(r"(?:vue\.(?:js|min\.js|runtime)|__VUE__|Vue\.component)", re.I)),
    ("jQuery", "", re.compile(r"(?:jquery[.\-]?\d|jQuery\.fn\.jquery)", re.I)),
    ("Next.js", "", re.compile(r"(?:_next/static|__NEXT_DATA__|_next/image)", re.I)),
    ("Nuxt", "", re.compile(r"(?:__nuxt|_nuxt/|nuxtjs)", re.I)),
    ("Svelte", "", re.compile(r"(?:svelte-\w|__svelte)", re.I)),
    ("Bootstrap", "", re.compile(r"(?:bootstrap\.(?:min\.)?(?:js|css))", re.I)),
    ("Tailwind CSS", "", re.compile(r"(?:tailwindcss|tailwind\.css)", re.I)),
    ("Webpack", "", re.compile(r"(?:webpackJsonp|__webpack_require__|webpack-)", re.I)),
]

_COOKIE_TECH: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "_rails_session": "Ruby on Rails",
    "laravel_session": "Laravel",
    "connect.sid": "Express.js/Node.js",
    "ci_session": "CodeIgniter",
    "CFID": "ColdFusion",
    "CFTOKEN": "ColdFusion",
    "wp-settings-": "WordPress",
    "symfony": "Symfony",
}


class TechFingerprintModule(BaseModule):
    """Fingerprint web technologies from headers, HTML, JS libraries, and cookies."""

    @property
    def name(self) -> str:
        return "tech_fingerprint"

    @property
    def display_name(self) -> str:
        return "Technology Fingerprint"

    @property
    def description(self) -> str:
        return "Identify server software, frameworks, and libraries from response headers, HTML, and cookies"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        url = target if "://" in target else f"https://{target}"

        if progress_callback:
            await progress_callback(f"Fingerprinting technologies on {url}...")

        resp = await self._http_get(url)
        if resp.get("error"):
            result.error = f"HTTP request failed: {resp['error']}"
            return result

        headers_lower = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        body = resp.get("body", "")

        detected: list[dict[str, str]] = []  # {"name": ..., "version": ..., "source": ...}

        # --- Response header fingerprinting -----------------------------------------------
        header_tech_map = {
            "server": "Server",
            "x-powered-by": "X-Powered-By",
            "x-aspnet-version": "ASP.NET",
            "x-generator": "Generator",
            "x-drupal-cache": "Drupal",
            "x-varnish": "Varnish",
        }

        for hdr, label in header_tech_map.items():
            val = headers_lower.get(hdr)
            if val:
                # Try to extract version
                version = ""
                vm = re.search(r"[\d]+(?:\.[\d]+)+", val)
                if vm:
                    version = vm.group(0)

                tech_name = val.split("/")[0].strip() if "/" in val else label
                detected.append({
                    "name": tech_name,
                    "version": version,
                    "source": f"header:{hdr}",
                    "raw": val,
                })

        # --- HTML meta generator tag -----------------------------------------------------
        for m in re.finditer(
            r'<meta\s+[^>]*name=["\']generator["\']\s+[^>]*content=["\']([^"\']+)["\']',
            body,
            re.I,
        ):
            gen = m.group(1).strip()
            version = ""
            vm = re.search(r"[\d]+(?:\.[\d]+)+", gen)
            if vm:
                version = vm.group(0)
            detected.append({"name": gen, "version": version, "source": "meta:generator"})

        # Reverse order meta tag
        for m in re.finditer(
            r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*name=["\']generator["\']',
            body,
            re.I,
        ):
            gen = m.group(1).strip()
            version = ""
            vm = re.search(r"[\d]+(?:\.[\d]+)+", gen)
            if vm:
                version = vm.group(0)
            detected.append({"name": gen, "version": version, "source": "meta:generator"})

        # --- JavaScript framework detection -----------------------------------------------
        for fw_name, _, pattern in _JS_FRAMEWORKS:
            if pattern.search(body):
                detected.append({"name": fw_name, "version": "", "source": "html:js_pattern"})

        # --- Cookie-based fingerprinting --------------------------------------------------
        set_cookie = headers_lower.get("set-cookie", "")
        for cookie_name, tech in _COOKIE_TECH.items():
            if cookie_name.lower() in set_cookie.lower():
                detected.append({"name": tech, "version": "", "source": f"cookie:{cookie_name}"})

        # --- Deduplicate by name (keep first with most info) ------------------------------
        seen_names: set[str] = set()
        unique_detected: list[dict[str, str]] = []
        for d in detected:
            key = d["name"].lower()
            if key not in seen_names:
                seen_names.add(key)
                unique_detected.append(d)

        # Create assets
        for d in unique_detected:
            version_str = f" {d['version']}" if d.get("version") else ""
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=f"{d['name']}{version_str}",
                    metadata={
                        "name": d["name"],
                        "version": d.get("version", ""),
                        "source": d["source"],
                    },
                )
            )

        result.raw_output["technologies"] = unique_detected
        result.raw_output["total_detected"] = len(unique_detected)

        # Summary finding
        if unique_detected:
            evidence_lines = []
            for d in unique_detected:
                ver = f" v{d['version']}" if d.get("version") else ""
                evidence_lines.append(f"  {d['name']}{ver} (via {d['source']})")
                if d.get("raw"):
                    evidence_lines.append(f"    Raw: {d['raw']}")

            result.findings.append(
                ModuleFinding(
                    title=f"Technology Stack: {len(unique_detected)} Technologies Detected",
                    description=(
                        f"Identified {len(unique_detected)} technologies/frameworks on the target. "
                        "Technology fingerprinting helps attackers find version-specific vulnerabilities."
                    ),
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence="\n".join(evidence_lines),
                    impact="Stack information aids in vulnerability research and exploit selection.",
                    remediation="Minimize information leakage: remove version headers, "
                    "obscure Server and X-Powered-By headers, remove generator meta tags.",
                    confidence=0.85,
                )
            )
        else:
            result.findings.append(
                ModuleFinding(
                    title="No Technologies Detected",
                    description="Could not fingerprint any specific technologies from the response.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence="No technology signatures found in headers, HTML, or cookies.",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        return result


# ---------------------------------------------------------------------------
# 6. WAF Detection
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: list[tuple[str, list[tuple[str, str, re.Pattern | None]]]] = [
    ("Cloudflare", [
        ("header", "cf-ray", None),
        ("cookie", "__cfduid", None),
        ("cookie", "__cf_bm", None),
        ("body", "", re.compile(r"Attention Required!|Cloudflare|cf-error", re.I)),
    ]),
    ("AWS WAF", [
        ("header", "x-amzn-requestid", None),
        ("header", "x-amz-cf-id", None),
        ("body", "", re.compile(r"Request blocked|AWS WAF", re.I)),
    ]),
    ("Akamai", [
        ("header", "x-akamai-transformed", None),
        ("body", "", re.compile(r"AkamaiGHost|Access Denied.*Akamai|Reference.*#\d+\.\w+", re.I)),
    ]),
    ("Sucuri", [
        ("header", "x-sucuri-id", None),
        ("body", "", re.compile(r"Sucuri WebSite Firewall|sucuri\.net", re.I)),
    ]),
    ("ModSecurity", [
        ("header", "server", re.compile(r"Mod_Security|NOYB", re.I)),
        ("body", "", re.compile(r"Mod_Security|Not Acceptable!.*Security Rules", re.I)),
    ]),
    ("Imperva/Incapsula", [
        ("cookie", "visid_incap_", None),
        ("cookie", "incap_ses_", None),
        ("body", "", re.compile(r"Incapsula incident|_Incapsula_Resource", re.I)),
    ]),
    ("F5 BIG-IP", [
        ("cookie", "BIGipServer", None),
        ("cookie", "TS", re.compile(r"^TS[a-f0-9]{6,}")),
        ("header", "server", re.compile(r"BigIP|BIG-IP", re.I)),
    ]),
    ("Barracuda", [
        ("cookie", "barra_counter_session", None),
        ("header", "server", re.compile(r"Barracuda", re.I)),
    ]),
    ("Fortinet/FortiWeb", [
        ("cookie", "FORTIWAFSID", None),
        ("header", "server", re.compile(r"FortiWeb", re.I)),
    ]),
    ("Wordfence", [
        ("body", "", re.compile(r"wordfence|wfacp_|This response was generated by Wordfence", re.I)),
    ]),
]


class WafDetectionModule(BaseModule):
    """Detect web application firewalls by sending a suspicious request and analysing the response."""

    @property
    def name(self) -> str:
        return "waf_detection"

    @property
    def display_name(self) -> str:
        return "WAF Detection"

    @property
    def description(self) -> str:
        return "Detect web application firewalls by analysing response signatures to normal and malicious requests"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        url = target if "://" in target else f"https://{target}"

        # --- Normal request (baseline) ---------------------------------------------------
        if progress_callback:
            await progress_callback("Fetching baseline response...")

        normal_resp = await self._http_get(url)
        normal_status = normal_resp.get("status", 0)

        # --- Suspicious request ----------------------------------------------------------
        if progress_callback:
            await progress_callback("Sending WAF probe request...")

        separator = "&" if "?" in url else "?"
        probe_url = f"{url}{separator}test=%3Cscript%3Ealert(1)%3C/script%3E&id=1'+OR+1%3D1--"

        probe_resp = await self._http_get(probe_url)
        probe_status = probe_resp.get("status", 0)
        probe_headers = {k.lower(): v for k, v in probe_resp.get("headers", {}).items()}
        probe_body = probe_resp.get("body", "")
        probe_cookies = probe_headers.get("set-cookie", "")

        # Also check normal response headers for persistent WAF signatures
        normal_headers = {k.lower(): v for k, v in normal_resp.get("headers", {}).items()}
        normal_cookies = normal_headers.get("set-cookie", "")

        detected_wafs: list[str] = []
        waf_evidence: list[str] = []

        for waf_name, signatures in _WAF_SIGNATURES:
            matched = False
            match_details: list[str] = []

            for sig_type, sig_key, sig_pattern in signatures:
                if matched:
                    break

                if sig_type == "header":
                    for headers_set, label in [(probe_headers, "probe"), (normal_headers, "normal")]:
                        val = headers_set.get(sig_key, "")
                        if val:
                            if sig_pattern is None:
                                matched = True
                                match_details.append(f"Header '{sig_key}' present in {label}: {val[:100]}")
                            elif sig_pattern.search(val):
                                matched = True
                                match_details.append(f"Header '{sig_key}' matches in {label}: {val[:100]}")

                elif sig_type == "cookie":
                    for cookie_str, label in [(probe_cookies, "probe"), (normal_cookies, "normal")]:
                        if sig_pattern is None:
                            if sig_key.lower() in cookie_str.lower():
                                matched = True
                                match_details.append(f"Cookie '{sig_key}' found in {label} Set-Cookie")
                        else:
                            if sig_pattern.search(cookie_str):
                                matched = True
                                match_details.append(f"Cookie pattern matched in {label} Set-Cookie")

                elif sig_type == "body":
                    if sig_pattern and sig_pattern.search(probe_body):
                        matched = True
                        match_details.append(f"Body pattern matched in probe response")

            if matched:
                detected_wafs.append(waf_name)
                waf_evidence.extend(match_details)

        # --- Status code analysis --------------------------------------------------------
        status_blocked = probe_status in (403, 406, 429, 503) and normal_status == 200
        if status_blocked and not detected_wafs:
            waf_evidence.append(
                f"Probe blocked (HTTP {probe_status}) while normal request returned {normal_status}"
            )

        result.raw_output["normal_status"] = normal_status
        result.raw_output["probe_status"] = probe_status
        result.raw_output["detected_wafs"] = detected_wafs
        result.raw_output["status_blocked"] = status_blocked

        # --- Findings and assets ---------------------------------------------------------
        if detected_wafs:
            for waf in detected_wafs:
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.TECHNOLOGY,
                        value=waf,
                        metadata={"type": "waf", "source": "waf_detection"},
                    )
                )

            result.findings.append(
                ModuleFinding(
                    title=f"WAF Detected: {', '.join(detected_wafs)}",
                    description=f"Identified {len(detected_wafs)} WAF/protection system(s) on the target: "
                    f"{', '.join(detected_wafs)}.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=(
                        f"Normal request: HTTP {normal_status}\n"
                        f"Probe request: HTTP {probe_status}\n"
                        f"Detected WAFs: {', '.join(detected_wafs)}\n"
                        f"Evidence:\n" + "\n".join(f"  {e}" for e in waf_evidence)
                    ),
                    impact="WAF presence affects testing methodology. Certain payloads may be blocked.",
                    remediation="N/A — WAF is a defensive measure. Ensure WAF rules cover OWASP Top 10.",
                    confidence=0.85,
                )
            )
        elif status_blocked:
            result.findings.append(
                ModuleFinding(
                    title="Possible WAF Detected (Status Code Analysis)",
                    description=f"The probe request was blocked with HTTP {probe_status} "
                    f"while the normal request returned {normal_status}. "
                    "A WAF or security filter may be in place but could not be fingerprinted.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=(
                        f"Normal request: HTTP {normal_status}\n"
                        f"Probe request: HTTP {probe_status}\n"
                        f"Probe URL: {probe_url[:200]}"
                    ),
                    impact="Testing may be limited by active filtering.",
                    remediation="N/A",
                    confidence=0.6,
                )
            )
        else:
            result.findings.append(
                ModuleFinding(
                    title="No WAF Detected",
                    description="No web application firewall signatures detected. "
                    "The server did not block or alter the probe request.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=(
                        f"Normal request: HTTP {normal_status}\n"
                        f"Probe request: HTTP {probe_status}\n"
                        "No WAF signature matched in headers, cookies, or body."
                    ),
                    impact="No WAF may mean less filtering of malicious payloads.",
                    remediation="Consider deploying a WAF for defense-in-depth.",
                    confidence=0.7,
                )
            )

        return result


# ---------------------------------------------------------------------------
# 7. Favicon Hash
# ---------------------------------------------------------------------------


class FaviconHashModule(BaseModule):
    """Download favicon, compute mmh3 hash, and optionally search Shodan for related infrastructure."""

    @property
    def name(self) -> str:
        return "favicon_hash"

    @property
    def display_name(self) -> str:
        return "Favicon Hash"

    @property
    def description(self) -> str:
        return "Compute favicon mmh3 hash and search Shodan for servers with the same hash"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Content Discovery"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        base = _base_url(target)
        favicon_url = f"{base}/favicon.ico"

        if progress_callback:
            await progress_callback(f"Downloading favicon from {favicon_url}...")

        # Download favicon as raw bytes via httpx
        favicon_bytes: bytes | None = None
        try:
            import httpx

            async with httpx.AsyncClient(
                timeout=settings.http_timeout, follow_redirects=True, verify=False
            ) as client:
                resp = await client.get(favicon_url)
                if resp.status_code == 200 and len(resp.content) > 0:
                    favicon_bytes = resp.content
        except Exception as exc:
            result.error = f"Failed to download favicon: {exc}"
            return result

        if not favicon_bytes:
            result.findings.append(
                ModuleFinding(
                    title="No Favicon Found",
                    description=f"No favicon.ico found at {favicon_url}.",
                    severity=FindingSeverity.INFO,
                    category="Content Discovery",
                    evidence=f"GET {favicon_url} returned no content or non-200 status",
                    impact="N/A",
                    remediation="N/A",
                    confidence=1.0,
                )
            )
            return result

        # Compute mmh3 hash
        try:
            import codecs
            import mmh3

            b64_favicon = codecs.encode(favicon_bytes, "base64")
            favicon_hash = mmh3.hash(b64_favicon)
        except ImportError:
            # mmh3 not installed — compute a fallback hash for reporting
            import hashlib as _hl

            favicon_hash = int(_hl.md5(favicon_bytes).hexdigest()[:8], 16)
            result.raw_output["hash_method"] = "md5_fallback (mmh3 not installed)"
        except Exception as exc:
            result.error = f"Hash computation failed: {exc}"
            return result

        result.raw_output["favicon_hash"] = favicon_hash
        result.raw_output["favicon_size"] = len(favicon_bytes)
        result.raw_output["favicon_url"] = favicon_url

        result.findings.append(
            ModuleFinding(
                title=f"Favicon Hash: {favicon_hash}",
                description=(
                    f"Favicon mmh3 hash for {base}: {favicon_hash}. "
                    f"This hash can be used to find related infrastructure on Shodan "
                    f"(query: http.favicon.hash:{favicon_hash})."
                ),
                severity=FindingSeverity.INFO,
                category="Content Discovery",
                evidence=(
                    f"Favicon URL: {favicon_url}\n"
                    f"Size: {len(favicon_bytes)} bytes\n"
                    f"mmh3 hash: {favicon_hash}\n"
                    f"Shodan query: http.favicon.hash:{favicon_hash}"
                ),
                impact="Favicon hash is used to discover related infrastructure sharing the same favicon.",
                remediation="N/A — informational fingerprint.",
                confidence=1.0,
            )
        )

        # --- Shodan search ---------------------------------------------------------------
        if settings.shodan_api_key:
            if progress_callback:
                await progress_callback(f"Searching Shodan for favicon hash {favicon_hash}...")

            shodan_url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={settings.shodan_api_key}"
                f"&query=http.favicon.hash:{favicon_hash}"
            )

            shodan_resp = await self._http_get(shodan_url, timeout=20)
            if not shodan_resp.get("error") and shodan_resp.get("status") == 200:
                try:
                    shodan_data = json.loads(shodan_resp["body"])
                except (json.JSONDecodeError, ValueError):
                    shodan_data = {}

                matches = shodan_data.get("matches", [])
                result.raw_output["shodan_matches"] = len(matches)

                if matches:
                    evidence_lines: list[str] = []
                    for match in matches[:50]:
                        ip = match.get("ip_str", "")
                        port = match.get("port", "")
                        org = match.get("org", "")
                        hostnames = match.get("hostnames", [])

                        if ip:
                            result.assets.append(
                                ModuleAsset(
                                    asset_type=AssetType.IP,
                                    value=ip,
                                    metadata={
                                        "port": port,
                                        "org": org,
                                        "hostnames": hostnames,
                                        "source": "shodan_favicon_hash",
                                    },
                                )
                            )
                            line = f"  {ip}:{port}"
                            if org:
                                line += f" ({org})"
                            if hostnames:
                                line += f" [{', '.join(hostnames[:3])}]"
                            evidence_lines.append(line)

                    result.findings.append(
                        ModuleFinding(
                            title=f"Shodan: {len(matches)} Host(s) Share Favicon Hash",
                            description=(
                                f"Shodan found {len(matches)} host(s) with the same favicon hash "
                                f"({favicon_hash}). These may be related infrastructure "
                                f"(same application, same organization, same CDN)."
                            ),
                            severity=FindingSeverity.LOW
                            if len(matches) > 1
                            else FindingSeverity.INFO,
                            category="Content Discovery",
                            evidence=(
                                f"Favicon hash: {favicon_hash}\n"
                                f"Shodan matches: {len(matches)}\n"
                                f"Hosts:\n" + "\n".join(evidence_lines[:20])
                            ),
                            impact="Reveals related infrastructure that may share vulnerabilities "
                            "or provide lateral movement paths.",
                            remediation="Review whether all identified hosts are intended to be publicly accessible.",
                            confidence=0.7,
                            validation_hint="Verify each IP is in scope before testing",
                        )
                    )
                else:
                    result.findings.append(
                        ModuleFinding(
                            title="Shodan: No Matches for Favicon Hash",
                            description=f"Shodan returned no results for http.favicon.hash:{favicon_hash}.",
                            severity=FindingSeverity.INFO,
                            category="Content Discovery",
                            evidence=f"Shodan query returned 0 matches",
                            impact="N/A",
                            remediation="N/A",
                            confidence=1.0,
                        )
                    )
        else:
            result.raw_output["shodan_available"] = False

        return result
