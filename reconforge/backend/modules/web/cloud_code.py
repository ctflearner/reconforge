"""Cloud storage discovery, GitHub code search, and document metadata extraction modules."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
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


def _org_from_domain(domain: str) -> str:
    """Derive short org/company name from domain (e.g., example.com -> example)."""
    return domain.split(".")[0]


# ---------------------------------------------------------------------------
# CloudStorageModule
# ---------------------------------------------------------------------------

class CloudStorageModule(BaseModule):
    """Discover publicly accessible cloud storage buckets associated with the target."""

    @property
    def name(self) -> str:
        return "cloud_storage"

    @property
    def display_name(self) -> str:
        return "Cloud Storage Discovery"

    @property
    def description(self) -> str:
        return (
            "Generates bucket name permutations from the target domain and checks "
            "AWS S3, Google Cloud Storage, and Azure Blob Storage for public access."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Cloud & Code"

    _BUCKET_SUFFIXES = [
        "", "-backup", "-dev", "-staging", "-prod", "-assets", "-static",
        "-uploads", "-data", "-logs", "-private", "-public", "-media",
        "-files", "-cdn", "-web", "-api", "-app", "-test", "-internal",
    ]

    async def _check_bucket(
        self,
        bucket: str,
        provider: str,
        url: str,
    ) -> dict[str, Any] | None:
        """HEAD-check a single bucket URL. Returns result dict or None if not found."""
        try:
            resp = await self._http_get(url, timeout=8)
            status = resp.get("status", 0)
            if status in (200, 403):
                return {
                    "bucket": bucket,
                    "provider": provider,
                    "url": url,
                    "status": status,
                    "accessible": status == 200,
                }
        except Exception:
            pass
        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        company = _org_from_domain(domain)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain, "company": company}

        # Generate bucket permutations
        buckets = [f"{company}{suffix}" for suffix in self._BUCKET_SUFFIXES]

        # Build check tasks for all providers
        tasks: list[tuple[str, str, str]] = []
        for bucket in buckets:
            tasks.append((bucket, "aws_s3", f"https://{bucket}.s3.amazonaws.com/"))
            tasks.append((bucket, "gcs", f"https://storage.googleapis.com/{bucket}"))
            tasks.append((bucket, "azure_blob", f"https://{bucket}.blob.core.windows.net/"))

        if progress_callback:
            await progress_callback(
                f"Checking {len(tasks)} cloud storage endpoints for '{company}' permutations..."
            )

        # Run concurrent checks with semaphore to avoid overwhelming targets
        sem = asyncio.Semaphore(15)
        found_buckets: list[dict[str, Any]] = []

        async def _bounded_check(bucket: str, provider: str, url: str) -> dict[str, Any] | None:
            async with sem:
                return await self._check_bucket(bucket, provider, url)

        results = await asyncio.gather(
            *[_bounded_check(b, p, u) for b, p, u in tasks],
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, dict):
                found_buckets.append(result)

        raw["buckets_checked"] = len(tasks)
        raw["buckets_found"] = found_buckets

        # Generate findings and assets
        public_count = 0
        private_count = 0

        for fb in found_buckets:
            provider_label = {
                "aws_s3": "AWS S3",
                "gcs": "Google Cloud Storage",
                "azure_blob": "Azure Blob Storage",
            }.get(fb["provider"], fb["provider"])

            access_level = "public" if fb["accessible"] else "private"
            assets.append(
                ModuleAsset(
                    AssetType.CLOUD_RESOURCE,
                    fb["url"],
                    {
                        "provider": fb["provider"],
                        "bucket": fb["bucket"],
                        "access_level": access_level,
                        "status_code": fb["status"],
                    },
                )
            )

            if fb["accessible"]:
                public_count += 1
                findings.append(
                    ModuleFinding(
                        title=f"Publicly Accessible {provider_label} Bucket: {fb['bucket']}",
                        description=(
                            f"The cloud storage bucket '{fb['bucket']}' on {provider_label} "
                            f"is publicly accessible (HTTP 200). This may expose sensitive data."
                        ),
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=(
                            f"URL: {fb['url']}\n"
                            f"Provider: {provider_label}\n"
                            f"HTTP Status: {fb['status']}\n"
                            f"Access: PUBLIC"
                        ),
                        impact=(
                            "Publicly accessible cloud storage may contain sensitive files, backups, "
                            "credentials, source code, or customer data accessible to anyone."
                        ),
                        remediation=(
                            "Immediately restrict bucket access to authorized principals only. "
                            "Audit bucket contents for sensitive data exposure. "
                            "Enable bucket-level access logging."
                        ),
                        cwe_id="CWE-284",
                        cvss_score=7.5,
                        confidence=0.9,
                    )
                )
            else:
                private_count += 1
                findings.append(
                    ModuleFinding(
                        title=f"{provider_label} Bucket Exists (Private): {fb['bucket']}",
                        description=(
                            f"The bucket '{fb['bucket']}' exists on {provider_label} but is not "
                            f"publicly accessible (HTTP 403). This confirms the bucket name is in use."
                        ),
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        evidence=(
                            f"URL: {fb['url']}\n"
                            f"Provider: {provider_label}\n"
                            f"HTTP Status: {fb['status']}\n"
                            f"Access: PRIVATE (403 Forbidden)"
                        ),
                        impact="Bucket exists and is properly restricted. Name confirmed for further enumeration.",
                        remediation="No immediate action. Verify bucket policies remain restrictive.",
                        confidence=0.85,
                    )
                )

        # Summary finding
        if found_buckets:
            findings.append(
                ModuleFinding(
                    title=f"Cloud Storage Discovery Summary for {domain}",
                    description=(
                        f"Discovered {len(found_buckets)} cloud storage bucket(s): "
                        f"{public_count} publicly accessible, {private_count} private."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=(
                        f"Company name: {company}\n"
                        f"Permutations checked: {len(buckets)}\n"
                        f"Providers checked: AWS S3, GCS, Azure Blob\n"
                        f"Total endpoints probed: {len(tasks)}\n"
                        f"Buckets found: {len(found_buckets)} "
                        f"({public_count} public, {private_count} private)"
                    ),
                    impact="Cloud storage exposure can lead to data leakage and lateral movement.",
                    remediation="Review all discovered buckets and ensure least-privilege access policies.",
                    confidence=0.9,
                )
            )
        else:
            findings.append(
                ModuleFinding(
                    title=f"No Cloud Storage Buckets Found for {domain}",
                    description=(
                        f"No S3, GCS, or Azure Blob buckets matching common '{company}' "
                        f"name permutations were found."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"Checked {len(tasks)} endpoints across 3 providers. None returned 200 or 403.",
                    impact="No cloud storage exposure detected via common naming patterns.",
                    remediation="Consider checking additional naming conventions or using wordlists.",
                    confidence=0.7,
                    validation_hint="Try additional permutations or tools like cloud_enum for deeper coverage.",
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# GithubDorkModule
# ---------------------------------------------------------------------------

class GithubDorkModule(BaseModule):
    """Search GitHub for leaked secrets and sensitive files related to the target domain."""

    @property
    def name(self) -> str:
        return "github_dork"

    @property
    def display_name(self) -> str:
        return "GitHub Code Search"

    @property
    def description(self) -> str:
        return (
            "Searches GitHub code for leaked credentials, API keys, and sensitive "
            "configuration files associated with the target domain."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Cloud & Code"

    @property
    def requires_api_key(self) -> str | None:
        return "github_token"

    async def _search_github(
        self,
        query: str,
        token: str,
    ) -> list[dict[str, Any]]:
        """Execute a single GitHub code search query. Returns list of result items."""
        url = f"https://api.github.com/search/code?q={query}&per_page=10"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ReconForge-OSINT",
        }
        resp = await self._http_get(url, headers=headers, timeout=20)

        # Handle rate limiting
        remaining = resp.get("headers", {}).get("x-ratelimit-remaining", "1")
        if remaining == "0":
            reset_ts = resp.get("headers", {}).get("x-ratelimit-reset", "0")
            logger.warning("GitHub rate limit hit, reset at %s", reset_ts)
            # Wait briefly to avoid hammering
            await asyncio.sleep(5)

        if resp["status"] == 200 and not resp.get("error"):
            body = json.loads(resp["body"])
            return body.get("items", [])
        elif resp["status"] == 403:
            logger.warning("GitHub API rate limited or forbidden for query: %s", query)
            return []
        else:
            logger.warning("GitHub search returned %s for query: %s", resp["status"], query)
            return []

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        domain = _extract_domain(target)
        orgname = _org_from_domain(domain)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain, "orgname": orgname}

        if not settings.github_token:
            # No token — suggest manual dork queries
            dork_queries = [
                f'"{domain}" password',
                f'"{domain}" secret',
                f'"{domain}" api_key',
                f'"{domain}" token',
                f'"{domain}" filename:.env',
                f'"{domain}" filename:config',
                f'org:{orgname} password',
            ]
            findings.append(
                ModuleFinding(
                    title=f"GitHub Code Search Requires API Token",
                    description=(
                        f"No GitHub token configured. Manual search recommended for {domain}."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=(
                        f"Domain: {domain}\n"
                        f"Suggested GitHub dork queries:\n"
                        + "\n".join(f"  - {q}" for q in dork_queries)
                        + f"\n\nSearch URL: https://github.com/search?type=code&q=%22{domain}%22+password"
                    ),
                    impact="Potential secret leaks cannot be automatically detected without API access.",
                    remediation="Configure a GitHub personal access token for automated code search.",
                    confidence=0.5,
                )
            )
            return ModuleResult(findings=findings, assets=assets, raw_output=raw)

        # --- Execute dork queries ---
        token = settings.github_token
        dork_queries = [
            (f'"{domain}" password', "password"),
            (f'"{domain}" secret', "secret"),
            (f'"{domain}" api_key', "api_key"),
            (f'"{domain}" token', "token"),
            (f'"{domain}" filename:.env', ".env file"),
            (f'"{domain}" filename:config', "config file"),
            (f"org:{orgname} password", "org password"),
        ]

        all_results: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        for query, label in dork_queries:
            if progress_callback:
                await progress_callback(f"GitHub search: {label}...")
            try:
                items = await self._search_github(query, token)
                for item in items:
                    html_url = item.get("html_url", "")
                    if html_url and html_url not in seen_urls:
                        seen_urls.add(html_url)
                        repo_name = item.get("repository", {}).get("full_name", "unknown/unknown")
                        file_path = item.get("path", "")
                        # Get text fragment if available
                        text_matches = item.get("text_matches", [])
                        snippet = ""
                        if text_matches:
                            snippet = text_matches[0].get("fragment", "")[:300]

                        all_results.append({
                            "query": label,
                            "repo": repo_name,
                            "file": file_path,
                            "url": html_url,
                            "snippet": snippet,
                        })
                # Respect rate limits between queries
                await asyncio.sleep(2)
            except Exception as exc:
                logger.warning("GitHub search failed for '%s': %s", label, exc)
                raw[f"search_error_{label}"] = str(exc)

        raw["total_results"] = len(all_results)
        raw["results"] = all_results[:50]  # Cap raw output

        # --- Classify results and generate findings ---
        secret_keywords = {"password", "secret", "api_key", "token", "apikey", "private_key", "aws_access"}
        config_keywords = {".env", "config", "credentials", "settings"}

        for result in all_results:
            snippet_lower = result.get("snippet", "").lower()
            file_lower = result.get("file", "").lower()
            query_label = result.get("query", "")

            # Determine if this looks like an actual secret leak
            is_secret = any(kw in snippet_lower for kw in secret_keywords)
            is_config = any(kw in file_lower for kw in config_keywords)

            if is_secret:
                assets.append(
                    ModuleAsset(
                        AssetType.SECRET,
                        result["url"],
                        {
                            "repo": result["repo"],
                            "file": result["file"],
                            "query": query_label,
                        },
                    )
                )
                findings.append(
                    ModuleFinding(
                        title=f"Potential Secret Leak in GitHub: {result['repo']}",
                        description=(
                            f"GitHub code search found potential credential or secret exposure "
                            f"in repository '{result['repo']}' (file: {result['file']})."
                        ),
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=(
                            f"Repository: {result['repo']}\n"
                            f"File: {result['file']}\n"
                            f"URL: {result['url']}\n"
                            f"Search query: {query_label}\n"
                            f"Snippet:\n{result.get('snippet', 'N/A')}"
                        ),
                        impact=(
                            "Leaked credentials in public repositories can lead to unauthorized access, "
                            "account takeover, and data breaches."
                        ),
                        remediation=(
                            "Immediately rotate the exposed credential. Remove or redact the file from "
                            "git history (git filter-branch or BFG). Enable GitHub secret scanning."
                        ),
                        cwe_id="CWE-798",
                        cvss_score=8.2,
                        confidence=0.7,
                        validation_hint="Verify the snippet contains an actual secret, not example/test data.",
                    )
                )
            elif is_config:
                assets.append(
                    ModuleAsset(
                        AssetType.FILE,
                        result["url"],
                        {
                            "repo": result["repo"],
                            "file": result["file"],
                            "query": query_label,
                        },
                    )
                )

        # Summary finding
        secret_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        findings.append(
            ModuleFinding(
                title=f"GitHub Code Search Summary for {domain}",
                description=(
                    f"Searched {len(dork_queries)} dork queries against GitHub. "
                    f"Found {len(all_results)} unique result(s), "
                    f"{secret_count} flagged as potential secret leaks."
                ),
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence=(
                    f"Domain: {domain}\n"
                    f"Org name: {orgname}\n"
                    f"Queries executed: {len(dork_queries)}\n"
                    f"Unique results: {len(all_results)}\n"
                    f"Potential secrets: {secret_count}\n"
                    + (
                        "\nTop results:\n"
                        + "\n".join(
                            f"  - [{r['query']}] {r['repo']}/{r['file']}"
                            for r in all_results[:15]
                        )
                        if all_results
                        else ""
                    )
                ),
                impact="Code search reveals the organization's public code footprint and potential leaks.",
                remediation=(
                    "Enable GitHub secret scanning and push protection. "
                    "Regularly audit public repositories for credential exposure."
                ),
                confidence=0.85,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# MetadataExtractModule
# ---------------------------------------------------------------------------

class MetadataExtractModule(BaseModule):
    """Extract metadata from documents linked on the target page."""

    @property
    def name(self) -> str:
        return "metadata_extract"

    @property
    def display_name(self) -> str:
        return "Document Metadata"

    @property
    def description(self) -> str:
        return (
            "Finds PDF, DOCX, XLSX, and PPTX files linked on the target page and "
            "extracts metadata (author, software, internal paths, dates) via exiftool."
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "Cloud & Code"

    _DOC_PATTERN = re.compile(
        r'href=["\']([^"\']*\.(?:pdf|docx?|xlsx?|pptx?))["\']',
        re.IGNORECASE,
    )

    _MAX_DOCS = 5
    _MAX_DOC_SIZE = 10 * 1024 * 1024  # 10 MB

    _INTERESTING_FIELDS = {
        "Author", "Creator", "Producer", "Title", "Subject",
        "CreationDate", "CreateDate", "ModifyDate", "ModDate",
        "Software", "Application", "Company", "Manager",
        "LastModifiedBy", "Last Modified By",
        "GPSLatitude", "GPSLongitude", "GPSPosition",
    }

    async def _download_doc(self, url: str, dest_path: str) -> bool:
        """Download a document to a local path. Returns True on success."""
        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False
            ) as client:
                async with client.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        return False
                    total = 0
                    with open(dest_path, "wb") as f:
                        async for chunk in resp.aiter_bytes(8192):
                            total += len(chunk)
                            if total > self._MAX_DOC_SIZE:
                                return False
                            f.write(chunk)
            return True
        except Exception as exc:
            logger.warning("Failed to download %s: %s", url, exc)
            return False

    async def _extract_exiftool(self, filepath: str) -> dict[str, str]:
        """Run exiftool on a file and return parsed metadata dict."""
        stdout, stderr, rc = await self._run_command(
            ["exiftool", "-j", filepath], timeout=30
        )
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                if isinstance(data, list) and data:
                    return {str(k): str(v) for k, v in data[0].items() if v}
            except (json.JSONDecodeError, IndexError):
                pass
        return {}

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

        # --- Fetch page and find document links ---
        if progress_callback:
            await progress_callback("Fetching target page to discover documents...")
        page_url = target if "://" in target else f"https://{target}"
        resp = await self._http_get(page_url, timeout=20)
        html = resp.get("body", "") if resp.get("status") else ""
        raw["page_status"] = resp.get("status", 0)

        if not html:
            findings.append(
                ModuleFinding(
                    title=f"Could Not Fetch Target Page ({domain})",
                    description=f"Failed to retrieve the page at {page_url} for document discovery.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"URL: {page_url}\nHTTP Status: {resp.get('status', 0)}\nError: {resp.get('error', 'N/A')}",
                    impact="Document metadata extraction could not be performed.",
                    remediation="Verify the target URL is accessible.",
                    confidence=0.9,
                )
            )
            return ModuleResult(findings=findings, assets=assets, raw_output=raw)

        # Find document URLs
        doc_hrefs = self._DOC_PATTERN.findall(html)
        # Resolve relative URLs
        base_url = f"https://{domain}"
        doc_urls: list[str] = []
        seen: set[str] = set()
        for href in doc_hrefs:
            if href.startswith("//"):
                full = f"https:{href}"
            elif href.startswith("/"):
                full = f"{base_url}{href}"
            elif href.startswith("http"):
                full = href
            else:
                full = f"{base_url}/{href}"
            if full not in seen:
                seen.add(full)
                doc_urls.append(full)

        doc_urls = doc_urls[: self._MAX_DOCS]
        raw["documents_found"] = len(doc_hrefs)
        raw["documents_analyzed"] = len(doc_urls)

        if not doc_urls:
            findings.append(
                ModuleFinding(
                    title=f"No Documents Found on {domain}",
                    description=f"No PDF, DOCX, XLSX, or PPTX links were found on the target page.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"URL: {page_url}\nDocument links found: 0",
                    impact="No document metadata to extract.",
                    remediation="Check subpages or sitemap for additional document links.",
                    confidence=0.9,
                )
            )
            return ModuleResult(findings=findings, assets=assets, raw_output=raw)

        # --- Download and analyze documents ---
        all_metadata: list[dict[str, Any]] = []
        persons_found: set[str] = set()
        internal_paths: list[str] = []
        software_versions: list[str] = []
        gps_locations: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            for i, doc_url in enumerate(doc_urls):
                if progress_callback:
                    await progress_callback(f"Analyzing document {i + 1}/{len(doc_urls)}: {doc_url.split('/')[-1]}")

                filename = doc_url.split("/")[-1].split("?")[0] or f"doc_{i}"
                filepath = os.path.join(tmpdir, filename)

                if not await self._download_doc(doc_url, filepath):
                    raw[f"doc_{i}_error"] = f"Download failed: {doc_url}"
                    continue

                # Extract metadata
                metadata = await self._extract_exiftool(filepath)
                if not metadata:
                    raw[f"doc_{i}_error"] = f"Exiftool extraction failed: {doc_url}"
                    continue

                # Filter to interesting fields
                interesting = {
                    k: v for k, v in metadata.items() if k in self._INTERESTING_FIELDS
                }
                doc_info = {"url": doc_url, "filename": filename, "metadata": interesting}
                all_metadata.append(doc_info)

                # FILE asset
                assets.append(
                    ModuleAsset(
                        AssetType.FILE,
                        doc_url,
                        {"filename": filename, "metadata": interesting},
                    )
                )

                # --- Analyze metadata values ---

                # Authors / people
                for field in ("Author", "Creator", "LastModifiedBy", "Last Modified By", "Manager"):
                    value = metadata.get(field, "").strip()
                    if value and len(value) > 1 and value not in persons_found:
                        # Skip tool names that look like software
                        if not any(sw in value.lower() for sw in ("adobe", "microsoft", "libreoffice", "openoffice", "latex")):
                            persons_found.add(value)
                            assets.append(
                                ModuleAsset(
                                    AssetType.PERSON,
                                    value,
                                    {"source": "document_metadata", "field": field, "document": doc_url},
                                )
                            )

                # Internal paths
                path_pattern = re.compile(r'(?:C:\\Users\\[^\s"]+|/home/[^\s"]+|/Users/[^\s"]+)')
                for key, val in metadata.items():
                    for match in path_pattern.findall(str(val)):
                        internal_paths.append(f"{filename}: {key} = {match}")

                # Software/technology
                for field in ("Producer", "Creator", "Software", "Application"):
                    value = metadata.get(field, "").strip()
                    if value and len(value) > 1:
                        software_versions.append(f"{filename}: {value}")
                        assets.append(
                            ModuleAsset(
                                AssetType.TECHNOLOGY,
                                value,
                                {"source": "document_metadata", "field": field, "document": doc_url},
                            )
                        )

                # GPS coordinates
                for field in ("GPSLatitude", "GPSLongitude", "GPSPosition"):
                    value = metadata.get(field, "").strip()
                    if value:
                        gps_locations.append(f"{filename}: {field} = {value}")

        raw["metadata"] = all_metadata
        raw["persons"] = sorted(persons_found)
        raw["internal_paths"] = internal_paths
        raw["software"] = software_versions
        raw["gps"] = gps_locations

        # --- Generate findings ---

        if persons_found:
            findings.append(
                ModuleFinding(
                    title=f"Internal Usernames Discovered in Document Metadata ({domain})",
                    description=(
                        f"Found {len(persons_found)} unique person name(s)/username(s) "
                        f"in metadata of documents hosted on {domain}."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=(
                        f"Persons/usernames found:\n"
                        + "\n".join(f"  - {p}" for p in sorted(persons_found))
                    ),
                    impact=(
                        "Disclosed usernames can be used for targeted phishing, password spraying, "
                        "or social engineering attacks."
                    ),
                    remediation=(
                        "Strip metadata from documents before publishing. "
                        "Use organizational tools (e.g., Adobe Acrobat, ExifTool) to sanitize metadata."
                    ),
                    confidence=0.85,
                )
            )

        if internal_paths:
            findings.append(
                ModuleFinding(
                    title=f"Internal Paths Disclosed in Document Metadata ({domain})",
                    description=(
                        f"Document metadata contains {len(internal_paths)} internal file system path(s)."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="Internal paths:\n" + "\n".join(f"  - {p}" for p in internal_paths),
                    impact=(
                        "Internal paths reveal operating system, username patterns, and directory structure, "
                        "aiding attackers in targeted exploitation."
                    ),
                    remediation="Strip metadata from all publicly hosted documents.",
                    confidence=0.85,
                )
            )

        if gps_locations:
            findings.append(
                ModuleFinding(
                    title=f"GPS Coordinates Found in Document Metadata ({domain})",
                    description=(
                        f"GPS location data was found in {len(gps_locations)} document metadata field(s)."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="GPS data:\n" + "\n".join(f"  - {g}" for g in gps_locations),
                    impact="GPS coordinates may reveal physical office locations or employee addresses.",
                    remediation="Remove EXIF/GPS data from documents before public hosting.",
                    confidence=0.85,
                )
            )

        if software_versions:
            findings.append(
                ModuleFinding(
                    title=f"Software Versions Disclosed via Document Metadata ({domain})",
                    description=(
                        f"Document metadata reveals {len(software_versions)} software/version string(s)."
                    ),
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="Software disclosed:\n" + "\n".join(f"  - {s}" for s in software_versions),
                    impact="Software version disclosure aids attackers in identifying known vulnerabilities.",
                    remediation="Sanitize document metadata to remove producer and software version strings.",
                    confidence=0.8,
                )
            )

        # Summary finding
        findings.append(
            ModuleFinding(
                title=f"Document Metadata Analysis Summary ({domain})",
                description=(
                    f"Analyzed {len(all_metadata)} document(s) from {domain}. "
                    f"Found {len(persons_found)} person(s), {len(internal_paths)} internal path(s), "
                    f"{len(software_versions)} software string(s), {len(gps_locations)} GPS location(s)."
                ),
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence=(
                    f"Documents analyzed: {len(all_metadata)}/{len(doc_urls)}\n"
                    f"Total document links found on page: {len(doc_hrefs)}\n"
                    + "\n".join(
                        f"  - {m['filename']}: {len(m['metadata'])} metadata fields"
                        for m in all_metadata
                    )
                ),
                impact="Document metadata is a rich source of OSINT for attackers.",
                remediation=(
                    "Implement a metadata sanitization policy for all public documents. "
                    "Use tools like exiftool -all= to strip metadata before publishing."
                ),
                confidence=0.9,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)
