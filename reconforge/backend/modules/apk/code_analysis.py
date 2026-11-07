"""APK code analysis modules — secret scanning, endpoint extraction, crypto audit, storage, webview."""
from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
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

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SOURCE_EXTENSIONS = {".java", ".kt", ".smali"}
_RESOURCE_EXTENSIONS = {".xml", ".json", ".properties", ".yml", ".yaml", ".cfg", ".conf"}
_ALL_SCAN_EXTENSIONS = _SOURCE_EXTENSIONS | _RESOURCE_EXTENSIONS


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _collect_files(root_dir: str, extensions: set[str] | None = None) -> list[str]:
    """Walk directory and return file paths matching extensions."""
    exts = extensions or _ALL_SCAN_EXTENSIONS
    files: list[str] = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if any(fname.endswith(ext) for ext in exts):
                files.append(os.path.join(dirpath, fname))
    return files


def _read_file_safe(path: str, max_bytes: int = 5_000_000) -> str:
    """Read a file up to max_bytes, replacing undecodable chars."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except Exception:
        return ""


async def _ensure_decompiled(mod: BaseModule, apk_path: str, scan_context: dict[str, Any]) -> str | None:
    """Decompile APK with jadx if not already done. Returns decompiled dir or None."""
    existing = scan_context.get("decompiled_dir")
    if existing and os.path.isdir(existing):
        return existing

    apk_hash = hashlib.sha256(apk_path.encode()).hexdigest()[:16]
    out_dir = os.path.join(settings.decompiled_dir, apk_hash)

    # Check if already decompiled from a previous run
    if os.path.isdir(out_dir) and any(os.scandir(out_dir)):
        scan_context["decompiled_dir"] = out_dir
        return out_dir

    os.makedirs(out_dir, exist_ok=True)
    stdout, stderr, rc = await mod._run_command(
        ["jadx", "-d", out_dir, "--no-res", "--no-debug-info", apk_path],
        timeout=300,
    )
    if rc != 0:
        # Retry with resources (some APKs need it)
        stdout2, stderr2, rc2 = await mod._run_command(
            ["jadx", "-d", out_dir, apk_path],
            timeout=300,
        )
        if rc2 != 0:
            logger.error("jadx failed: %s / %s", stderr, stderr2)
            return None

    scan_context["decompiled_dir"] = out_dir
    return out_dir


# ---------------------------------------------------------------------------
# Secret patterns — 40+ regex rules
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str, float]] = [
    # (label, compiled regex, severity, description, base_confidence)
    # --- Cloud provider keys ---
    ("AWS Access Key", re.compile(r'(?:^|["\'\s=:])((AKIA)[A-Z0-9]{16})(?:["\'\s,;]|$)'), FindingSeverity.CRITICAL,
     "AWS IAM access key ID", 0.9),
    ("AWS Secret Key", re.compile(r'(?:aws_secret_access_key|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), FindingSeverity.CRITICAL,
     "AWS secret access key", 0.85),
    ("Google API Key", re.compile(r'(?:^|["\'\s=:])(AIza[A-Za-z0-9_-]{35})(?:["\'\s,;]|$)'), FindingSeverity.HIGH,
     "Google API key", 0.85),
    ("Google OAuth Client ID", re.compile(r'(\d+-[a-z0-9_]+\.apps\.googleusercontent\.com)'), FindingSeverity.MEDIUM,
     "Google OAuth client ID", 0.8),
    ("Firebase URL", re.compile(r'(https?://[a-z0-9-]+\.firebaseio\.com)'), FindingSeverity.HIGH,
     "Firebase Realtime Database URL — may allow unauthenticated read/write", 0.85),
    ("Firebase API Key", re.compile(r'(?:firebase|api)[_-]?key\s*[=:]\s*["\']?(AIza[A-Za-z0-9_-]{35})["\']?', re.I), FindingSeverity.HIGH,
     "Firebase API key", 0.85),

    # --- Payment / SaaS ---
    ("Stripe Secret Key", re.compile(r'(sk_live_[A-Za-z0-9]{24,})'), FindingSeverity.CRITICAL,
     "Stripe live secret key — full payment API access", 0.95),
    ("Stripe Publishable Key", re.compile(r'(pk_live_[A-Za-z0-9]{24,})'), FindingSeverity.MEDIUM,
     "Stripe publishable key (limited risk)", 0.8),
    ("Stripe Test Key", re.compile(r'(sk_test_[A-Za-z0-9]{24,})'), FindingSeverity.LOW,
     "Stripe test secret key", 0.6),
    ("Twilio Account SID", re.compile(r'(AC[a-f0-9]{32})'), FindingSeverity.HIGH,
     "Twilio account SID", 0.75),
    ("Twilio Auth Token", re.compile(r'(SK[a-f0-9]{32})'), FindingSeverity.HIGH,
     "Twilio auth token or API key SID", 0.8),
    ("SendGrid API Key", re.compile(r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})'), FindingSeverity.HIGH,
     "SendGrid API key", 0.9),
    ("Mailgun API Key", re.compile(r'(key-[a-f0-9]{32})'), FindingSeverity.HIGH,
     "Mailgun API key", 0.8),
    ("Square Access Token", re.compile(r'(sq0atp-[A-Za-z0-9_-]{22})'), FindingSeverity.HIGH,
     "Square access token", 0.85),
    ("Square OAuth Secret", re.compile(r'(sq0csp-[A-Za-z0-9_-]{43})'), FindingSeverity.CRITICAL,
     "Square OAuth secret", 0.85),
    ("PayPal Braintree Token", re.compile(r'access_token\$production\$[a-z0-9]+\$[a-f0-9]{32}'), FindingSeverity.CRITICAL,
     "PayPal/Braintree production access token", 0.9),

    # --- Chat / collaboration ---
    ("Slack Bot Token", re.compile(r'(xoxb-[0-9]+-[0-9A-Za-z]+)'), FindingSeverity.HIGH,
     "Slack bot token", 0.9),
    ("Slack User Token", re.compile(r'(xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+)'), FindingSeverity.HIGH,
     "Slack user token", 0.9),
    ("Slack Webhook", re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'), FindingSeverity.MEDIUM,
     "Slack incoming webhook URL", 0.85),
    ("Discord Bot Token", re.compile(r'((?:N|M|O)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})'), FindingSeverity.HIGH,
     "Discord bot token", 0.7),
    ("Discord Webhook", re.compile(r'(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)'), FindingSeverity.MEDIUM,
     "Discord webhook URL", 0.85),
    ("Telegram Bot Token", re.compile(r'(\d{8,10}:[A-Za-z0-9_-]{35})'), FindingSeverity.HIGH,
     "Telegram bot token", 0.75),

    # --- VCS ---
    ("GitHub Personal Access Token", re.compile(r'(ghp_[A-Za-z0-9]{36,})'), FindingSeverity.CRITICAL,
     "GitHub personal access token", 0.95),
    ("GitHub OAuth Token", re.compile(r'(gho_[A-Za-z0-9]{36,})'), FindingSeverity.CRITICAL,
     "GitHub OAuth access token", 0.95),
    ("GitHub App Token", re.compile(r'(ghu_[A-Za-z0-9]{36,})'), FindingSeverity.HIGH,
     "GitHub user-to-server token", 0.9),
    ("GitHub Fine-Grained Token", re.compile(r'(github_pat_[A-Za-z0-9_]{36,})'), FindingSeverity.CRITICAL,
     "GitHub fine-grained PAT", 0.95),
    ("GitLab Token", re.compile(r'(glpat-[A-Za-z0-9_-]{20,})'), FindingSeverity.CRITICAL,
     "GitLab personal access token", 0.9),
    ("Bitbucket App Password", re.compile(r'(?:bitbucket|bb).{0,20}(?:password|token|secret)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), FindingSeverity.HIGH,
     "Bitbucket app password", 0.6),

    # --- Crypto / keys ---
    ("RSA Private Key", re.compile(r'(-----BEGIN RSA PRIVATE KEY-----)'), FindingSeverity.CRITICAL,
     "RSA private key in source", 0.95),
    ("EC Private Key", re.compile(r'(-----BEGIN EC PRIVATE KEY-----)'), FindingSeverity.CRITICAL,
     "Elliptic curve private key in source", 0.95),
    ("Generic Private Key", re.compile(r'(-----BEGIN PRIVATE KEY-----)'), FindingSeverity.CRITICAL,
     "Private key in source", 0.95),
    ("PGP Private Key", re.compile(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)'), FindingSeverity.CRITICAL,
     "PGP private key block", 0.95),

    # --- JWT ---
    ("JSON Web Token", re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), FindingSeverity.HIGH,
     "Hardcoded JWT — may contain session data or secrets", 0.75),

    # --- Auth patterns ---
    ("Basic Auth Header", re.compile(r'(?:Authorization|auth)\s*[=:]\s*["\']?(Basic\s+[A-Za-z0-9+/=]{8,})["\']?', re.I), FindingSeverity.HIGH,
     "Hardcoded Basic auth credentials", 0.85),
    ("Bearer Token", re.compile(r'(?:Authorization|auth)\s*[=:]\s*["\']?(Bearer\s+[A-Za-z0-9._-]{20,})["\']?', re.I), FindingSeverity.HIGH,
     "Hardcoded Bearer token", 0.8),

    # --- Database URIs ---
    ("JDBC Connection String", re.compile(r'(jdbc:[a-z]+://[^\s"\'<>]{10,})'), FindingSeverity.HIGH,
     "JDBC connection string — may contain credentials", 0.8),
    ("MongoDB URI", re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]{10,})'), FindingSeverity.HIGH,
     "MongoDB connection URI", 0.8),
    ("Redis URI", re.compile(r'(redis://[^\s"\'<>]{5,})'), FindingSeverity.HIGH,
     "Redis connection URI", 0.8),
    ("PostgreSQL URI", re.compile(r'(postgres(?:ql)?://[^\s"\'<>]{10,})'), FindingSeverity.HIGH,
     "PostgreSQL connection URI", 0.8),
    ("MySQL URI", re.compile(r'(mysql://[^\s"\'<>]{10,})'), FindingSeverity.HIGH,
     "MySQL connection URI", 0.8),

    # --- Generic assignment patterns ---
    ("Generic API Key Assignment", re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,})["\']', re.I), FindingSeverity.MEDIUM,
     "Generic API key assignment", 0.55),
    ("Generic Secret Assignment", re.compile(r'(?:secret|client_secret|app_secret)\s*[=:]\s*["\']([A-Za-z0-9_/+=!@#$%^&*-]{8,})["\']', re.I), FindingSeverity.HIGH,
     "Generic secret value assignment", 0.6),
    ("Generic Password Assignment", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I), FindingSeverity.HIGH,
     "Hardcoded password", 0.6),
    ("Generic Token Assignment", re.compile(r'(?:access_token|auth_token|session_token)\s*[=:]\s*["\']([A-Za-z0-9_.-]{10,})["\']', re.I), FindingSeverity.HIGH,
     "Hardcoded token value", 0.6),
    ("Encryption Key Assignment", re.compile(r'(?:encryption[_-]?key|enc[_-]?key|aes[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), FindingSeverity.CRITICAL,
     "Hardcoded encryption key", 0.7),
    ("Signing Key Assignment", re.compile(r'(?:signing[_-]?key|sign[_-]?key|hmac[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), FindingSeverity.CRITICAL,
     "Hardcoded signing key", 0.7),

    # --- Misc cloud / services ---
    ("Azure Storage Key", re.compile(r'(?:AccountKey|azure_storage_key)\s*=\s*([A-Za-z0-9+/=]{44,})'), FindingSeverity.CRITICAL,
     "Azure storage account key", 0.85),
    ("Heroku API Key", re.compile(r'(heroku[_-]?api[_-]?key\s*[=:]\s*["\']?[a-f0-9-]{36})', re.I), FindingSeverity.HIGH,
     "Heroku API key", 0.8),
    ("Mapbox Token", re.compile(r'(pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{20,})'), FindingSeverity.MEDIUM,
     "Mapbox public token", 0.75),
    ("Algolia API Key", re.compile(r'(?:algolia|search)[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']?([a-f0-9]{32})["\']?', re.I), FindingSeverity.MEDIUM,
     "Algolia API key", 0.65),
]

# False-positive suppression: skip matches containing these
_FP_TOKENS = {
    "example.com", "localhost", "placeholder", "your_", "YOUR_", "xxx",
    "CHANGEME", "TODO", "FIXME", "insert_", "sample", "test_key", "<",
    "0000000000", "aaaaaaa", "123456",
}


# ---------------------------------------------------------------------------
# Module 1: ApkSecretScanModule
# ---------------------------------------------------------------------------

class ApkSecretScanModule(BaseModule):
    """Decompile APK and scan source for hardcoded secrets."""

    @property
    def name(self) -> str:
        return "apk_secrets"

    @property
    def display_name(self) -> str:
        return "APK Secret Scanner"

    @property
    def description(self) -> str:
        return "Decompile APK with jadx and scan code for hardcoded secrets, keys, tokens"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 600

    def _is_false_positive(self, match_text: str) -> bool:
        lower = match_text.lower()
        if any(fp in lower for fp in _FP_TOKENS):
            return True
        # All same char
        if len(set(match_text.replace("-", "").replace("_", ""))) <= 2:
            return True
        return False

    def _compute_confidence(self, match_text: str, base_conf: float) -> float:
        """Adjust confidence based on entropy."""
        entropy = _shannon_entropy(match_text)
        if len(match_text) < 12:
            threshold = 3.5
        else:
            threshold = 4.0

        if entropy >= threshold + 0.5:
            return min(1.0, base_conf + 0.1)
        elif entropy >= threshold:
            return base_conf
        else:
            return max(0.1, base_conf - 0.2)

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Decompiling APK with jadx...")

        decompiled = await _ensure_decompiled(self, apk_path, scan_context)
        if not decompiled:
            result.error = "Failed to decompile APK with jadx"
            return result

        if progress_callback:
            await progress_callback("Scanning decompiled source for secrets...")

        files = _collect_files(decompiled, _ALL_SCAN_EXTENSIONS)
        secrets_found: list[dict[str, Any]] = []
        seen_values: set[str] = set()

        for fpath in files:
            content = _read_file_safe(fpath)
            if not content:
                continue

            rel_path = os.path.relpath(fpath, decompiled)

            for line_num, line in enumerate(content.splitlines(), 1):
                for label, pattern, severity, desc, base_conf in _SECRET_PATTERNS:
                    for m in pattern.finditer(line):
                        matched = m.group(1) if m.lastindex else m.group(0)
                        matched = matched.strip()

                        if not matched or len(matched) < 4:
                            continue
                        if self._is_false_positive(matched):
                            continue

                        # Deduplicate
                        dedup_key = f"{label}:{matched}"
                        if dedup_key in seen_values:
                            continue
                        seen_values.add(dedup_key)

                        confidence = self._compute_confidence(matched, base_conf)

                        secrets_found.append({
                            "label": label,
                            "value": matched,
                            "file": rel_path,
                            "line": line_num,
                            "severity": severity,
                            "description": desc,
                            "confidence": confidence,
                            "context": line.strip()[:300],
                        })

        result.raw_output["total_files_scanned"] = len(files)
        result.raw_output["secrets_count"] = len(secrets_found)

        for secret in secrets_found:
            # Mask middle of value for evidence
            val = secret["value"]
            if len(val) > 10:
                masked = val[:6] + "***" + val[-4:]
            else:
                masked = val[:3] + "***"

            result.findings.append(
                ModuleFinding(
                    title=f"{secret['label']} Found",
                    description=f"{secret['description']}. "
                    f"Found in {secret['file']} at line {secret['line']}.",
                    severity=secret["severity"],
                    category="code_analysis",
                    evidence=f"File: {secret['file']}\n"
                    f"Line: {secret['line']}\n"
                    f"Value (masked): {masked}\n"
                    f"Context: {secret['context']}",
                    raw_data={"file": secret["file"], "line": secret["line"], "label": secret["label"]},
                    impact=f"Leaked {secret['label']} can be used by attackers to access "
                    "the corresponding service or system.",
                    remediation="Remove hardcoded secret from source. Use environment variables, "
                    "Android Keystore, or a secrets management service.",
                    cwe_id="CWE-798",
                    cvss_score=9.0 if secret["severity"] == FindingSeverity.CRITICAL else 7.5,
                    owasp_category="M9: Reverse Engineering",
                    confidence=secret["confidence"],
                    validation_hint=f"Check: grep -n '{val[:8]}' {secret['file']}",
                )
            )

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SECRET,
                    value=masked,
                    metadata={
                        "type": secret["label"],
                        "file": secret["file"],
                        "line": secret["line"],
                        "confidence": secret["confidence"],
                    },
                )
            )

        if not secrets_found:
            result.findings.append(
                ModuleFinding(
                    title="No Hardcoded Secrets Found",
                    description=f"Scanned {len(files)} files with {len(_SECRET_PATTERNS)} "
                    "patterns — no secrets detected.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Files scanned: {len(files)}",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        return result


# ---------------------------------------------------------------------------
# Module 2: EndpointExtractModule
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r'(https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{8,})'
)
_IP_PATTERN = re.compile(
    r'(?:^|["\'\s=:,])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:["\'\s:,;/]|$)'
)
_RETROFIT_PATTERN = re.compile(
    r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']+)["\']'
)
_OKHTTP_URL_PATTERN = re.compile(
    r'(?:Request\.Builder|HttpUrl|newCall)\s*\(?\s*\)?\s*\.?\s*url\s*\(\s*["\']([^"\']+)["\']'
)
_VOLLEY_PATTERN = re.compile(
    r'(?:String|Json(?:Object|Array))Request\s*\(\s*(?:Request\.Method\.\w+\s*,\s*)?["\']([^"\']+)["\']'
)
_HTTPURLCONNECTION_PATTERN = re.compile(
    r'(?:new\s+)?URL\s*\(\s*["\']([^"\']+)["\']'
)

_ANALYTICS_DOMAINS = {
    "google-analytics.com", "analytics.google.com", "firebase.google.com",
    "crashlytics.com", "app-measurement.com", "adjust.com", "appsflyer.com",
    "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
    "braze.com", "branch.io", "onelink.me", "mparticle.com", "heap.io",
    "fullstory.com", "hotjar.com", "sentry.io",
}

_THIRD_PARTY_DOMAINS = {
    "googleapis.com", "facebook.com", "graph.facebook.com",
    "twitter.com", "api.twitter.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "microsoft.com", "apple.com", "gstatic.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
}

_INTERNAL_IP_PATTERN = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)'
)

_SKIP_URL_PATTERNS = {
    "schemas.android.com", "www.w3.org", "ns.adobe.com",
    "xmlpull.org", "xml.org", "schemas.microsoft.com",
    "purl.org", "xmlns", "example.com",
}


class EndpointExtractModule(BaseModule):
    """Extract URLs, IPs, and API endpoints from decompiled code."""

    @property
    def name(self) -> str:
        return "apk_endpoints"

    @property
    def display_name(self) -> str:
        return "Endpoint Extractor"

    @property
    def description(self) -> str:
        return "Extract URLs, IPs, and API endpoints from decompiled APK source"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 300

    def _categorize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            return "unknown"

        if any(d in host for d in _ANALYTICS_DOMAINS):
            return "analytics"
        if any(d in host for d in _THIRD_PARTY_DOMAINS):
            return "third_party"
        if _INTERNAL_IP_PATTERN.match(host):
            return "internal"
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "10.0.2.2"):
            return "internal"
        return "api_endpoint"

    def _should_skip(self, url: str) -> bool:
        lower = url.lower()
        return any(skip in lower for skip in _SKIP_URL_PATTERNS)

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        decompiled = await _ensure_decompiled(self, apk_path, scan_context)
        if not decompiled:
            result.error = "Failed to decompile APK"
            return result

        if progress_callback:
            await progress_callback("Extracting endpoints from decompiled code...")

        files = _collect_files(decompiled, _ALL_SCAN_EXTENSIONS)

        urls: dict[str, dict[str, Any]] = {}  # url -> metadata
        ips: set[str] = set()
        retrofit_paths: list[dict[str, str]] = []

        for fpath in files:
            content = _read_file_safe(fpath)
            if not content:
                continue
            rel_path = os.path.relpath(fpath, decompiled)

            # URL extraction
            for m in _URL_PATTERN.finditer(content):
                url = m.group(1).rstrip(".,;)\"'")
                if self._should_skip(url):
                    continue
                if url not in urls:
                    urls[url] = {
                        "first_file": rel_path,
                        "category": self._categorize_url(url),
                        "count": 0,
                    }
                urls[url]["count"] += 1

            # IP extraction
            for m in _IP_PATTERN.finditer(content):
                ip = m.group(1)
                parts = ip.split(".")
                if all(0 <= int(p) <= 255 for p in parts):
                    ips.add(ip)

            # Retrofit annotations
            for m in _RETROFIT_PATTERN.finditer(content):
                path = m.group(1)
                retrofit_paths.append({"path": path, "file": rel_path})

            # OkHttp URLs
            for m in _OKHTTP_URL_PATTERN.finditer(content):
                url = m.group(1)
                if not self._should_skip(url) and url not in urls:
                    urls[url] = {"first_file": rel_path, "category": self._categorize_url(url), "count": 1}

            # Volley URLs
            for m in _VOLLEY_PATTERN.finditer(content):
                url = m.group(1)
                if not self._should_skip(url) and url.startswith("http") and url not in urls:
                    urls[url] = {"first_file": rel_path, "category": self._categorize_url(url), "count": 1}

            # HttpURLConnection
            for m in _HTTPURLCONNECTION_PATTERN.finditer(content):
                url = m.group(1)
                if url.startswith("http") and not self._should_skip(url) and url not in urls:
                    urls[url] = {"first_file": rel_path, "category": self._categorize_url(url), "count": 1}

        result.raw_output["urls_found"] = len(urls)
        result.raw_output["ips_found"] = len(ips)
        result.raw_output["retrofit_paths"] = len(retrofit_paths)

        # Categorize and create assets
        categories: dict[str, list[str]] = {}
        for url, meta in urls.items():
            cat = meta["category"]
            categories.setdefault(cat, []).append(url)
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=url,
                    metadata={
                        "category": cat,
                        "file": meta["first_file"],
                        "occurrences": meta["count"],
                    },
                )
            )

        for ip in ips:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.IP,
                    value=ip,
                    metadata={"source": "decompiled_code"},
                )
            )

        for rp in retrofit_paths:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=rp["path"],
                    metadata={"type": "retrofit_path", "file": rp["file"]},
                )
            )

        # Resolve API domains to IPs
        api_domains: set[str] = set()
        for url in categories.get("api_endpoint", []):
            try:
                parsed = urlparse(url)
                if parsed.hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname):
                    api_domains.add(parsed.hostname)
            except Exception:
                pass

        if progress_callback:
            await progress_callback(f"Resolving {len(api_domains)} API domains...")

        for domain in list(api_domains)[:50]:
            resolved = await self._resolve_dns(domain, "A")
            for ip in resolved:
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.IP,
                        value=ip,
                        metadata={"resolved_from": domain, "source": "endpoint_dns"},
                    )
                )

        # Findings
        internal_urls = categories.get("internal", [])
        if internal_urls:
            result.findings.append(
                ModuleFinding(
                    title=f"Internal/Development Endpoints Found ({len(internal_urls)})",
                    description="Internal IPs or localhost URLs found in decompiled code.",
                    severity=FindingSeverity.MEDIUM,
                    category="code_analysis",
                    evidence="Internal endpoints:\n" + "\n".join(f"  {u}" for u in internal_urls[:20]),
                    impact="Exposes internal infrastructure details. May be reachable from test networks.",
                    remediation="Remove internal endpoints from production builds. Use build flavors.",
                    cwe_id="CWE-200",
                    cvss_score=5.3,
                    confidence=0.85,
                )
            )

        if retrofit_paths:
            evidence = "\n".join(f"  {rp['path']} ({rp['file']})" for rp in retrofit_paths[:30])
            result.findings.append(
                ModuleFinding(
                    title=f"Retrofit API Paths Extracted ({len(retrofit_paths)})",
                    description="API paths from Retrofit annotations reveal backend endpoints.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Retrofit endpoints:\n{evidence}",
                    impact="API surface map for further testing.",
                    remediation="N/A — informational for attack surface mapping.",
                    confidence=0.9,
                )
            )

        # Summary
        result.findings.append(
            ModuleFinding(
                title=f"Endpoint Extraction Summary: {len(urls)} URLs, {len(ips)} IPs",
                description=f"Extracted endpoints from {len(files)} decompiled files. "
                f"Categories: {', '.join(f'{k}={len(v)}' for k, v in categories.items())}.",
                severity=FindingSeverity.INFO,
                category="code_analysis",
                evidence=f"Total URLs: {len(urls)}\nTotal IPs: {len(ips)}\n"
                f"Retrofit paths: {len(retrofit_paths)}",
                impact="Provides attack surface map for further testing.",
                remediation="Review endpoints for sensitive/internal exposure.",
                confidence=0.9,
            )
        )

        return result


# ---------------------------------------------------------------------------
# Module 3: CryptoAuditModule
# ---------------------------------------------------------------------------

_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str, str, str, float]] = [
    # (title, pattern, severity, description, impact, remediation, cvss)
    (
        "DES Encryption Used",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:DES(?:/[^"\']+)?)["\']'),
        FindingSeverity.HIGH,
        "DES is a broken cipher with 56-bit key — trivially brute-forceable.",
        "Encrypted data can be decrypted by attacker in seconds.",
        "Replace DES with AES-256-GCM.",
        7.5,
    ),
    (
        "3DES Encryption Used",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:DESede|TripleDES)(?:/[^"\']+)?["\']'),
        FindingSeverity.MEDIUM,
        "3DES is deprecated — vulnerable to Sweet32 attack.",
        "Encrypted data may be recoverable with sufficient ciphertext.",
        "Replace 3DES with AES-256-GCM.",
        5.3,
    ),
    (
        "AES ECB Mode",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES/ECB[^"\']*["\']'),
        FindingSeverity.HIGH,
        "AES in ECB mode does not use IV — identical plaintext blocks produce identical ciphertext.",
        "Patterns in plaintext leak through ciphertext. Padding oracle attacks possible.",
        "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with random IV.",
        7.0,
    ),
    (
        "AES CBC without Authenticated Encryption",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES/CBC/PKCS5Padding["\']'),
        FindingSeverity.LOW,
        "AES-CBC with PKCS5 padding is vulnerable to padding oracle attacks without HMAC.",
        "Potential padding oracle if ciphertext is malleable.",
        "Use AES/GCM/NoPadding for authenticated encryption.",
        3.7,
    ),
    (
        "RC4 Cipher Used",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARCFOUR)["\']'),
        FindingSeverity.HIGH,
        "RC4 stream cipher is broken — biases allow plaintext recovery.",
        "Encrypted data may be recoverable.",
        "Replace RC4 with AES-GCM.",
        7.5,
    ),
    (
        "MD5 Hash Used",
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'),
        FindingSeverity.MEDIUM,
        "MD5 is broken — collision attacks are practical.",
        "If used for integrity or signatures, can be forged. If for passwords, easily cracked.",
        "Use SHA-256 or SHA-3 for hashing. Use bcrypt/scrypt/argon2 for passwords.",
        5.3,
    ),
    (
        "SHA-1 Hash Used",
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']'),
        FindingSeverity.MEDIUM,
        "SHA-1 is deprecated — practical collision attacks demonstrated (SHAttered).",
        "Signatures and integrity checks using SHA-1 can be forged.",
        "Use SHA-256 or SHA-3.",
        5.3,
    ),
    (
        "Hardcoded Encryption Key",
        re.compile(
            r'(?:new\s+)?SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{[^}]+\}|'
            r'["\'][^"\']+["\']\.getBytes)'
        ),
        FindingSeverity.CRITICAL,
        "Encryption key is hardcoded in source — can be extracted by decompilation.",
        "All encrypted data can be decrypted by anyone with the APK.",
        "Use Android Keystore for key storage. Derive keys from user credentials + salt.",
        9.1,
    ),
    (
        "Insecure Random (java.util.Random)",
        re.compile(r'new\s+(?:java\.util\.)?Random\s*\('),
        FindingSeverity.MEDIUM,
        "java.util.Random is not cryptographically secure — predictable output.",
        "Tokens, nonces, or keys generated with Random are predictable.",
        "Use java.security.SecureRandom for cryptographic operations.",
        5.9,
    ),
    (
        "SecureRandom with Hardcoded Seed",
        re.compile(r'SecureRandom\s*\(\s*\)\s*;[^}]*\.setSeed\s*\(\s*(?:\d+L?|["\'][^"\']+["\']\.getBytes)'),
        FindingSeverity.HIGH,
        "SecureRandom seeded with a hardcoded value — output becomes deterministic.",
        "All cryptographic randomness becomes predictable.",
        "Do not call setSeed() on SecureRandom — it self-seeds from OS entropy.",
        7.5,
    ),
    (
        "Custom Crypto Implementation",
        re.compile(
            r'(?:class\s+\w*(?:Cipher|Encrypt|Crypto|AES|DES)\w*\s+'
            r'(?:extends|implements)|void\s+(?:encrypt|decrypt)\s*\([^)]*byte\s*\[\])'
        ),
        FindingSeverity.MEDIUM,
        "Custom cryptographic implementation detected — likely contains subtle flaws.",
        "Custom crypto is almost always weaker than standard library implementations.",
        "Use standard javax.crypto or Android Keystore APIs.",
        6.5,
    ),
    (
        "Null IV Used",
        re.compile(r'new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*(?:16|8)\s*\]'),
        FindingSeverity.HIGH,
        "Initialization vector is all zeros — eliminates IV randomization benefit.",
        "Identical plaintexts produce identical ciphertexts across encryptions.",
        "Generate random IV with SecureRandom for each encryption operation.",
        7.0,
    ),
    (
        "Hardcoded IV",
        re.compile(
            r'new\s+IvParameterSpec\s*\(\s*(?:["\'][^"\']+["\']\.getBytes|'
            r'new\s+byte\s*\[\s*\]\s*\{[^}]+\})'
        ),
        FindingSeverity.HIGH,
        "Hardcoded initialization vector — reuse across encryptions is insecure.",
        "IV reuse enables ciphertext analysis attacks.",
        "Generate a unique random IV per encryption operation.",
        7.0,
    ),
    (
        "Bouncy Castle with Weak Params",
        re.compile(r'(?:Bouncy|BC).*(?:DES|RC[24]|MD5|SHA1)', re.I),
        FindingSeverity.MEDIUM,
        "Bouncy Castle provider used with weak algorithm.",
        "Weak algorithm regardless of provider.",
        "Use strong algorithms (AES-GCM, SHA-256+) even with Bouncy Castle.",
        5.3,
    ),
]


class CryptoAuditModule(BaseModule):
    """Audit decompiled code for weak cryptographic usage."""

    @property
    def name(self) -> str:
        return "apk_crypto_audit"

    @property
    def display_name(self) -> str:
        return "Crypto Audit"

    @property
    def description(self) -> str:
        return "Detect weak crypto: DES, ECB, MD5, SHA-1, hardcoded keys, insecure random"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 180

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        decompiled = await _ensure_decompiled(self, apk_path, scan_context)
        if not decompiled:
            result.error = "Failed to decompile APK"
            return result

        if progress_callback:
            await progress_callback("Auditing cryptographic implementations...")

        files = _collect_files(decompiled, _SOURCE_EXTENSIONS)
        findings_count = 0

        for fpath in files:
            content = _read_file_safe(fpath)
            if not content:
                continue
            rel_path = os.path.relpath(fpath, decompiled)
            lines = content.splitlines()

            for title, pattern, severity, desc, impact, remed, cvss in _CRYPTO_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.search(line):
                        # Grab context (2 lines before and after)
                        start = max(0, line_num - 3)
                        end = min(len(lines), line_num + 2)
                        context_lines = lines[start:end]
                        context = "\n".join(
                            f"  {start + i + 1}: {l}" for i, l in enumerate(context_lines)
                        )

                        result.findings.append(
                            ModuleFinding(
                                title=title,
                                description=f"{desc} Found in {rel_path} at line {line_num}.",
                                severity=severity,
                                category="code_analysis",
                                evidence=f"File: {rel_path}\nLine: {line_num}\n\n{context}",
                                impact=impact,
                                remediation=remed,
                                cwe_id="CWE-327",
                                cvss_score=cvss,
                                owasp_category="M5: Insufficient Cryptography",
                                confidence=0.85,
                            )
                        )
                        findings_count += 1

        if findings_count == 0:
            result.findings.append(
                ModuleFinding(
                    title="No Weak Cryptography Detected",
                    description=f"Scanned {len(files)} source files — no weak crypto patterns found.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Files scanned: {len(files)}",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        result.raw_output["files_scanned"] = len(files)
        result.raw_output["crypto_findings"] = findings_count
        return result


# ---------------------------------------------------------------------------
# Module 4: StoragePatternsModule
# ---------------------------------------------------------------------------

_STORAGE_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str, str, str, str]] = [
    (
        "World-Readable SharedPreferences",
        re.compile(r'getSharedPreferences\s*\([^)]*MODE_WORLD_READABLE'),
        FindingSeverity.HIGH,
        "SharedPreferences opened with MODE_WORLD_READABLE — any app can read the data.",
        "Stored tokens, credentials, or PII readable by any app on device.",
        "Use MODE_PRIVATE. Use EncryptedSharedPreferences for sensitive data.",
        "CWE-732",
    ),
    (
        "World-Writable SharedPreferences",
        re.compile(r'getSharedPreferences\s*\([^)]*MODE_WORLD_WRITEABLE'),
        FindingSeverity.HIGH,
        "SharedPreferences opened with MODE_WORLD_WRITEABLE — any app can modify the data.",
        "Malicious app can tamper with app configuration or inject data.",
        "Use MODE_PRIVATE.",
        "CWE-732",
    ),
    (
        "External Storage Write",
        re.compile(
            r'(?:getExternalStorageDirectory|getExternalFilesDir|'
            r'Environment\.getExternalStoragePublicDirectory)\s*\('
        ),
        FindingSeverity.MEDIUM,
        "App writes to external storage which is world-readable on pre-Android-10.",
        "Sensitive files on external storage accessible to all apps.",
        "Use internal storage (getFilesDir) for sensitive data. Use Scoped Storage.",
        "CWE-922",
    ),
    (
        "SQLite Database Open",
        re.compile(r'(?:openOrCreateDatabase|SQLiteDatabase\.openDatabase)\s*\('),
        FindingSeverity.LOW,
        "SQLite database creation detected — check for sensitive data storage.",
        "Unencrypted databases on rooted devices expose all contents.",
        "Use SQLCipher for encrypted database storage.",
        "CWE-312",
    ),
    (
        "File Write with External Path",
        re.compile(
            r'new\s+File(?:Output(?:Stream)?|Writer)\s*\(\s*(?:'
            r'(?:getExternalStorageDirectory|"/sdcard"|"/mnt/sdcard"|"/storage/emulated"))'
        ),
        FindingSeverity.MEDIUM,
        "File I/O to external storage path detected.",
        "Files written to external storage are accessible to all apps.",
        "Write sensitive data to internal storage only.",
        "CWE-922",
    ),
    (
        "Cleartext Data in SharedPreferences",
        re.compile(
            r'\.edit\s*\(\s*\)\s*\.put(?:String|Int|Long)\s*\(\s*["\']'
            r'(?:password|token|secret|api_key|auth|credential|session|pin|ssn|credit_card)'
            r'["\']',
            re.I,
        ),
        FindingSeverity.HIGH,
        "Sensitive data stored in cleartext SharedPreferences.",
        "Data extractable via backup (adb backup) or on rooted device.",
        "Use EncryptedSharedPreferences from AndroidX Security library.",
        "CWE-312",
    ),
    (
        "Sensitive Column in ContentValues",
        re.compile(
            r'(?:ContentValues|put)\s*[\.(]\s*["\']'
            r'(?:password|token|secret|api_key|auth_token|session_id|private_key|'
            r'credit_card|ssn|pin_code|security_answer|encryption_key)'
            r'["\']',
            re.I,
        ),
        FindingSeverity.MEDIUM,
        "Sensitive-looking column name written to database via ContentValues.",
        "Sensitive data may be stored unencrypted in SQLite.",
        "Encrypt sensitive columns or use SQLCipher for whole-database encryption.",
        "CWE-312",
    ),
    (
        "Internal Storage MODE_WORLD_READABLE",
        re.compile(r'openFileOutput\s*\([^)]*MODE_WORLD_READABLE'),
        FindingSeverity.HIGH,
        "Internal file opened with MODE_WORLD_READABLE.",
        "Any app can read the file contents.",
        "Use MODE_PRIVATE for all internal files.",
        "CWE-732",
    ),
    (
        "WebView Cache/Storage",
        re.compile(r'(?:setDomStorageEnabled|setDatabaseEnabled|setAppCacheEnabled)\s*\(\s*true\s*\)'),
        FindingSeverity.LOW,
        "WebView DOM storage / app cache enabled — data persists on disk.",
        "Cached web data may contain tokens or PII on disk.",
        "Clear WebView data on logout. Disable caching for sensitive views.",
        "CWE-922",
    ),
    (
        "Logging Sensitive Data",
        re.compile(
            r'Log\.\w\s*\(\s*[^)]*(?:password|token|secret|key|auth|credential|session)',
            re.I,
        ),
        FindingSeverity.MEDIUM,
        "Potentially sensitive data written to Android log (logcat).",
        "Any app with READ_LOGS (pre-4.1) or adb can read logged secrets.",
        "Remove sensitive data from log statements. Use ProGuard to strip logs.",
        "CWE-532",
    ),
]


class StoragePatternsModule(BaseModule):
    """Detect insecure data storage patterns in decompiled code."""

    @property
    def name(self) -> str:
        return "apk_storage"

    @property
    def display_name(self) -> str:
        return "Storage Patterns"

    @property
    def description(self) -> str:
        return "Detect insecure data storage: world-readable prefs, external storage, sensitive DB columns"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 180

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        decompiled = await _ensure_decompiled(self, apk_path, scan_context)
        if not decompiled:
            result.error = "Failed to decompile APK"
            return result

        if progress_callback:
            await progress_callback("Scanning for insecure storage patterns...")

        files = _collect_files(decompiled, _SOURCE_EXTENSIONS)
        seen: set[str] = set()
        total_found = 0

        for fpath in files:
            content = _read_file_safe(fpath)
            if not content:
                continue
            rel_path = os.path.relpath(fpath, decompiled)
            lines = content.splitlines()

            for title, pattern, severity, desc, impact, remed, cwe in _STORAGE_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.search(line):
                        dedup = f"{title}:{rel_path}:{line_num}"
                        if dedup in seen:
                            continue
                        seen.add(dedup)

                        start = max(0, line_num - 3)
                        end = min(len(lines), line_num + 2)
                        context = "\n".join(
                            f"  {start + i + 1}: {l}" for i, l in enumerate(lines[start:end])
                        )

                        result.findings.append(
                            ModuleFinding(
                                title=title,
                                description=f"{desc} Found in {rel_path} at line {line_num}.",
                                severity=severity,
                                category="code_analysis",
                                evidence=f"File: {rel_path}\nLine: {line_num}\n\n{context}",
                                impact=impact,
                                remediation=remed,
                                cwe_id=cwe,
                                owasp_category="M2: Insecure Data Storage",
                                confidence=0.8,
                            )
                        )
                        total_found += 1

        if total_found == 0:
            result.findings.append(
                ModuleFinding(
                    title="No Insecure Storage Patterns Found",
                    description=f"Scanned {len(files)} files — no insecure storage patterns detected.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Files scanned: {len(files)}",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        result.raw_output["files_scanned"] = len(files)
        result.raw_output["storage_findings"] = total_found
        return result


# ---------------------------------------------------------------------------
# Module 5: WebviewAuditModule
# ---------------------------------------------------------------------------

_WEBVIEW_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str, str, str, str, float]] = [
    (
        "JavaScript Enabled in WebView",
        re.compile(r'\.setJavaScriptEnabled\s*\(\s*true\s*\)'),
        FindingSeverity.MEDIUM,
        "WebView has JavaScript enabled — prerequisite for XSS via WebView.",
        "If WebView loads untrusted content, JS execution enables XSS attacks.",
        "Disable JS if not needed. Apply strict CSP. Validate loaded URLs.",
        "CWE-79",
        0.75,
    ),
    (
        "JavaScript Interface Exposed",
        re.compile(r'\.addJavascriptInterface\s*\('),
        FindingSeverity.HIGH,
        "Native Java object exposed to JavaScript via addJavascriptInterface. "
        "On API < 17, ALL public methods are callable from JS.",
        "Attacker-controlled JS can invoke native methods — potential RCE on old devices.",
        "Remove if not needed. Annotate methods with @JavascriptInterface (API 17+). "
        "Never expose on API < 17.",
        "CWE-749",
        0.85,
    ),
    (
        "File Access Enabled in WebView",
        re.compile(r'\.setAllowFileAccess\s*\(\s*true\s*\)'),
        FindingSeverity.HIGH,
        "WebView allows file:// access — can read local files.",
        "XSS in WebView can read app private files via file:// protocol.",
        "Set setAllowFileAccess(false). Use WebViewAssetLoader for local resources.",
        "CWE-22",
        0.8,
    ),
    (
        "File Access From File URLs Enabled",
        re.compile(r'\.setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)'),
        FindingSeverity.HIGH,
        "file:// pages can access other file:// URLs — bypasses same-origin for local files.",
        "XSS in a file:// context can read any file the app can access.",
        "Set setAllowFileAccessFromFileURLs(false) (default since API 16).",
        "CWE-22",
        0.85,
    ),
    (
        "Universal File Access From File URLs",
        re.compile(r'\.setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)'),
        FindingSeverity.CRITICAL,
        "file:// pages can access ANY origin — complete same-origin bypass.",
        "XSS in file context can access all web origins AND local files.",
        "Set setAllowUniversalAccessFromFileURLs(false) (default since API 16).",
        "CWE-346",
        0.9,
    ),
    (
        "Mixed Content Always Allowed",
        re.compile(r'\.setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)'),
        FindingSeverity.MEDIUM,
        "WebView loads HTTP resources on HTTPS pages — MITM can inject content.",
        "Attacker on network can inject malicious scripts via HTTP sub-resources.",
        "Use MIXED_CONTENT_NEVER_ALLOW or MIXED_CONTENT_COMPATIBILITY_MODE.",
        "CWE-319",
        0.8,
    ),
    (
        "WebView loadUrl with Variable",
        re.compile(r'\.loadUrl\s*\(\s*(?!["\']).+\)'),
        FindingSeverity.MEDIUM,
        "WebView.loadUrl() called with a variable — may load attacker-controlled URL.",
        "If URL comes from intent/deeplink, attacker can load arbitrary pages in WebView.",
        "Validate URLs against allowlist. Never load URLs from untrusted intents.",
        "CWE-601",
        0.6,
    ),
    (
        "WebView Content Access Enabled",
        re.compile(r'\.setAllowContentAccess\s*\(\s*true\s*\)'),
        FindingSeverity.MEDIUM,
        "WebView can access content:// URIs — potential data leak via provider.",
        "JS in WebView can read from exported content providers.",
        "Set setAllowContentAccess(false) unless explicitly needed.",
        "CWE-927",
        0.75,
    ),
    (
        "WebView Debugging Enabled",
        re.compile(r'WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)'),
        FindingSeverity.MEDIUM,
        "WebView remote debugging enabled — Chrome DevTools can inspect all WebViews.",
        "On device, attacker app can extract data from WebView via chrome://inspect.",
        "Disable WebView debugging in release builds.",
        "CWE-489",
        0.85,
    ),
    (
        "SSL Error Handler Override",
        re.compile(r'onReceivedSslError\s*\([^)]*\)\s*\{[^}]*handler\.proceed'),
        FindingSeverity.CRITICAL,
        "WebView SSL error handler overridden to proceed on certificate errors.",
        "MITM attacks succeed because invalid/self-signed certs are accepted.",
        "Do not override onReceivedSslError to proceed. Cancel by default.",
        "CWE-295",
        0.9,
    ),
]


class WebviewAuditModule(BaseModule):
    """Audit WebView configurations for security issues."""

    @property
    def name(self) -> str:
        return "apk_webview"

    @property
    def display_name(self) -> str:
        return "WebView Audit"

    @property
    def description(self) -> str:
        return "Detect insecure WebView settings: JS enabled, file access, JS interfaces"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 180

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        decompiled = await _ensure_decompiled(self, apk_path, scan_context)
        if not decompiled:
            result.error = "Failed to decompile APK"
            return result

        if progress_callback:
            await progress_callback("Auditing WebView configurations...")

        files = _collect_files(decompiled, _SOURCE_EXTENSIONS)
        seen: set[str] = set()
        total_found = 0

        # Track per-file flags for combination checks
        file_flags: dict[str, set[str]] = {}

        for fpath in files:
            content = _read_file_safe(fpath)
            if not content:
                continue
            rel_path = os.path.relpath(fpath, decompiled)
            lines = content.splitlines()
            file_flags[rel_path] = set()

            for title, pattern, severity, desc, impact, remed, cwe, conf in _WEBVIEW_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.search(line):
                        file_flags[rel_path].add(title)

                        dedup = f"{title}:{rel_path}:{line_num}"
                        if dedup in seen:
                            continue
                        seen.add(dedup)

                        start = max(0, line_num - 3)
                        end = min(len(lines), line_num + 2)
                        context = "\n".join(
                            f"  {start + i + 1}: {l}" for i, l in enumerate(lines[start:end])
                        )

                        result.findings.append(
                            ModuleFinding(
                                title=title,
                                description=f"{desc} Found in {rel_path} at line {line_num}.",
                                severity=severity,
                                category="code_analysis",
                                evidence=f"File: {rel_path}\nLine: {line_num}\n\n{context}",
                                impact=impact,
                                remediation=remed,
                                cwe_id=cwe,
                                owasp_category="M1: Improper Platform Usage",
                                confidence=conf,
                            )
                        )
                        total_found += 1

        # --- Combination findings ---
        for rel_path, flags in file_flags.items():
            # JS Interface + File Access = critical combo
            if "JavaScript Interface Exposed" in flags and (
                "File Access Enabled in WebView" in flags
                or "File Access From File URLs Enabled" in flags
                or "Universal File Access From File URLs" in flags
            ):
                result.findings.append(
                    ModuleFinding(
                        title="JavaScript Interface + File Access (Critical Combo)",
                        description=f"In {rel_path}: WebView exposes JS interface AND allows file access. "
                        "JS code can invoke native methods AND read local files.",
                        severity=FindingSeverity.CRITICAL,
                        category="code_analysis",
                        evidence=f"File: {rel_path}\nFlags: {', '.join(sorted(flags))}",
                        impact="Remote code execution via XSS in WebView — JS can call native "
                        "Java methods and read arbitrary local files.",
                        remediation="Remove JS interface or disable file access. Never combine both.",
                        cwe_id="CWE-749",
                        cvss_score=9.0,
                        owasp_category="M1: Improper Platform Usage",
                        confidence=0.85,
                    )
                )

            # SSL bypass + JS enabled
            if "SSL Error Handler Override" in flags and "JavaScript Enabled in WebView" in flags:
                result.findings.append(
                    ModuleFinding(
                        title="SSL Bypass + JavaScript (MITM-to-XSS Chain)",
                        description=f"In {rel_path}: WebView ignores SSL errors AND has JS enabled. "
                        "MITM attacker can inject and execute JS.",
                        severity=FindingSeverity.CRITICAL,
                        category="code_analysis",
                        evidence=f"File: {rel_path}\nFlags: SSL Error Override + JS Enabled",
                        impact="Network attacker can inject JS into WebView via MITM.",
                        remediation="Fix SSL error handler. Implement certificate pinning.",
                        cwe_id="CWE-295",
                        cvss_score=9.0,
                        confidence=0.85,
                    )
                )

        if total_found == 0:
            result.findings.append(
                ModuleFinding(
                    title="No WebView Security Issues Found",
                    description=f"Scanned {len(files)} files — no insecure WebView patterns detected.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Files scanned: {len(files)}",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        result.raw_output["files_scanned"] = len(files)
        result.raw_output["webview_findings"] = total_found
        return result
