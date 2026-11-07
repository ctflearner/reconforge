"""SSL/TLS, security headers, and CORS analysis modules."""
from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl
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

logger = logging.getLogger(__name__)


def _extract_host_port(target: str) -> tuple[str, int]:
    """Parse target URL into (hostname, port). Default port 443."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or parsed.path.split("/")[0]
    port = parsed.port or (443 if parsed.scheme != "http" else 80)
    return host, port


# ---------------------------------------------------------------------------
# 1. SSL/TLS Analysis
# ---------------------------------------------------------------------------


class SslAnalysisModule(BaseModule):
    """Connect to target via SSL/TLS, pull certificate chain, and flag weaknesses."""

    @property
    def name(self) -> str:
        return "ssl_analysis"

    @property
    def display_name(self) -> str:
        return "SSL/TLS Analysis"

    @property
    def description(self) -> str:
        return (
            "Retrieve the SSL/TLS certificate chain and analyse for expiry, "
            "weak keys, weak signatures, self-signed certs, and SAN entries"
        )

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "SSL/TLS"

    @property
    def timeout(self) -> int:
        return 30

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        host, port = _extract_host_port(target)

        if progress_callback:
            await progress_callback(f"Connecting to {host}:{port} for SSL/TLS analysis...")

        # --- Fetch certificate -----------------------------------------------------------
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    peer_cert = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()
        except Exception as exc:
            result.error = f"SSL connection failed: {exc}"
            return result

        if not der_cert:
            result.error = "No certificate returned by the server"
            return result

        # --- Parse certificate fields via openssl (more reliable for key size etc.) ------
        import asyncio
        import tempfile, os

        cert_info: dict[str, Any] = {}

        # Decode using ssl module's dict if available
        if peer_cert:
            cert_info["subject"] = _x509_name_to_str(peer_cert.get("subject", ()))
            cert_info["issuer"] = _x509_name_to_str(peer_cert.get("issuer", ()))
            cert_info["serial"] = peer_cert.get("serialNumber", "")
            cert_info["not_before"] = peer_cert.get("notBefore", "")
            cert_info["not_after"] = peer_cert.get("notAfter", "")

            # SAN names
            san_entries: list[str] = []
            for entry_type, value in peer_cert.get("subjectAltName", ()):
                san_entries.append(value)
            cert_info["san"] = san_entries
        else:
            cert_info["san"] = []

        # Use openssl x509 to extract key size and signature algorithm from DER
        key_bits: int | None = None
        sig_algo: str = ""
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".der")
            os.write(tmp_fd, der_cert)
            os.close(tmp_fd)

            proc = await asyncio.create_subprocess_exec(
                "openssl", "x509", "-inform", "DER", "-in", tmp_path,
                "-noout", "-text",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text_out = stdout_bytes.decode(errors="replace")
            os.unlink(tmp_path)

            # Key size
            m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text_out)
            if m:
                key_bits = int(m.group(1))
            cert_info["key_bits"] = key_bits

            # Signature algorithm
            m = re.search(r"Signature Algorithm:\s*(\S+)", text_out)
            if m:
                sig_algo = m.group(1)
            cert_info["signature_algorithm"] = sig_algo

        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        cert_info["protocol"] = protocol_version
        cert_info["cipher"] = cipher[0] if cipher else ""
        cert_info["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else None
        cert_info["sha256_fingerprint"] = hashlib.sha256(der_cert).hexdigest()

        result.raw_output["certificate"] = cert_info

        # --- Determine expiry dates ------------------------------------------------------
        not_after_str = cert_info.get("not_after", "")
        not_before_str = cert_info.get("not_before", "")
        now = datetime.now(timezone.utc)
        expiry_dt: datetime | None = None
        days_remaining: int | None = None

        if not_after_str:
            try:
                expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_remaining = (expiry_dt - now).days
                cert_info["days_remaining"] = days_remaining
            except ValueError:
                pass

        # --- Certificate asset -----------------------------------------------------------
        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.CERTIFICATE,
                value=f"{host}:{port}",
                metadata={
                    "subject": cert_info.get("subject", ""),
                    "issuer": cert_info.get("issuer", ""),
                    "not_after": not_after_str,
                    "days_remaining": days_remaining,
                    "key_bits": key_bits,
                    "signature_algorithm": sig_algo,
                    "sha256": cert_info.get("sha256_fingerprint", ""),
                },
            )
        )

        # --- SAN domain/subdomain assets -------------------------------------------------
        for san in cert_info.get("san", []):
            san_clean = san.lstrip("*.")
            if san_clean and "." in san_clean:
                atype = AssetType.SUBDOMAIN if san_clean.count(".") > 1 else AssetType.DOMAIN
                result.assets.append(
                    ModuleAsset(
                        asset_type=atype,
                        value=san_clean,
                        metadata={"source": "certificate_san", "original": san},
                    )
                )

        # --- Findings --------------------------------------------------------------------

        # 1. Expired certificate
        if days_remaining is not None and days_remaining < 0:
            result.findings.append(
                ModuleFinding(
                    title="SSL Certificate Expired",
                    description=f"The certificate for {host} expired {abs(days_remaining)} days ago "
                    f"(expiry: {not_after_str}).",
                    severity=FindingSeverity.HIGH,
                    category="SSL/TLS",
                    evidence=f"notAfter: {not_after_str}\nDays past expiry: {abs(days_remaining)}",
                    impact="Browsers will reject the connection. Users may click through warnings, "
                    "enabling MITM attacks.",
                    remediation="Renew the SSL certificate immediately.",
                    cwe_id="CWE-295",
                    cvss_score=7.4,
                    confidence=0.99,
                )
            )

        # 2. Expiring soon
        elif days_remaining is not None and 0 <= days_remaining <= 30:
            result.findings.append(
                ModuleFinding(
                    title="SSL Certificate Expiring Soon",
                    description=f"Certificate expires in {days_remaining} days ({not_after_str}).",
                    severity=FindingSeverity.MEDIUM,
                    category="SSL/TLS",
                    evidence=f"notAfter: {not_after_str}\nDays remaining: {days_remaining}",
                    impact="Service will become untrusted if not renewed before expiry.",
                    remediation="Renew the certificate before expiry. Consider automated renewal (Let's Encrypt / ACME).",
                    cwe_id="CWE-295",
                    cvss_score=5.0,
                    confidence=0.95,
                )
            )

        # 3. Self-signed
        subject = cert_info.get("subject", "")
        issuer = cert_info.get("issuer", "")
        if subject and issuer and subject == issuer:
            result.findings.append(
                ModuleFinding(
                    title="Self-Signed Certificate",
                    description=f"Certificate on {host} is self-signed (subject == issuer).",
                    severity=FindingSeverity.HIGH,
                    category="SSL/TLS",
                    evidence=f"Subject: {subject}\nIssuer: {issuer}",
                    impact="Browsers will not trust this certificate. Users trained to bypass "
                    "warnings become vulnerable to MITM.",
                    remediation="Obtain a certificate from a trusted Certificate Authority.",
                    cwe_id="CWE-295",
                    cvss_score=7.4,
                    confidence=0.95,
                )
            )

        # 4. Weak key size
        if key_bits is not None and key_bits < 2048:
            result.findings.append(
                ModuleFinding(
                    title=f"Weak Certificate Key Size ({key_bits} bits)",
                    description=f"The certificate uses a {key_bits}-bit key, which is below "
                    "the minimum recommended 2048 bits for RSA.",
                    severity=FindingSeverity.HIGH,
                    category="SSL/TLS",
                    evidence=f"Key size: {key_bits} bits\nMinimum recommended: 2048 bits",
                    impact="Weak keys can be factored with sufficient compute, allowing "
                    "certificate forgery and MITM attacks.",
                    remediation="Reissue the certificate with at least a 2048-bit RSA key (4096 preferred) "
                    "or 256-bit ECDSA key.",
                    cwe_id="CWE-326",
                    cvss_score=7.5,
                    confidence=0.95,
                )
            )

        # 5. Weak signature algorithm (SHA-1)
        if sig_algo and ("sha1" in sig_algo.lower() or "sha-1" in sig_algo.lower()):
            result.findings.append(
                ModuleFinding(
                    title="Weak Signature Algorithm (SHA-1)",
                    description=f"Certificate uses {sig_algo} signature algorithm. "
                    "SHA-1 is deprecated and collision attacks are practical.",
                    severity=FindingSeverity.MEDIUM,
                    category="SSL/TLS",
                    evidence=f"Signature Algorithm: {sig_algo}",
                    impact="SHA-1 collisions are feasible, enabling certificate forgery.",
                    remediation="Reissue with SHA-256 or stronger signature algorithm.",
                    cwe_id="CWE-328",
                    cvss_score=5.9,
                    confidence=0.95,
                )
            )

        # 6. Wildcard certificate
        wildcard_sans = [s for s in cert_info.get("san", []) if s.startswith("*.")]
        if wildcard_sans:
            result.findings.append(
                ModuleFinding(
                    title="Wildcard Certificate In Use",
                    description=f"Certificate includes wildcard SAN(s): {', '.join(wildcard_sans)}. "
                    "A compromised private key affects all subdomains.",
                    severity=FindingSeverity.INFO,
                    category="SSL/TLS",
                    evidence=f"Wildcard SANs: {', '.join(wildcard_sans)}",
                    impact="If the private key is compromised, attacker can impersonate any "
                    "subdomain covered by the wildcard.",
                    remediation="Consider per-service certificates for sensitive subdomains. "
                    "Store the private key securely with restricted access.",
                    confidence=0.9,
                )
            )

        # 7. Summary finding
        result.findings.append(
            ModuleFinding(
                title=f"SSL/TLS Summary for {host}",
                description=(
                    f"Protocol: {protocol_version}, Cipher: {cert_info.get('cipher', 'N/A')}, "
                    f"Key: {key_bits or 'unknown'} bits, SigAlgo: {sig_algo or 'unknown'}, "
                    f"SANs: {len(cert_info.get('san', []))}, "
                    f"Expiry: {not_after_str} ({days_remaining} days)"
                ),
                severity=FindingSeverity.INFO,
                category="SSL/TLS",
                evidence=(
                    f"Host: {host}:{port}\n"
                    f"Protocol: {protocol_version}\n"
                    f"Cipher: {cert_info.get('cipher', 'N/A')} ({cert_info.get('cipher_bits', '?')} bits)\n"
                    f"Subject: {subject}\n"
                    f"Issuer: {issuer}\n"
                    f"SANs: {', '.join(cert_info.get('san', []))}\n"
                    f"Key: {key_bits} bits, Algorithm: {sig_algo}\n"
                    f"Valid: {not_before_str} — {not_after_str}\n"
                    f"SHA-256: {cert_info.get('sha256_fingerprint', '')}"
                ),
                impact="Informational — certificate metadata for further analysis.",
                remediation="N/A",
                confidence=1.0,
            )
        )

        return result


def _x509_name_to_str(name_tuple: tuple) -> str:
    """Convert the nested tuple from ssl.getpeercert() subject/issuer to a flat string."""
    parts: list[str] = []
    for rdn in name_tuple:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# 2. Security Headers
# ---------------------------------------------------------------------------

# Expected headers: (header_lower, display_name, severity, cwe, impact, remediation)
_SECURITY_HEADERS: list[tuple[str, str, FindingSeverity, str, str, str]] = [
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS)",
        FindingSeverity.MEDIUM,
        "CWE-319",
        "Without HSTS the browser may connect over HTTP first, enabling SSL-stripping MITM attacks.",
        "Add the Strict-Transport-Security header with a long max-age (e.g. 31536000) and includeSubDomains.",
    ),
    (
        "content-security-policy",
        "Content-Security-Policy (CSP)",
        FindingSeverity.MEDIUM,
        "CWE-1021",
        "Without CSP the browser has no restrictions on inline scripts, framing, or resource origins — "
        "increases XSS impact.",
        "Implement a strict Content-Security-Policy. Start with report-only mode and iteratively tighten.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        FindingSeverity.LOW,
        "CWE-1021",
        "Page can be framed by any origin, enabling clickjacking attacks.",
        "Set X-Frame-Options to DENY or SAMEORIGIN. Prefer CSP frame-ancestors directive.",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        FindingSeverity.LOW,
        "CWE-16",
        "Without nosniff, browsers may MIME-sniff responses and execute content as a different type.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        FindingSeverity.LOW,
        "",
        "Sensitive URL paths or query parameters may leak to third parties via the Referer header.",
        "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        FindingSeverity.LOW,
        "",
        "Without Permissions-Policy, embedded content may access powerful features (camera, mic, geolocation).",
        "Set Permissions-Policy to disable unused browser features.",
    ),
]


class SecurityHeadersModule(BaseModule):
    """Fetch a URL and audit HTTP security headers."""

    @property
    def name(self) -> str:
        return "security_headers"

    @property
    def display_name(self) -> str:
        return "Security Headers"

    @property
    def description(self) -> str:
        return "Check for missing or misconfigured HTTP security headers"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "HTTP Security"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        url = target if "://" in target else f"https://{target}"

        if progress_callback:
            await progress_callback(f"Fetching headers from {url}...")

        resp = await self._http_get(url)
        if resp.get("error"):
            result.error = f"HTTP request failed: {resp['error']}"
            return result

        headers_lower: dict[str, str] = {
            k.lower(): v for k, v in resp.get("headers", {}).items()
        }

        result.raw_output["status"] = resp["status"]
        result.raw_output["url"] = resp["url"]
        result.raw_output["headers"] = resp.get("headers", {})

        present_count = 0
        total_checked = len(_SECURITY_HEADERS)

        # --- Check each expected header --------------------------------------------------
        for header_key, display, severity, cwe, impact, remediation in _SECURITY_HEADERS:
            value = headers_lower.get(header_key)
            if value:
                present_count += 1
            else:
                result.findings.append(
                    ModuleFinding(
                        title=f"Missing Header: {display}",
                        description=f"The response from {url} does not include the {display} header.",
                        severity=severity,
                        category="HTTP Security",
                        evidence=f"Header '{header_key}' not present in response.\n"
                        f"HTTP {resp['status']} {resp['url']}",
                        impact=impact,
                        remediation=remediation,
                        cwe_id=cwe,
                        confidence=0.95,
                    )
                )

        # --- X-XSS-Protection set to 0 --------------------------------------------------
        xxss = headers_lower.get("x-xss-protection", "")
        if xxss.strip().startswith("0"):
            result.findings.append(
                ModuleFinding(
                    title="X-XSS-Protection Explicitly Disabled",
                    description="X-XSS-Protection is set to 0. While the header is deprecated in "
                    "modern browsers, explicitly disabling it removes a defense layer in older browsers.",
                    severity=FindingSeverity.INFO,
                    category="HTTP Security",
                    evidence=f"X-XSS-Protection: {xxss}",
                    impact="Legacy browsers lose their built-in XSS filter.",
                    remediation="Remove the header entirely (modern approach) or set to '1; mode=block' for legacy support.",
                    confidence=0.9,
                )
            )

        # --- Dangerous CSP values --------------------------------------------------------
        csp_value = headers_lower.get("content-security-policy", "")
        if csp_value:
            dangerous_directives: list[str] = []
            if "'unsafe-inline'" in csp_value:
                dangerous_directives.append("unsafe-inline")
            if "'unsafe-eval'" in csp_value:
                dangerous_directives.append("unsafe-eval")
            if "data:" in csp_value:
                dangerous_directives.append("data: URI allowed")
            if dangerous_directives:
                result.findings.append(
                    ModuleFinding(
                        title="Weak Content-Security-Policy",
                        description=f"CSP contains dangerous directives: {', '.join(dangerous_directives)}. "
                        "These weaken XSS protections.",
                        severity=FindingSeverity.MEDIUM,
                        category="HTTP Security",
                        evidence=f"Content-Security-Policy: {csp_value[:500]}",
                        impact="unsafe-inline allows inline script execution; unsafe-eval allows "
                        "eval() — both negate much of CSP's XSS protection.",
                        remediation="Remove unsafe-inline/unsafe-eval. Use nonces or hashes for inline scripts. "
                        "Avoid data: URIs in script-src.",
                        cwe_id="CWE-1021",
                        confidence=0.9,
                    )
                )

        # --- HSTS max-age too short ------------------------------------------------------
        hsts_value = headers_lower.get("strict-transport-security", "")
        if hsts_value:
            m = re.search(r"max-age=(\d+)", hsts_value)
            if m:
                max_age = int(m.group(1))
                if max_age < 15768000:  # < 6 months
                    result.findings.append(
                        ModuleFinding(
                            title="HSTS max-age Too Short",
                            description=f"HSTS max-age is {max_age} seconds "
                            f"({max_age // 86400} days). Recommended minimum is 6 months (15768000).",
                            severity=FindingSeverity.LOW,
                            category="HTTP Security",
                            evidence=f"Strict-Transport-Security: {hsts_value}",
                            impact="Short HSTS window leaves a larger attack surface for SSL-stripping.",
                            remediation="Increase max-age to at least 31536000 (1 year). "
                            "Add includeSubDomains and preload if applicable.",
                            confidence=0.9,
                        )
                    )

        # --- Server / X-Powered-By information disclosure --------------------------------
        for hdr in ("server", "x-powered-by", "x-aspnet-version"):
            val = headers_lower.get(hdr)
            if val:
                result.findings.append(
                    ModuleFinding(
                        title=f"Information Disclosure: {hdr}",
                        description=f"The '{hdr}' header reveals server technology: {val}",
                        severity=FindingSeverity.INFO,
                        category="HTTP Security",
                        evidence=f"{hdr}: {val}",
                        impact="Helps attacker fingerprint the stack and find version-specific exploits.",
                        remediation=f"Remove or obscure the '{hdr}' header in production.",
                        confidence=0.85,
                    )
                )

        # --- Score summary ---------------------------------------------------------------
        score = round((present_count / total_checked) * 100) if total_checked else 0
        result.raw_output["score"] = score
        result.raw_output["present_count"] = present_count
        result.raw_output["total_checked"] = total_checked

        result.findings.append(
            ModuleFinding(
                title=f"Security Headers Score: {score}% ({present_count}/{total_checked})",
                description=f"{present_count} of {total_checked} recommended security headers are present.",
                severity=FindingSeverity.INFO,
                category="HTTP Security",
                evidence=f"Present: {present_count}/{total_checked}\nScore: {score}%",
                impact="A low score indicates multiple missing defense-in-depth headers.",
                remediation="Implement all recommended security headers.",
                confidence=1.0,
            )
        )

        return result


# ---------------------------------------------------------------------------
# 3. CORS Analysis
# ---------------------------------------------------------------------------


class CorsAnalysisModule(BaseModule):
    """Send requests with various Origin headers to detect CORS misconfigurations."""

    @property
    def name(self) -> str:
        return "cors_analysis"

    @property
    def display_name(self) -> str:
        return "CORS Analysis"

    @property
    def description(self) -> str:
        return "Test for CORS misconfigurations including origin reflection, null origin, and wildcard credentials"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "HTTP Security"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        url = target if "://" in target else f"https://{target}"

        parsed = urlparse(url)
        target_domain = parsed.hostname or ""

        # Build test origins
        test_origins: list[tuple[str, str]] = [
            ("https://evil.com", "arbitrary_origin"),
            ("null", "null_origin"),
            (f"https://subdomain.{target_domain}", "subdomain"),
            (f"https://{target_domain}.evil.com", "domain_suffix"),
        ]

        cors_results: list[dict[str, Any]] = []

        for origin, label in test_origins:
            if progress_callback:
                await progress_callback(f"Testing CORS with Origin: {origin}")

            headers = {"Origin": origin}
            resp = await self._http_get(url, headers=headers)
            if resp.get("error"):
                cors_results.append({"origin": origin, "label": label, "error": resp["error"]})
                continue

            resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "").lower()
            acam = resp_headers.get("access-control-allow-methods", "")

            cors_results.append({
                "origin": origin,
                "label": label,
                "status": resp["status"],
                "acao": acao,
                "acac": acac,
                "acam": acam,
            })

        result.raw_output["cors_tests"] = cors_results

        # --- Analyse results -------------------------------------------------------------

        evil_result = next((r for r in cors_results if r["label"] == "arbitrary_origin"), None)
        null_result = next((r for r in cors_results if r["label"] == "null_origin"), None)
        subdomain_result = next((r for r in cors_results if r["label"] == "subdomain"), None)
        suffix_result = next((r for r in cors_results if r["label"] == "domain_suffix"), None)

        has_finding = False

        # 1. Origin reflection — any arbitrary origin reflected back
        if evil_result and not evil_result.get("error"):
            acao = evil_result.get("acao", "")
            acac = evil_result.get("acac", "")
            if acao == "https://evil.com":
                sev = FindingSeverity.HIGH
                title = "CORS: Arbitrary Origin Reflected"
                desc = (
                    "The server reflects any Origin back in Access-Control-Allow-Origin. "
                    "Any website can make authenticated cross-origin requests."
                )
                if acac == "true":
                    desc += " Credentials are also allowed, enabling full account takeover from any origin."
                result.findings.append(
                    ModuleFinding(
                        title=title,
                        description=desc,
                        severity=sev,
                        category="HTTP Security",
                        evidence=(
                            f"Request Origin: https://evil.com\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: {acac}\n"
                            f"Response Access-Control-Allow-Methods: {evil_result.get('acam', '')}"
                        ),
                        impact="Attacker-controlled site can read authenticated responses, steal tokens, "
                        "and perform actions as the victim.",
                        remediation="Whitelist specific trusted origins. Never reflect the Origin header blindly.",
                        cwe_id="CWE-942",
                        cvss_score=8.1 if acac == "true" else 7.1,
                        owasp_category="A05:2021 Security Misconfiguration",
                        confidence=0.95,
                    )
                )
                has_finding = True

        # 2. Null origin allowed with credentials
        if null_result and not null_result.get("error"):
            acao = null_result.get("acao", "")
            acac = null_result.get("acac", "")
            if acao == "null" and acac == "true":
                result.findings.append(
                    ModuleFinding(
                        title="CORS: Null Origin Allowed with Credentials",
                        description="The server allows Origin: null with credentials. "
                        "Sandboxed iframes and redirects send Origin: null, allowing bypass.",
                        severity=FindingSeverity.HIGH,
                        category="HTTP Security",
                        evidence=(
                            f"Request Origin: null\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: {acac}"
                        ),
                        impact="Attacker can craft a sandboxed iframe that sends null origin and reads "
                        "authenticated responses.",
                        remediation="Do not whitelist 'null' as an allowed origin.",
                        cwe_id="CWE-942",
                        cvss_score=8.1,
                        confidence=0.95,
                    )
                )
                has_finding = True

        # 3. Wildcard (*) with credentials
        if evil_result and not evil_result.get("error"):
            acao = evil_result.get("acao", "")
            acac = evil_result.get("acac", "")
            if acao == "*" and acac == "true":
                result.findings.append(
                    ModuleFinding(
                        title="CORS: Wildcard with Credentials",
                        description="Access-Control-Allow-Origin is * while Allow-Credentials is true. "
                        "Browsers block this combination, but misconfigured proxies may not.",
                        severity=FindingSeverity.HIGH,
                        category="HTTP Security",
                        evidence=(
                            f"Access-Control-Allow-Origin: *\n"
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        impact="Proxy or non-browser clients may honour this, allowing cross-origin data theft.",
                        remediation="Use a specific origin whitelist instead of wildcard when credentials are needed.",
                        cwe_id="CWE-942",
                        cvss_score=7.5,
                        confidence=0.85,
                    )
                )
                has_finding = True

        # Also check null_result for wildcard + credentials
        if null_result and not null_result.get("error"):
            acao = null_result.get("acao", "")
            acac = null_result.get("acac", "")
            if acao == "*" and acac == "true":
                # Only add if not already added from evil_result
                existing_titles = {f.title for f in result.findings}
                if "CORS: Wildcard with Credentials" not in existing_titles:
                    result.findings.append(
                        ModuleFinding(
                            title="CORS: Wildcard with Credentials",
                            description="Access-Control-Allow-Origin is * while Allow-Credentials is true.",
                            severity=FindingSeverity.HIGH,
                            category="HTTP Security",
                            evidence=(
                                f"Access-Control-Allow-Origin: *\n"
                                f"Access-Control-Allow-Credentials: true"
                            ),
                            impact="Proxy or non-browser clients may honour this, allowing cross-origin data theft.",
                            remediation="Use specific origin whitelist instead of wildcard when credentials are needed.",
                            cwe_id="CWE-942",
                            cvss_score=7.5,
                            confidence=0.85,
                        )
                    )
                    has_finding = True

        # 4. Subdomain allowed (weaker issue)
        if subdomain_result and not subdomain_result.get("error"):
            acao = subdomain_result.get("acao", "")
            if acao == f"https://subdomain.{target_domain}":
                result.findings.append(
                    ModuleFinding(
                        title="CORS: Subdomain Origin Accepted",
                        description=f"The server accepts origins from subdomains of {target_domain}. "
                        "If any subdomain is compromised (XSS), it can read cross-origin data.",
                        severity=FindingSeverity.MEDIUM,
                        category="HTTP Security",
                        evidence=(
                            f"Request Origin: https://subdomain.{target_domain}\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: "
                            f"{subdomain_result.get('acac', '')}"
                        ),
                        impact="XSS on any subdomain escalates to cross-origin data access on the main domain.",
                        remediation="Whitelist only specific, trusted subdomains. Ensure subdomains are free of XSS.",
                        cwe_id="CWE-942",
                        cvss_score=5.3,
                        confidence=0.8,
                    )
                )
                has_finding = True

        # 5. Domain suffix bypass (target_domain.evil.com accepted)
        if suffix_result and not suffix_result.get("error"):
            acao = suffix_result.get("acao", "")
            if acao == f"https://{target_domain}.evil.com":
                result.findings.append(
                    ModuleFinding(
                        title="CORS: Domain Suffix Bypass",
                        description=f"The server accepted {target_domain}.evil.com as a valid origin. "
                        "The origin check likely uses a suffix match instead of exact match.",
                        severity=FindingSeverity.HIGH,
                        category="HTTP Security",
                        evidence=(
                            f"Request Origin: https://{target_domain}.evil.com\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: "
                            f"{suffix_result.get('acac', '')}"
                        ),
                        impact="Attacker registers a lookalike domain to bypass CORS and steal data.",
                        remediation="Use exact origin matching, not suffix/contains matching.",
                        cwe_id="CWE-942",
                        cvss_score=8.1,
                        confidence=0.95,
                    )
                )
                has_finding = True

        # 6. Proper CORS — if no issues found, note the policy
        if not has_finding:
            summary_lines: list[str] = []
            for cr in cors_results:
                if cr.get("error"):
                    summary_lines.append(f"Origin: {cr['origin']} — error: {cr['error']}")
                else:
                    summary_lines.append(
                        f"Origin: {cr['origin']} — ACAO: {cr.get('acao', 'absent')}, "
                        f"ACAC: {cr.get('acac', 'absent')}"
                    )
            result.findings.append(
                ModuleFinding(
                    title="CORS Policy Appears Properly Configured",
                    description="No CORS misconfigurations detected. The server does not reflect "
                    "arbitrary origins or allow dangerous cross-origin access.",
                    severity=FindingSeverity.INFO,
                    category="HTTP Security",
                    evidence="\n".join(summary_lines),
                    impact="N/A — CORS policy is restrictive.",
                    remediation="N/A — continue to maintain strict origin whitelisting.",
                    confidence=0.85,
                )
            )

        return result
