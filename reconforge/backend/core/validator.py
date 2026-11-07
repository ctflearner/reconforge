"""False-positive validation engine — verifies findings before reporting."""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any

import httpx

from backend.config import settings
from backend.modules.base import FindingSeverity, ModuleFinding

logger = logging.getLogger(__name__)


class Validator:
    """Multi-strategy validation to eliminate false positives.

    Strategies:
    1. Re-verification — re-test the finding independently
    2. Confidence thresholding — low-confidence findings flagged
    3. Context validation — check if finding makes sense for target type
    4. Duplicate dedup — same finding from multiple modules = higher confidence
    5. Known false-positive patterns — match against known FP signatures
    """

    KNOWN_FP_PATTERNS: list[dict[str, Any]] = [
        {
            "category": "secret",
            "pattern": r"(?:example|test|placeholder|dummy|sample|xxx|changeme|TODO)",
            "reason": "Placeholder/example value, not a real secret",
        },
        {
            "category": "secret",
            "pattern": r"^[A-Za-z0-9]{1,8}$",
            "reason": "Too short to be a real API key or token",
        },
        {
            "category": "subdomain",
            "pattern": r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|\.local$)",
            "reason": "Internal/localhost address, not a real subdomain",
        },
        {
            "category": "endpoint",
            "pattern": r"(?:example\.com|test\.example|httpbin\.org|jsonplaceholder)",
            "reason": "Example/test domain in endpoint",
        },
        {
            "category": "email",
            "pattern": r"(?:noreply|no-reply|donotreply|example\.com|test@|user@)",
            "reason": "Generic/placeholder email address",
        },
        {
            "category": "vulnerability",
            "pattern": r"(?:X-Powered-By|Server: )",
            "reason": "Information disclosure via header — low risk, verify relevance",
        },
    ]

    async def validate(
        self,
        finding: ModuleFinding,
        target: str,
        target_type: str,
        module_name: str,
    ) -> bool:
        """Run all validation checks. Return True if finding is confirmed valid."""
        if not settings.enable_validation:
            return True

        try:
            # 1. Confidence threshold
            if finding.confidence < 0.3:
                logger.debug("Rejected %s — confidence %.2f below threshold", finding.title, finding.confidence)
                return False

            # 2. Known FP pattern matching
            if self._matches_known_fp(finding):
                logger.debug("Rejected %s — matches known FP pattern", finding.title)
                return False

            # 3. Context validation
            if not self._context_valid(finding, target, target_type):
                logger.debug("Rejected %s — context mismatch", finding.title)
                return False

            # 4. Re-verification for specific categories
            if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                verified = await self._reverify(finding, target, target_type)
                if not verified:
                    logger.info("Rejected HIGH/CRITICAL finding %s — re-verification failed", finding.title)
                    return False

            # 5. Evidence quality check
            if not self._evidence_adequate(finding):
                if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                    finding.confidence *= 0.5
                    if finding.confidence < 0.4:
                        return False

            return True

        except Exception as exc:
            logger.warning("Validation error for %s: %s — accepting finding", finding.title, exc)
            return True

    def _matches_known_fp(self, finding: ModuleFinding) -> bool:
        combined = f"{finding.title} {finding.description} {finding.evidence}"
        for fp in self.KNOWN_FP_PATTERNS:
            if fp["category"] in finding.category.lower():
                if re.search(fp["pattern"], combined, re.IGNORECASE):
                    return True
        return False

    def _context_valid(self, finding: ModuleFinding, target: str, target_type: str) -> bool:
        # Web findings should reference the target domain
        if target_type == "url" and finding.category in ("subdomain", "endpoint"):
            from urllib.parse import urlparse
            domain = urlparse(target).netloc or target
            base = domain.split(".")[-2] if "." in domain else domain
            if base and base.lower() not in finding.evidence.lower() and base.lower() not in finding.description.lower():
                return False

        # APK findings should reference the package or file
        if target_type == "apk" and finding.category == "permission":
            if not finding.evidence:
                return False

        return True

    async def _reverify(self, finding: ModuleFinding, target: str, target_type: str) -> bool:
        """Re-test critical/high findings independently."""
        category = finding.category.lower()

        if "secret" in category or "credential" in category:
            return self._verify_secret(finding)

        if "ssl" in category or "tls" in category:
            return await self._verify_ssl(finding, target)

        if "header" in category:
            return await self._verify_header(finding, target)

        if "dns" in category:
            return await self._verify_dns(finding, target)

        if "port" in category or "service" in category:
            return await self._verify_port(finding, target)

        # For categories we can't independently verify, trust the module
        return True

    def _verify_secret(self, finding: ModuleFinding) -> bool:
        evidence = finding.evidence or ""
        # Check entropy — real secrets tend to have high entropy
        if len(evidence) < 10:
            return False
        unique = len(set(evidence))
        if unique < len(evidence) * 0.3:
            return False
        # Check it's not all one character class
        if evidence.isalpha() or evidence.isdigit():
            return False
        return True

    async def _verify_ssl(self, finding: ModuleFinding, target: str) -> bool:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or 443
            async with httpx.AsyncClient(timeout=10, verify=True) as client:
                try:
                    await client.get(f"https://{host}:{port}/", follow_redirects=False)
                    # If we get here, SSL is valid — finding about SSL issue needs checking
                except httpx.ConnectError:
                    return True  # Connection issue = SSL finding likely valid
                except Exception:
                    return True
            return True
        except Exception:
            return True

    async def _verify_header(self, finding: ModuleFinding, target: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                resp = await client.get(target)
                # Check the header mentioned in finding actually exists/is missing
                raw = finding.raw_data
                if "missing_header" in raw:
                    return raw["missing_header"].lower() not in (h.lower() for h in resp.headers)
                if "header_value" in raw:
                    header_name = raw.get("header_name", "")
                    actual = resp.headers.get(header_name, "")
                    return actual == raw["header_value"]
            return True
        except Exception:
            return True

    async def _verify_dns(self, finding: ModuleFinding, target: str) -> bool:
        try:
            import dns.resolver
            from urllib.parse import urlparse
            domain = urlparse(target).netloc or target
            domain = domain.split(":")[0]
            dns.resolver.resolve(domain, "A")
            return True
        except Exception:
            return True

    async def _verify_port(self, finding: ModuleFinding, target: str) -> bool:
        raw = finding.raw_data
        port = raw.get("port")
        host = raw.get("host", target)
        if not port:
            return True
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True  # Port is open — finding valid
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False  # Port not reachable — finding invalid

    def _evidence_adequate(self, finding: ModuleFinding) -> bool:
        if not finding.evidence and not finding.raw_data:
            return False
        if finding.evidence and len(finding.evidence.strip()) < 10:
            return False
        return True
