"""Base module interface for all OSINT/analysis modules."""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from backend.config import settings

logger = logging.getLogger(__name__)


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    URL = "url"
    EMAIL = "email"
    ENDPOINT = "endpoint"
    SECRET = "secret"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    SOCIAL_PROFILE = "social_profile"
    CLOUD_RESOURCE = "cloud_resource"
    COMPONENT = "component"
    FILE = "file"
    PERSON = "person"
    SERVICE = "service"
    PERMISSION = "permission"
    SDK = "sdk"


@dataclass
class ModuleFinding:
    title: str
    description: str
    severity: FindingSeverity
    category: str
    evidence: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float | None = None
    owasp_category: str = ""
    confidence: float = 0.8
    validation_hint: str = ""


@dataclass
class ModuleAsset:
    asset_type: AssetType
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    findings: list[ModuleFinding] = field(default_factory=list)
    assets: list[ModuleAsset] = field(default_factory=list)
    raw_output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BaseModule(ABC):
    """Every OSINT/analysis module extends this."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @property
    @abstractmethod
    def target_types(self) -> list[str]:
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        ...

    @property
    def requires_api_key(self) -> str | None:
        return None

    @property
    def timeout(self) -> int:
        return 120

    def api_key_available(self) -> bool:
        key_name = self.requires_api_key
        if not key_name:
            return True
        return bool(getattr(settings, key_name, ""))

    @abstractmethod
    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        ...

    async def validate_finding(self, finding: ModuleFinding, target: str) -> bool:
        """Override to add module-specific validation. Return False = false positive."""
        return True

    async def _run_command(self, cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
        except asyncio.TimeoutError:
            proc.kill()
            return "", f"Command timed out after {timeout}s", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1

    async def _http_get(self, url: str, headers: dict | None = None, timeout: int = 0) -> dict[str, Any]:
        import httpx

        t = timeout or settings.http_timeout
        try:
            async with httpx.AsyncClient(timeout=t, follow_redirects=True, verify=False) as client:
                resp = await client.get(url, headers=headers or {})
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:500_000],
                    "url": str(resp.url),
                }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}

    async def _http_post(self, url: str, data: Any = None, json_data: Any = None,
                         headers: dict | None = None, timeout: int = 0) -> dict[str, Any]:
        import httpx

        t = timeout or settings.http_timeout
        try:
            async with httpx.AsyncClient(timeout=t, follow_redirects=True, verify=False) as client:
                resp = await client.post(url, data=data, json=json_data, headers=headers or {})
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:500_000],
                    "url": str(resp.url),
                }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}

    async def _resolve_dns(self, domain: str, record_type: str = "A") -> list[str]:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception:
            return []

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "target_types": self.target_types,
            "category": self.category,
            "requires_api_key": self.requires_api_key,
            "api_key_configured": self.api_key_available(),
        }
