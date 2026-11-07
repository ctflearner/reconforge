"""Port scanning and service enumeration modules for IP targets."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Callable

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

# Ports considered high-risk when found open
HIGH_RISK_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# Top 100 TCP ports for fallback socket scan
TOP_100_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143,
    161, 179, 199, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
    3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
    5432, 5631, 5666, 5800, 5900, 5901, 6000, 6001, 6379, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9090, 9100, 9999, 10000,
    11211, 27017, 27018, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


# ---------------------------------------------------------------------------
# 1. Port Scan
# ---------------------------------------------------------------------------
class PortScanModule(BaseModule):
    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def display_name(self) -> str:
        return "Port Scan"

    @property
    def description(self) -> str:
        return "TCP/UDP port scan via nmap (fallback: async socket connect scan) with service detection."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Port & Service"

    @property
    def timeout(self) -> int:
        return 300

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}
        open_ports: list[dict[str, Any]] = []

        # --- Try nmap ---
        nmap_available = await self._check_nmap()

        if nmap_available:
            if progress_callback:
                await progress_callback("Running nmap TCP SYN scan (top 1000 ports)")

            # TCP scan
            tcp_stdout, tcp_stderr, tcp_rc = await self._run_command(
                ["nmap", "-sS", "-sV", "--top-ports", "1000", "-T4", "--open", "-oX", "-", target],
                timeout=240,
            )
            raw["nmap_tcp_stdout"] = tcp_stdout[:100_000]
            raw["nmap_tcp_rc"] = tcp_rc

            if tcp_rc == 0 and tcp_stdout:
                tcp_ports = self._parse_nmap_xml(tcp_stdout)
                open_ports.extend(tcp_ports)

            # UDP scan (top 100)
            if progress_callback:
                await progress_callback("Running nmap UDP scan (top 100 ports)")

            udp_stdout, udp_stderr, udp_rc = await self._run_command(
                ["nmap", "-sU", "--top-ports", "100", "-T4", "--open", "-oX", "-", target],
                timeout=180,
            )
            raw["nmap_udp_stdout"] = udp_stdout[:50_000]
            raw["nmap_udp_rc"] = udp_rc

            if udp_rc == 0 and udp_stdout:
                udp_ports = self._parse_nmap_xml(udp_stdout)
                open_ports.extend(udp_ports)
        else:
            # Fallback: async socket connect scan
            if progress_callback:
                await progress_callback("nmap not available — running async socket connect scan")

            open_ports = await self._socket_scan(target, progress_callback)
            raw["scan_method"] = "socket_connect"

        raw["open_ports"] = open_ports

        # --- Build assets ---
        for port_info in open_ports:
            port_num = port_info["port"]
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.PORT,
                    value=str(port_num),
                    metadata={
                        "port": port_num,
                        "protocol": port_info.get("protocol", "tcp"),
                        "state": port_info.get("state", "open"),
                        "service": port_info.get("service", ""),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                    },
                )
            )

            if port_info.get("service") or port_info.get("product"):
                assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SERVICE,
                        value=f"{port_info.get('product') or port_info.get('service', 'unknown')}:{port_num}",
                        metadata=port_info,
                    )
                )

        # --- Findings ---
        if open_ports:
            port_list_str = ", ".join(
                f"{p['port']}/{p.get('protocol', 'tcp')} ({p.get('service', '?')})"
                for p in open_ports
            )
            findings.append(
                ModuleFinding(
                    title=f"{len(open_ports)} open port(s) on {target}",
                    description=f"Port scan discovered {len(open_ports)} open port(s).",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence=f"Open ports: {port_list_str}",
                    raw_data={"open_ports": open_ports},
                    confidence=0.95 if nmap_available else 0.75,
                )
            )

        # Flag high-risk ports
        for port_info in open_ports:
            port_num = port_info["port"]
            if port_num in HIGH_RISK_PORTS:
                svc_name = HIGH_RISK_PORTS[port_num]
                findings.append(
                    ModuleFinding(
                        title=f"High-risk port open: {port_num}/{port_info.get('protocol', 'tcp')} ({svc_name})",
                        description=f"{svc_name} service detected on port {port_num}. This service is commonly targeted in attacks.",
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=f"Port: {port_num}\nService: {svc_name}\nProduct: {port_info.get('product', 'N/A')}\nVersion: {port_info.get('version', 'N/A')}",
                        impact=f"Exposed {svc_name} service may allow unauthorized access, brute-force attacks, or exploitation of known vulnerabilities.",
                        remediation=f"Restrict access to port {port_num} using firewall rules. Ensure {svc_name} is patched and requires strong authentication.",
                        confidence=0.9,
                        validation_hint=f"Verify: nmap -sV -sC -p {port_num} {target}",
                    )
                )

        if not open_ports:
            findings.append(
                ModuleFinding(
                    title=f"No open ports found on {target}",
                    description="Port scan did not detect any open ports. Host may be filtered or down.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    confidence=0.6,
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _check_nmap(self) -> bool:
        _, _, rc = await self._run_command(["nmap", "--version"], timeout=10)
        return rc == 0

    def _parse_nmap_xml(self, xml_str: str) -> list[dict[str, Any]]:
        """Parse nmap -oX output into port info dicts."""
        ports: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_str)
            for host_el in root.findall(".//host"):
                for port_el in host_el.findall(".//port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    state = state_el.get("state", "") if state_el is not None else ""
                    if state != "open":
                        continue
                    port_num = int(port_el.get("portid", 0))
                    protocol = port_el.get("protocol", "tcp")
                    service_name = service_el.get("name", "") if service_el is not None else ""
                    product = service_el.get("product", "") if service_el is not None else ""
                    version = service_el.get("version", "") if service_el is not None else ""
                    extra_info = service_el.get("extrainfo", "") if service_el is not None else ""

                    ports.append({
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extra_info": extra_info,
                    })
        except ET.ParseError as exc:
            logger.warning("Failed to parse nmap XML: %s", exc)
        return ports

    async def _socket_scan(
        self, target: str, progress_callback: Callable | None = None
    ) -> list[dict[str, Any]]:
        """Fallback async connect scan on top 100 ports."""
        open_ports: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(100)

        async def check_port(port: int) -> dict[str, Any] | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port), timeout=3
                    )
                    writer.close()
                    await writer.wait_closed()
                    return {"port": port, "protocol": "tcp", "state": "open", "service": "", "product": "", "version": ""}
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    return None

        tasks = [check_port(p) for p in TOP_100_PORTS]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r is not None:
                open_ports.append(r)

        if progress_callback:
            await progress_callback(f"Socket scan complete — {len(open_ports)} open")

        return sorted(open_ports, key=lambda x: x["port"])


# ---------------------------------------------------------------------------
# 2. Banner Grabbing
# ---------------------------------------------------------------------------
class BannerGrabModule(BaseModule):
    @property
    def name(self) -> str:
        return "banner_grab"

    @property
    def display_name(self) -> str:
        return "Banner Grabbing"

    @property
    def description(self) -> str:
        return "Grab service banners from open ports to identify software versions and potential info leaks."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Port & Service"

    @property
    def timeout(self) -> int:
        return 180

    # Service probes keyed by port
    _PROBES: dict[int, bytes] = {
        80: b"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        8080: b"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        8443: b"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        443: b"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        21: b"",     # FTP: read banner only
        22: b"",     # SSH: read banner only
        25: b"",     # SMTP: read banner only
        587: b"",    # SMTP submission
        3306: b"",   # MySQL greeting
        6379: b"INFO\r\n",  # Redis
    }

    # Known outdated version patterns
    _OUTDATED_PATTERNS: list[tuple[str, str, str]] = [
        (r"Apache/2\.2\.\d+", "Apache 2.2.x (EOL)", "Upgrade to Apache 2.4.x or later."),
        (r"Apache/2\.4\.([0-9]|[12]\d|3[0-9]|4[0-9])\b", "Apache 2.4.x (potentially outdated)", "Update to latest Apache 2.4.x release."),
        (r"nginx/1\.([0-9]|1[0-7])\.", "nginx (potentially outdated)", "Update to latest stable nginx."),
        (r"OpenSSH_[67]\.", "OpenSSH 6.x/7.x (outdated)", "Upgrade to OpenSSH 8.x or 9.x."),
        (r"Microsoft-IIS/[67]\.", "IIS 6/7 (EOL or outdated)", "Upgrade to IIS 10.x or later."),
        (r"PHP/5\.", "PHP 5.x (EOL)", "Upgrade to PHP 8.x."),
        (r"PHP/7\.[0-3]\.", "PHP 7.0-7.3 (EOL)", "Upgrade to PHP 8.x."),
        (r"ProFTPD 1\.[0-2]\.", "ProFTPD (outdated)", "Upgrade to latest ProFTPD."),
        (r"vsftpd 2\.", "vsftpd 2.x (outdated)", "Upgrade to vsftpd 3.x."),
    ]

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        # Determine which ports to scan
        ports_to_check: list[int] = []

        # Prefer ports from scan_context
        ctx_ports = scan_context.get("open_ports") or []
        if ctx_ports:
            for p in ctx_ports:
                port_num = p.get("port") if isinstance(p, dict) else int(p)
                if port_num not in ports_to_check:
                    ports_to_check.append(port_num)
        else:
            # Default common ports
            ports_to_check = [21, 22, 25, 80, 110, 143, 443, 587, 993, 995,
                              3306, 3389, 5432, 6379, 8080, 8443, 27017]

        if progress_callback:
            await progress_callback(f"Grabbing banners from {len(ports_to_check)} port(s)")

        banners: dict[int, str] = {}
        sem = asyncio.Semaphore(20)

        async def grab(port: int) -> tuple[int, str]:
            async with sem:
                return port, await self._grab_single(target, port)

        tasks = [grab(p) for p in ports_to_check]
        results = await asyncio.gather(*tasks)

        for port, banner in results:
            if banner:
                banners[port] = banner

        raw["banners"] = banners

        # Build assets and findings
        for port, banner in banners.items():
            # Clean banner for display (first 500 chars)
            clean_banner = banner[:500].replace("\x00", "").strip()

            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"banner:{port}",
                    metadata={"port": port, "banner": clean_banner, "ip": target},
                )
            )

            # Check for outdated versions
            for pattern, label, fix in self._OUTDATED_PATTERNS:
                if re.search(pattern, banner):
                    findings.append(
                        ModuleFinding(
                            title=f"Outdated software on port {port}: {label}",
                            description=f"Banner on port {port} reveals {label}.",
                            severity=FindingSeverity.MEDIUM,
                            category=self.category,
                            evidence=f"Port: {port}\nBanner:\n{clean_banner}",
                            impact="Outdated software may contain known vulnerabilities that are publicly exploitable.",
                            remediation=fix,
                            confidence=0.8,
                            validation_hint=f"Verify version: nmap -sV -p {port} {target}",
                        )
                    )
                    break  # One finding per port

            # Info disclosure: look for internal IPs, paths, stack traces
            info_leaks: list[str] = []
            internal_ips = re.findall(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", banner)
            if internal_ips:
                info_leaks.append(f"Internal IPs: {', '.join(set(internal_ips))}")
            file_paths = re.findall(r"(?:/[a-zA-Z0-9._-]+){3,}", banner)
            if file_paths:
                info_leaks.append(f"File paths: {', '.join(set(file_paths[:5]))}")

            if info_leaks:
                findings.append(
                    ModuleFinding(
                        title=f"Information disclosure in banner on port {port}",
                        description="Service banner leaks potentially sensitive information.",
                        severity=FindingSeverity.LOW,
                        category=self.category,
                        evidence=f"Port: {port}\nLeaked info:\n" + "\n".join(info_leaks) + f"\n\nFull banner:\n{clean_banner}",
                        impact="Leaked internal information aids attacker reconnaissance.",
                        remediation="Configure the service to suppress version and internal details from banners.",
                        cwe_id="CWE-200",
                        confidence=0.7,
                    )
                )

        # Summary
        if banners:
            summary_lines = [f"  Port {p}: {b[:80]}..." if len(b) > 80 else f"  Port {p}: {b}" for p, b in sorted(banners.items())]
            findings.append(
                ModuleFinding(
                    title=f"Banners collected from {len(banners)} port(s) on {target}",
                    description=f"Successfully grabbed {len(banners)} service banner(s).",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="\n".join(summary_lines),
                    confidence=0.9,
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _grab_single(self, target: str, port: int) -> str:
        """Connect to a single port, send probe, return banner text."""
        probe_template = self._PROBES.get(port)
        if probe_template is not None:
            probe = probe_template.replace(b"{target}", target.encode()) if b"{target}" in probe_template else probe_template
        else:
            probe = b"\r\n"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=5
            )
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return ""

        try:
            # For read-only services, read first
            if not probe:
                data = await asyncio.wait_for(reader.read(4096), timeout=5)
            else:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=5)

            return data.decode(errors="replace").strip()
        except (asyncio.TimeoutError, OSError):
            return ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 3. Service Enumeration
# ---------------------------------------------------------------------------
class ServiceEnumModule(BaseModule):
    @property
    def name(self) -> str:
        return "service_enum"

    @property
    def display_name(self) -> str:
        return "Service Enumeration"

    @property
    def description(self) -> str:
        return "Deep enumeration of detected services — anonymous access, auth checks, version extraction."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Port & Service"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        # Collect open ports from context
        open_ports: list[dict[str, Any]] = scan_context.get("open_ports") or []
        port_numbers: set[int] = set()
        for p in open_ports:
            port_numbers.add(p.get("port") if isinstance(p, dict) else int(p))

        # If no context, try common service ports
        if not port_numbers:
            port_numbers = {21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017}

        # --- HTTP enumeration ---
        http_ports = port_numbers & {80, 443, 8080, 8443}
        for port in sorted(http_ports):
            if progress_callback:
                await progress_callback(f"Enumerating HTTP on port {port}")
            result = await self._enum_http(target, port)
            raw[f"http_{port}"] = result
            if result.get("title") or result.get("server"):
                assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SERVICE,
                        value=f"http:{port}",
                        metadata={
                            "port": port,
                            "title": result.get("title", ""),
                            "server": result.get("server", ""),
                            "technologies": result.get("technologies", []),
                            "status_code": result.get("status_code"),
                        },
                    )
                )
                for tech in result.get("technologies") or []:
                    assets.append(
                        ModuleAsset(
                            asset_type=AssetType.TECHNOLOGY,
                            value=tech,
                            metadata={"port": port, "source": "http_header"},
                        )
                    )

        # --- FTP anonymous login ---
        if 21 in port_numbers:
            if progress_callback:
                await progress_callback("Checking FTP anonymous login")
            ftp_result = await self._enum_ftp(target)
            raw["ftp_21"] = ftp_result
            if ftp_result.get("anonymous_login"):
                findings.append(
                    ModuleFinding(
                        title=f"Anonymous FTP login allowed on {target}:21",
                        description="FTP server permits anonymous authentication, potentially exposing files.",
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=f"Connected to {target}:21\nSent: USER anonymous / PASS anonymous@\nResponse: {ftp_result.get('response', '')}",
                        impact="Anonymous FTP access may expose sensitive files, configuration data, or allow upload of malicious files.",
                        remediation="Disable anonymous FTP access or restrict it to a dedicated read-only directory with non-sensitive content.",
                        cwe_id="CWE-284",
                        confidence=0.95,
                        validation_hint=f"Verify: ftp {target} (login as anonymous)",
                    )
                )
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="ftp:21",
                    metadata={
                        "port": 21,
                        "anonymous": ftp_result.get("anonymous_login", False),
                        "banner": ftp_result.get("banner", ""),
                    },
                )
            )

        # --- SSH enumeration ---
        if 22 in port_numbers:
            if progress_callback:
                await progress_callback("Enumerating SSH")
            ssh_result = await self._enum_ssh(target)
            raw["ssh_22"] = ssh_result
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="ssh:22",
                    metadata={
                        "port": 22,
                        "banner": ssh_result.get("banner", ""),
                        "version": ssh_result.get("version", ""),
                        "audit_output": ssh_result.get("audit", "")[:1000],
                    },
                )
            )

        # --- Redis no-auth ---
        if 6379 in port_numbers:
            if progress_callback:
                await progress_callback("Checking Redis authentication")
            redis_result = await self._enum_redis(target)
            raw["redis_6379"] = redis_result
            if redis_result.get("no_auth"):
                findings.append(
                    ModuleFinding(
                        title=f"Redis requires no authentication on {target}:6379",
                        description="Redis is accessible without authentication, allowing full read/write access to data and potential RCE.",
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=f"Connected to {target}:6379\nSent: PING\nResponse: {redis_result.get('ping_response', '')}\n\nSent: INFO server\nResponse (truncated): {redis_result.get('info', '')[:500]}",
                        impact="Unauthenticated Redis allows data exfiltration, key manipulation, and potential RCE via CONFIG SET or module loading.",
                        remediation="Enable Redis authentication with a strong password (requirepass). Bind to localhost or use firewall rules.",
                        cwe_id="CWE-306",
                        confidence=0.95,
                        validation_hint=f"Verify: redis-cli -h {target} PING",
                    )
                )
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="redis:6379",
                    metadata={
                        "port": 6379,
                        "no_auth": redis_result.get("no_auth", False),
                        "version": redis_result.get("version", ""),
                    },
                )
            )

        # --- MySQL enumeration ---
        if 3306 in port_numbers:
            if progress_callback:
                await progress_callback("Enumerating MySQL")
            mysql_result = await self._enum_mysql(target)
            raw["mysql_3306"] = mysql_result
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="mysql:3306",
                    metadata={
                        "port": 3306,
                        "version": mysql_result.get("version", ""),
                    },
                )
            )

        # --- PostgreSQL enumeration ---
        if 5432 in port_numbers:
            if progress_callback:
                await progress_callback("Enumerating PostgreSQL")
            pg_result = await self._enum_postgres(target)
            raw["postgres_5432"] = pg_result
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="postgresql:5432",
                    metadata={
                        "port": 5432,
                        "accepting_connections": pg_result.get("accepting", False),
                        "version": pg_result.get("version", ""),
                    },
                )
            )

        # --- MongoDB no-auth ---
        if 27017 in port_numbers:
            if progress_callback:
                await progress_callback("Checking MongoDB authentication")
            mongo_result = await self._enum_mongodb(target)
            raw["mongodb_27017"] = mongo_result
            if mongo_result.get("no_auth"):
                findings.append(
                    ModuleFinding(
                        title=f"MongoDB requires no authentication on {target}:27017",
                        description="MongoDB is accessible without authentication, exposing all databases.",
                        severity=FindingSeverity.HIGH,
                        category=self.category,
                        evidence=f"Connected to {target}:27017\nResponse: {mongo_result.get('response', '')[:500]}",
                        impact="Unauthenticated MongoDB access exposes all databases and collections, allows data exfiltration, modification, or deletion.",
                        remediation="Enable MongoDB authentication. Bind to localhost or use network controls.",
                        cwe_id="CWE-306",
                        confidence=0.9,
                        validation_hint=f"Verify: mongosh --host {target} --eval 'db.adminCommand({{listDatabases:1}})'",
                    )
                )
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value="mongodb:27017",
                    metadata={
                        "port": 27017,
                        "no_auth": mongo_result.get("no_auth", False),
                    },
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    # -- Per-service helpers --

    async def _enum_http(self, target: str, port: int) -> dict[str, Any]:
        """Fetch HTTP root and extract metadata."""
        scheme = "https" if port in (443, 8443) else "http"
        resp = await self._http_get(f"{scheme}://{target}:{port}/", timeout=10)
        result: dict[str, Any] = {"status_code": resp.get("status"), "error": resp.get("error")}

        headers = resp.get("headers") or {}
        body = resp.get("body", "")

        result["server"] = headers.get("server", "")
        result["x_powered_by"] = headers.get("x-powered-by", "")

        # Extract title
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        result["title"] = title_match.group(1).strip()[:200] if title_match else ""

        # Detect technologies from headers and body
        techs: list[str] = []
        if result["server"]:
            techs.append(result["server"])
        if result["x_powered_by"]:
            techs.append(result["x_powered_by"])
        # Common meta generators
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', body, re.IGNORECASE)
        if gen_match:
            techs.append(gen_match.group(1).strip())
        result["technologies"] = techs

        return result

    async def _enum_ftp(self, target: str) -> dict[str, Any]:
        """Try anonymous FTP login via raw socket."""
        result: dict[str, Any] = {"anonymous_login": False, "banner": "", "response": ""}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 21), timeout=5
            )
            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=5)
            result["banner"] = banner.decode(errors="replace").strip()

            # Send USER anonymous
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_resp = await asyncio.wait_for(reader.readline(), timeout=5)
            user_resp_str = user_resp.decode(errors="replace").strip()

            # Send PASS
            writer.write(b"PASS anonymous@\r\n")
            await writer.drain()
            pass_resp = await asyncio.wait_for(reader.readline(), timeout=5)
            pass_resp_str = pass_resp.decode(errors="replace").strip()
            result["response"] = f"USER: {user_resp_str} | PASS: {pass_resp_str}"

            if pass_resp_str.startswith("230"):
                result["anonymous_login"] = True

            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as exc:
            result["error"] = str(exc)
        return result

    async def _enum_ssh(self, target: str) -> dict[str, Any]:
        """Grab SSH banner and try ssh-audit if available."""
        result: dict[str, Any] = {"banner": "", "version": "", "audit": ""}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 22), timeout=5
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            banner_str = banner.decode(errors="replace").strip()
            result["banner"] = banner_str

            # Extract version
            ver_match = re.search(r"SSH-\d+\.\d+-(.+)", banner_str)
            if ver_match:
                result["version"] = ver_match.group(1)

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError):
            pass

        # Try ssh-audit
        stdout, stderr, rc = await self._run_command(["ssh-audit", "-n", target], timeout=30)
        if rc == 0:
            result["audit"] = stdout
        return result

    async def _enum_redis(self, target: str) -> dict[str, Any]:
        """Check Redis for no-auth access."""
        result: dict[str, Any] = {"no_auth": False, "ping_response": "", "info": "", "version": ""}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 6379), timeout=5
            )

            # PING
            writer.write(b"PING\r\n")
            await writer.drain()
            ping_resp = await asyncio.wait_for(reader.read(1024), timeout=5)
            ping_str = ping_resp.decode(errors="replace").strip()
            result["ping_response"] = ping_str

            if "+PONG" in ping_str:
                result["no_auth"] = True

                # Get INFO
                writer.write(b"INFO server\r\n")
                await writer.drain()
                info_resp = await asyncio.wait_for(reader.read(4096), timeout=5)
                info_str = info_resp.decode(errors="replace")
                result["info"] = info_str

                ver_match = re.search(r"redis_version:(\S+)", info_str)
                if ver_match:
                    result["version"] = ver_match.group(1)

            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as exc:
            result["error"] = str(exc)
        return result

    async def _enum_mysql(self, target: str) -> dict[str, Any]:
        """Read MySQL greeting packet to extract version."""
        result: dict[str, Any] = {"version": ""}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 3306), timeout=5
            )
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            await writer.wait_closed()

            # MySQL greeting: skip first 4 bytes (packet header), then protocol version byte
            if len(data) > 5:
                # Version string is null-terminated starting at offset 5
                version_end = data.index(b"\x00", 5) if b"\x00" in data[5:] else len(data)
                result["version"] = data[5:version_end + 5].decode(errors="replace").rstrip("\x00")
        except (asyncio.TimeoutError, OSError, ValueError) as exc:
            result["error"] = str(exc)
        return result

    async def _enum_postgres(self, target: str) -> dict[str, Any]:
        """Attempt a PostgreSQL startup to extract version."""
        result: dict[str, Any] = {"accepting": False, "version": ""}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 5432), timeout=5
            )
            # Send SSLRequest (special startup message)
            # Length=8, SSL request code = 80877103
            ssl_request = struct.pack("!II", 8, 80877103)
            writer.write(ssl_request)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(1), timeout=5)
            if resp in (b"S", b"N"):
                result["accepting"] = True

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError) as exc:
            result["error"] = str(exc)

        # Try psql --version extraction via command if available
        if result["accepting"]:
            stdout, stderr, rc = await self._run_command(
                ["psql", f"--host={target}", "--port=5432", "--username=postgres",
                 "--no-password", "--command=SELECT version();"],
                timeout=5,
            )
            if rc == 0 and stdout:
                result["version"] = stdout.strip()[:200]

        return result

    async def _enum_mongodb(self, target: str) -> dict[str, Any]:
        """Check if MongoDB is accessible without auth."""
        result: dict[str, Any] = {"no_auth": False, "response": ""}

        # Try mongosh/mongo CLI first
        for cmd_name in ("mongosh", "mongo"):
            stdout, stderr, rc = await self._run_command(
                [cmd_name, "--host", target, "--port", "27017", "--eval",
                 "db.adminCommand({listDatabases:1})", "--quiet"],
                timeout=10,
            )
            if rc == 0 and stdout:
                result["no_auth"] = True
                result["response"] = stdout[:1000]
                return result
            if rc != -1:  # Command found but failed (auth required, etc.)
                result["response"] = (stderr or stdout)[:500]
                return result

        # Fallback: raw socket with MongoDB wire protocol (OP_QUERY isMaster)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 27017), timeout=5
            )

            # Build a minimal OP_QUERY for isMaster
            # This is the legacy wire protocol — sufficient to detect open access
            ns = b"admin.$cmd\x00"
            query_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster: 1}
            # OP_QUERY header: flags(4) + ns + skip(4) + return(4) + query_doc
            payload = struct.pack("<i", 0) + ns + struct.pack("<i", 0) + struct.pack("<i", -1) + query_doc
            # MsgHeader: length(4) + requestID(4) + responseTo(4) + opCode(4=OP_QUERY=2004)
            request_id = 1
            header = struct.pack("<iiii", 16 + len(payload), request_id, 0, 2004)
            writer.write(header + payload)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            result["response"] = data[:500].decode(errors="replace")

            # If we got a response at all without error, auth is likely not required
            if len(data) > 36 and b"ismaster" in data.lower():
                result["no_auth"] = True

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError) as exc:
            result["error"] = str(exc)

        return result


# ---------------------------------------------------------------------------
# 4. SSL Certificate Scan
# ---------------------------------------------------------------------------
class SslCertScanModule(BaseModule):
    @property
    def name(self) -> str:
        return "ssl_cert_scan"

    @property
    def display_name(self) -> str:
        return "SSL Certificate Scan"

    @property
    def description(self) -> str:
        return "Extract and analyze SSL/TLS certificates — expiry, CN, SANs, key strength, self-signed detection."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Port & Service"

    # Standard TLS ports to check
    _TLS_PORTS: list[int] = [443, 8443, 993, 995, 465, 636, 989, 990]

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        # Merge default TLS ports with any open ports from context
        ports_to_check: set[int] = set(self._TLS_PORTS)
        for p in scan_context.get("open_ports") or []:
            port_num = p.get("port") if isinstance(p, dict) else int(p)
            ports_to_check.add(port_num)

        if progress_callback:
            await progress_callback(f"Scanning {len(ports_to_check)} port(s) for TLS certificates")

        certs_found: dict[int, dict[str, Any]] = {}

        for port in sorted(ports_to_check):
            cert_info = await self._grab_cert(target, port)
            if cert_info:
                certs_found[port] = cert_info

        raw["certificates"] = certs_found

        for port, cert in certs_found.items():
            if progress_callback:
                await progress_callback(f"Analyzing certificate on port {port}")

            # --- Certificate asset ---
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.CERTIFICATE,
                    value=f"{target}:{port}",
                    metadata=cert,
                )
            )

            # --- SAN hostnames as assets ---
            for san in cert.get("sans") or []:
                san_clean = san.strip()
                if san_clean.startswith("*."):
                    asset_type = AssetType.SUBDOMAIN
                elif san_clean:
                    asset_type = AssetType.DOMAIN
                else:
                    continue
                assets.append(
                    ModuleAsset(
                        asset_type=asset_type,
                        value=san_clean,
                        metadata={"source": "ssl_certificate", "port": port},
                    )
                )

            # --- Check for issues ---
            now = datetime.now(timezone.utc)

            # Expiry
            not_after_str = cert.get("not_after", "")
            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    days_left = (not_after - now).days

                    if days_left < 0:
                        findings.append(
                            ModuleFinding(
                                title=f"Expired SSL certificate on {target}:{port}",
                                description=f"Certificate expired {abs(days_left)} day(s) ago on {not_after_str}.",
                                severity=FindingSeverity.HIGH,
                                category=self.category,
                                evidence=self._cert_evidence(port, cert),
                                impact="Expired certificates cause browser warnings, break trust chains, and may indicate neglected infrastructure.",
                                remediation="Renew the certificate immediately.",
                                cwe_id="CWE-295",
                                confidence=0.99,
                            )
                        )
                    elif days_left <= 30:
                        findings.append(
                            ModuleFinding(
                                title=f"SSL certificate expiring soon on {target}:{port}",
                                description=f"Certificate expires in {days_left} day(s) on {not_after_str}.",
                                severity=FindingSeverity.MEDIUM,
                                category=self.category,
                                evidence=self._cert_evidence(port, cert),
                                impact="Imminent certificate expiry will cause service disruption.",
                                remediation="Renew the certificate before expiry.",
                                cwe_id="CWE-295",
                                confidence=0.95,
                            )
                        )
                except ValueError:
                    pass

            # Self-signed
            if cert.get("self_signed"):
                findings.append(
                    ModuleFinding(
                        title=f"Self-signed certificate on {target}:{port}",
                        description="Certificate is self-signed and will not be trusted by default.",
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=self._cert_evidence(port, cert),
                        impact="Self-signed certificates are vulnerable to MITM attacks as clients cannot verify authenticity.",
                        remediation="Replace with a certificate from a trusted CA.",
                        cwe_id="CWE-295",
                        confidence=0.95,
                    )
                )

            # Weak key
            key_bits = cert.get("key_bits", 0)
            if key_bits and key_bits < 2048:
                findings.append(
                    ModuleFinding(
                        title=f"Weak key ({key_bits}-bit) on {target}:{port}",
                        description=f"Certificate uses a {key_bits}-bit key, below the 2048-bit minimum recommendation.",
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        evidence=self._cert_evidence(port, cert),
                        impact="Weak cryptographic keys can be factored, compromising TLS confidentiality.",
                        remediation="Regenerate the certificate with at least a 2048-bit RSA key or 256-bit ECDSA key.",
                        cwe_id="CWE-326",
                        confidence=0.95,
                    )
                )

            # Wildcard note (informational)
            wildcard_sans = [s for s in (cert.get("sans") or []) if s.startswith("*.")]
            if wildcard_sans:
                findings.append(
                    ModuleFinding(
                        title=f"Wildcard certificate on {target}:{port}",
                        description=f"Certificate covers wildcard domain(s): {', '.join(wildcard_sans)}.",
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        evidence=self._cert_evidence(port, cert),
                        confidence=0.9,
                    )
                )

        if not certs_found:
            findings.append(
                ModuleFinding(
                    title=f"No TLS certificates found on {target}",
                    description="No TLS-enabled services detected on standard ports.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    confidence=0.7,
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _grab_cert(self, target: str, port: int) -> dict[str, Any] | None:
        """Connect with TLS and extract certificate details."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx), timeout=8
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if not ssl_obj:
                writer.close()
                return None

            der_cert = ssl_obj.getpeercert(binary_form=True)
            peer_cert = ssl_obj.getpeercert()

            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

            if not peer_cert and not der_cert:
                return None

            info: dict[str, Any] = {}

            if peer_cert:
                # Subject
                subject_parts: list[str] = []
                for rdn in peer_cert.get("subject") or ():
                    for attr_type, attr_val in rdn:
                        subject_parts.append(f"{attr_type}={attr_val}")
                info["subject"] = ", ".join(subject_parts)

                # CN
                for rdn in peer_cert.get("subject") or ():
                    for attr_type, attr_val in rdn:
                        if attr_type == "commonName":
                            info["common_name"] = attr_val

                # Issuer
                issuer_parts: list[str] = []
                for rdn in peer_cert.get("issuer") or ():
                    for attr_type, attr_val in rdn:
                        issuer_parts.append(f"{attr_type}={attr_val}")
                info["issuer"] = ", ".join(issuer_parts)

                # SANs
                sans: list[str] = []
                for san_type, san_val in peer_cert.get("subjectAltName") or ():
                    if san_type == "DNS":
                        sans.append(san_val)
                info["sans"] = sans

                # Dates
                not_before = peer_cert.get("notBefore", "")
                not_after = peer_cert.get("notAfter", "")
                # Python ssl dates look like "Nov  6 12:00:00 2025 GMT"
                for date_field, key in [(not_before, "not_before"), (not_after, "not_after")]:
                    if date_field:
                        try:
                            dt = datetime.strptime(date_field, "%b %d %H:%M:%S %Y %Z")
                            info[key] = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            info[key] = date_field

                # Serial
                info["serial_number"] = peer_cert.get("serialNumber", "")

                # Self-signed check: subject == issuer
                info["self_signed"] = info.get("subject") == info.get("issuer")

            # Key size from DER (try openssl if available)
            if der_cert:
                key_bits = await self._get_key_bits(der_cert)
                if key_bits:
                    info["key_bits"] = key_bits

            return info

        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            return None

    async def _get_key_bits(self, der_cert: bytes) -> int | None:
        """Extract public key bit length from DER certificate."""
        import tempfile
        import os

        tmp_path = ""
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".der")
            os.write(fd, der_cert)
            os.close(fd)

            stdout, _, rc = await self._run_command(
                ["openssl", "x509", "-inform", "DER", "-in", tmp_path, "-noout", "-text"],
                timeout=10,
            )
            if rc == 0:
                m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", stdout)
                if m:
                    return int(m.group(1))
        except Exception:
            pass
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return None

    @staticmethod
    def _cert_evidence(port: int, cert: dict[str, Any]) -> str:
        lines = [
            f"Port: {port}",
            f"Subject: {cert.get('subject', 'N/A')}",
            f"Common Name: {cert.get('common_name', 'N/A')}",
            f"Issuer: {cert.get('issuer', 'N/A')}",
            f"SANs: {', '.join(cert.get('sans') or ['none'])}",
            f"Not Before: {cert.get('not_before', 'N/A')}",
            f"Not After: {cert.get('not_after', 'N/A')}",
            f"Serial: {cert.get('serial_number', 'N/A')}",
            f"Key Size: {cert.get('key_bits', 'N/A')} bits",
            f"Self-Signed: {cert.get('self_signed', 'N/A')}",
        ]
        return "\n".join(lines)
