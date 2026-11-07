"""Protocol enumeration modules — SMB, SNMP, SMTP, RPC."""
from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Callable

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
# Helpers
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_text: str) -> ET.Element | None:
    """Parse nmap -oX output, return root element or None."""
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        return None


# ===================================================================
# SMB Enumeration
# ===================================================================

class SmbEnumModule(BaseModule):
    """Enumerate SMB shares, signing, OS info, and null session access."""

    @property
    def name(self) -> str:
        return "smb_enum"

    @property
    def display_name(self) -> str:
        return "SMB Enumeration"

    @property
    def description(self) -> str:
        return "Enumerate SMB shares, OS info, signing policy, and null session access"

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Protocol Enumeration"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        shares: list[dict[str, str]] = []
        users: list[str] = []
        groups: list[str] = []
        os_info: str = ""
        signing_required: bool | None = None
        null_session_ok = False

        # ------------------------------------------------------------------
        # 1. nmap SMB scripts
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Running nmap SMB scripts...")

        nmap_out, nmap_err, nmap_rc = await self._run_command(
            [
                "nmap", "-p", "445",
                "--script", "smb-enum-shares,smb-os-discovery,smb-security-mode",
                "-oX", "-", target,
            ],
            timeout=90,
        )

        if nmap_rc == 0 and nmap_out.strip():
            result.raw_output["nmap_xml"] = nmap_out

            root = _parse_nmap_xml(nmap_out)
            if root is not None:
                for script in root.iter("script"):
                    sid = script.get("id", "")
                    output = script.get("output", "")

                    if sid == "smb-os-discovery":
                        os_match = re.search(r"OS:\s*(.+)", output)
                        if os_match:
                            os_info = os_match.group(1).strip()
                        # also check <elem> children
                        for elem in script.findall(".//elem"):
                            if elem.get("key") == "os":
                                os_info = os_info or (elem.text or "").strip()

                    elif sid == "smb-security-mode":
                        if "message_signing" in output.lower():
                            signing_required = "required" in output.lower()
                        for elem in script.findall(".//elem"):
                            if elem.get("key") == "message_signing":
                                val = (elem.text or "").lower()
                                signing_required = val == "required"

                    elif sid == "smb-enum-shares":
                        for table in script.findall(".//table"):
                            share_name = table.get("key", "")
                            share_info: dict[str, str] = {"name": share_name}
                            for elem in table.findall("elem"):
                                share_info[elem.get("key", "")] = (elem.text or "")
                            if share_name:
                                shares.append(share_info)

        # ------------------------------------------------------------------
        # 2. smbclient null session fallback
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Trying null session with smbclient...")

        smb_out, smb_err, smb_rc = await self._run_command(
            ["smbclient", "-L", f"//{target}", "-N"],
            timeout=30,
        )
        result.raw_output["smbclient"] = smb_out + smb_err

        if smb_rc == 0 and smb_out.strip():
            null_session_ok = True
            # Parse share list: "  ShareName  Disk  Comment"
            for line in smb_out.splitlines():
                m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line)
                if m and not any(s["name"] == m.group(1) for s in shares):
                    shares.append({
                        "name": m.group(1),
                        "type": m.group(2),
                        "comment": m.group(3).strip(),
                    })

        # ------------------------------------------------------------------
        # 3. rpcclient null session — user & group enumeration
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Trying RPC null session for user/group enum...")

        rpc_users_out, _, rpc_users_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"],
            timeout=30,
        )
        result.raw_output["rpcclient_users"] = rpc_users_out

        if rpc_users_rc == 0 and rpc_users_out.strip() and "NT_STATUS" not in rpc_users_out:
            null_session_ok = True
            for m in re.finditer(r"user:\[([^\]]+)\]", rpc_users_out):
                uname = m.group(1)
                if uname not in users:
                    users.append(uname)

        rpc_groups_out, _, rpc_groups_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "enumdomgroups"],
            timeout=30,
        )
        result.raw_output["rpcclient_groups"] = rpc_groups_out

        if rpc_groups_rc == 0 and rpc_groups_out.strip() and "NT_STATUS" not in rpc_groups_out:
            for m in re.finditer(r"group:\[([^\]]+)\]", rpc_groups_out):
                gname = m.group(1)
                if gname not in groups:
                    groups.append(gname)

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        # Null / anonymous session access
        if null_session_ok:
            evidence_parts = []
            if smb_rc == 0:
                evidence_parts.append(f"smbclient -L //{target} -N succeeded")
            if rpc_users_rc == 0 and "NT_STATUS" not in rpc_users_out:
                evidence_parts.append(f"rpcclient enumdomusers returned {len(users)} user(s)")
            result.findings.append(
                ModuleFinding(
                    title="Anonymous/Null Session Access Allowed",
                    description=(
                        f"SMB null session is permitted on {target}. An unauthenticated "
                        "attacker can enumerate shares, users, and groups."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="Protocol Enumeration",
                    evidence="\n".join(evidence_parts),
                    raw_data={"users": users, "groups": groups, "shares": [s["name"] for s in shares]},
                    impact="Unauthenticated enumeration of domain users, groups, and shares — "
                           "facilitates password spraying and lateral movement.",
                    remediation="Disable anonymous access: set RestrictAnonymous=1 or 2 via GPO. "
                                "Disable null sessions on domain controllers.",
                    cwe_id="CWE-284",
                    cvss_score=7.5,
                    confidence=0.9,
                    validation_hint=f"smbclient -L //{target} -N",
                )
            )

        # SMB signing
        if signing_required is not None and not signing_required:
            result.findings.append(
                ModuleFinding(
                    title="SMB Signing Not Required",
                    description=f"SMB message signing is not enforced on {target}.",
                    severity=FindingSeverity.MEDIUM,
                    category="Protocol Enumeration",
                    evidence="smb-security-mode: message_signing != required",
                    impact="Enables SMB relay attacks (ntlmrelayx) to capture and relay "
                           "authentication hashes.",
                    remediation="Enable and require SMB signing via GPO: "
                                "Microsoft network server: Digitally sign communications (always) = Enabled.",
                    cwe_id="CWE-311",
                    cvss_score=5.3,
                    confidence=0.85,
                )
            )

        # Readable shares
        for share in shares:
            sname = share.get("name", "")
            stype = share.get("type", share.get("Type", ""))
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"smb://{target}/{sname}",
                    metadata={"share_name": sname, "type": stype, "protocol": "smb"},
                )
            )
            if sname and sname not in ("IPC$",):
                result.findings.append(
                    ModuleFinding(
                        title=f"Readable SMB Share: {sname}",
                        description=f"Share '{sname}' is accessible via null session on {target}.",
                        severity=FindingSeverity.MEDIUM,
                        category="Protocol Enumeration",
                        evidence=f"Share: {sname} Type: {stype}",
                        impact="May expose sensitive files, configs, or scripts to unauthenticated users.",
                        remediation="Restrict share permissions. Remove anonymous access.",
                        cwe_id="CWE-284",
                        confidence=0.75,
                    )
                )

        # OS version disclosure
        if os_info:
            result.findings.append(
                ModuleFinding(
                    title="SMB OS Version Disclosure",
                    description=f"SMB reveals operating system: {os_info}",
                    severity=FindingSeverity.LOW,
                    category="Protocol Enumeration",
                    evidence=f"OS: {os_info}",
                    impact="Aids attacker in targeting OS-specific exploits.",
                    remediation="Disable SMB OS discovery where possible.",
                    cwe_id="CWE-200",
                    confidence=0.9,
                )
            )

        # User assets
        for uname in users:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERSON,
                    value=uname,
                    metadata={"source": "smb_null_session", "host": target},
                )
            )

        result.raw_output["summary"] = {
            "shares": len(shares),
            "users": len(users),
            "groups": len(groups),
            "os_info": os_info,
            "signing_required": signing_required,
            "null_session": null_session_ok,
        }

        return result


# ===================================================================
# SNMP Enumeration
# ===================================================================

class SnmpEnumModule(BaseModule):
    """Enumerate SNMP community strings and extract system info."""

    @property
    def name(self) -> str:
        return "snmp_enum"

    @property
    def display_name(self) -> str:
        return "SNMP Enumeration"

    @property
    def description(self) -> str:
        return "Brute-force SNMP community strings and extract system/network info"

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Protocol Enumeration"

    _COMMUNITY_STRINGS = ["public", "private", "community", "manager", "cisco", "default"]

    _OID_MAP = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "interfaces": "1.3.6.1.2.1.2.2",
        "routes": "1.3.6.1.2.1.4.21",
    }

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        valid_communities: list[str] = []
        system_info: dict[str, str] = {}
        interfaces: list[str] = []

        # ------------------------------------------------------------------
        # 1. Try snmpwalk with each community string
        # ------------------------------------------------------------------
        for community in self._COMMUNITY_STRINGS:
            if progress_callback:
                await progress_callback(f"Trying SNMP community: {community}")

            # Quick single OID check first (sysDescr)
            out, err, rc = await self._run_command(
                ["snmpget", "-v2c", "-c", community, target, self._OID_MAP["sysDescr"]],
                timeout=10,
            )
            if rc != 0 or "Timeout" in err or "No Response" in err:
                # snmpget not available — try snmpwalk
                out, err, rc = await self._run_command(
                    ["snmpwalk", "-v2c", "-c", community, "-t", "5", "-r", "1",
                     target, self._OID_MAP["sysDescr"]],
                    timeout=15,
                )
                if rc != 0 or "Timeout" in (out + err) or "No Response" in (out + err):
                    continue

            if rc == 0 and out.strip() and "Timeout" not in out and "No Response" not in out:
                valid_communities.append(community)

                # Extract sysDescr
                desc_match = re.search(r"STRING:\s*[\"']?(.+?)[\"']?\s*$", out, re.M)
                if desc_match:
                    system_info["sysDescr"] = desc_match.group(1).strip()

                # Fetch remaining scalar OIDs
                for label, oid in self._OID_MAP.items():
                    if label in ("interfaces", "routes", "sysDescr"):
                        continue
                    scalar_out, _, scalar_rc = await self._run_command(
                        ["snmpget", "-v2c", "-c", community, target, oid],
                        timeout=10,
                    )
                    if scalar_rc != 0:
                        scalar_out, _, scalar_rc = await self._run_command(
                            ["snmpwalk", "-v2c", "-c", community, "-t", "5", "-r", "1",
                             target, oid],
                            timeout=15,
                        )
                    if scalar_rc == 0 and scalar_out.strip():
                        val_match = re.search(r"STRING:\s*[\"']?(.+?)[\"']?\s*$", scalar_out, re.M)
                        if val_match:
                            system_info[label] = val_match.group(1).strip()

                # Walk interfaces
                iface_out, _, iface_rc = await self._run_command(
                    ["snmpwalk", "-v2c", "-c", community, "-t", "5", "-r", "1",
                     target, self._OID_MAP["interfaces"]],
                    timeout=30,
                )
                if iface_rc == 0 and iface_out.strip():
                    for line in iface_out.splitlines():
                        iface_match = re.search(r"STRING:\s*[\"']?(.+?)[\"']?\s*$", line)
                        if iface_match:
                            iface_val = iface_match.group(1).strip()
                            if iface_val and iface_val not in interfaces:
                                interfaces.append(iface_val)

                # One valid community is enough to get info — stop bruting
                break

        # ------------------------------------------------------------------
        # 2. Fallback: nmap SNMP scripts
        # ------------------------------------------------------------------
        if not valid_communities:
            if progress_callback:
                await progress_callback("Falling back to nmap SNMP scripts...")

            nmap_out, _, nmap_rc = await self._run_command(
                [
                    "nmap", "-sU", "-p", "161",
                    "--script", "snmp-brute,snmp-info,snmp-interfaces",
                    "-oX", "-", target,
                ],
                timeout=90,
            )
            result.raw_output["nmap_xml"] = nmap_out

            if nmap_rc == 0:
                root = _parse_nmap_xml(nmap_out)
                if root is not None:
                    for script in root.iter("script"):
                        sid = script.get("id", "")
                        output = script.get("output", "")
                        if sid == "snmp-brute":
                            for m in re.finditer(r"(\S+)\s*-\s*Valid", output):
                                cs = m.group(1)
                                if cs not in valid_communities:
                                    valid_communities.append(cs)
                        elif sid == "snmp-info":
                            for elem in script.findall(".//elem"):
                                key = elem.get("key", "")
                                val = (elem.text or "").strip()
                                if key and val:
                                    system_info[key] = val
                        elif sid == "snmp-interfaces":
                            for table in script.findall(".//table"):
                                iname = table.get("key", "")
                                if iname and iname not in interfaces:
                                    interfaces.append(iname)

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        if valid_communities:
            result.findings.append(
                ModuleFinding(
                    title="Default SNMP Community String Accepted",
                    description=(
                        f"SNMP on {target} responds to default community string(s): "
                        f"{', '.join(valid_communities)}. Full device information is exposed."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="Protocol Enumeration",
                    evidence=(
                        f"Valid communities: {', '.join(valid_communities)}\n"
                        + "\n".join(f"  {k}: {v}" for k, v in system_info.items())
                    ),
                    raw_data={"communities": valid_communities, "system_info": system_info},
                    impact="Attacker can read full device configuration, interface list, "
                           "routing tables, ARP cache, and running processes. Write-access "
                           "community strings allow reconfiguration.",
                    remediation="Change default community strings to strong random values. "
                                "Restrict SNMP access via ACL to management VLAN. "
                                "Migrate to SNMPv3 with authentication and encryption.",
                    cwe_id="CWE-798",
                    cvss_score=7.5,
                    confidence=0.95,
                    validation_hint=f"snmpwalk -v2c -c {valid_communities[0]} {target}",
                )
            )

        # Hostname asset
        hostname = system_info.get("sysName", "")
        if hostname:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.DOMAIN,
                    value=hostname,
                    metadata={"source": "snmp", "host": target},
                )
            )

        # Interface assets
        for iface in interfaces:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"snmp://{target}/interface/{iface}",
                    metadata={"interface": iface, "host": target, "protocol": "snmp"},
                )
            )

        result.raw_output["summary"] = {
            "valid_communities": valid_communities,
            "system_info": system_info,
            "interfaces": interfaces,
        }

        return result


# ===================================================================
# SMTP Enumeration
# ===================================================================

class SmtpEnumModule(BaseModule):
    """Enumerate SMTP services — banner, VRFY, EXPN, open relay check."""

    @property
    def name(self) -> str:
        return "smtp_enum"

    @property
    def display_name(self) -> str:
        return "SMTP Enumeration"

    @property
    def description(self) -> str:
        return "Check SMTP for user enumeration (VRFY/EXPN) and open relay"

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Protocol Enumeration"

    _PORTS = [25, 587, 465]
    _VRFY_USERS = ["root", "admin", "test", "postmaster", "info", "webmaster"]

    async def _smtp_connect(
        self, target: str, port: int, use_ssl: bool = False
    ) -> dict[str, Any]:
        """Connect to SMTP, return banner + EHLO response + test results."""
        info: dict[str, Any] = {
            "port": port,
            "banner": "",
            "ehlo": "",
            "vrfy_enabled": False,
            "expn_enabled": False,
            "open_relay": False,
            "verified_users": [],
            "commands": [],
        }

        try:
            if use_ssl:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=True), timeout=10
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=10
                )
        except Exception:
            return info

        try:
            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=10)
            info["banner"] = banner.decode(errors="replace").strip()

            # EHLO
            writer.write(f"EHLO reconforge.local\r\n".encode())
            await writer.drain()
            ehlo_lines: list[str] = []
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=5)
                    decoded = line.decode(errors="replace").strip()
                    ehlo_lines.append(decoded)
                    if not decoded or decoded[3:4] == " ":
                        break
                except asyncio.TimeoutError:
                    break
            info["ehlo"] = "\n".join(ehlo_lines)
            info["commands"] = ehlo_lines

            # VRFY
            for user in self._VRFY_USERS:
                writer.write(f"VRFY {user}\r\n".encode())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.readline(), timeout=5)
                    resp_str = resp.decode(errors="replace").strip()
                    code = resp_str[:3] if len(resp_str) >= 3 else ""
                    if code in ("250", "251", "252"):
                        info["vrfy_enabled"] = True
                        info["verified_users"].append(user)
                except asyncio.TimeoutError:
                    break

            # EXPN
            writer.write(b"EXPN postmaster\r\n")
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                resp_str = resp.decode(errors="replace").strip()
                if resp_str[:3] in ("250", "251"):
                    info["expn_enabled"] = True
            except asyncio.TimeoutError:
                pass

            # Open relay test
            writer.write(b"MAIL FROM:<test@evil.com>\r\n")
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                mail_code = resp.decode(errors="replace").strip()[:3]
                if mail_code == "250":
                    writer.write(b"RCPT TO:<test@external-domain.com>\r\n")
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.readline(), timeout=5)
                    rcpt_code = resp.decode(errors="replace").strip()[:3]
                    if rcpt_code == "250":
                        info["open_relay"] = True
                    # Reset
                    writer.write(b"RSET\r\n")
                    await writer.drain()
                    try:
                        await asyncio.wait_for(reader.readline(), timeout=3)
                    except asyncio.TimeoutError:
                        pass
            except asyncio.TimeoutError:
                pass

            # QUIT
            writer.write(b"QUIT\r\n")
            await writer.drain()

        except Exception as exc:
            logger.debug("SMTP error on %s:%d — %s", target, port, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return info

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        port_results: list[dict[str, Any]] = []

        for port in self._PORTS:
            if progress_callback:
                await progress_callback(f"Probing SMTP on port {port}...")

            use_ssl = port == 465
            info = await self._smtp_connect(target, port, use_ssl=use_ssl)

            if not info["banner"]:
                continue  # port not open / no response

            port_results.append(info)

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"smtp://{target}:{port}",
                    metadata={"banner": info["banner"], "protocol": "smtp"},
                )
            )

            # Open relay
            if info["open_relay"]:
                result.findings.append(
                    ModuleFinding(
                        title=f"Open SMTP Relay on Port {port}",
                        description=(
                            f"SMTP server on {target}:{port} accepts mail from arbitrary "
                            "senders to arbitrary recipients — open relay confirmed."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="Protocol Enumeration",
                        evidence=(
                            f"MAIL FROM:<test@evil.com> → 250\n"
                            f"RCPT TO:<test@external-domain.com> → 250"
                        ),
                        impact="Attackers can send spoofed emails through this server, "
                               "enabling phishing, spam, and domain reputation damage.",
                        remediation="Configure SMTP to require authentication. Restrict "
                                    "relay to authorized senders/IPs only.",
                        cwe_id="CWE-284",
                        cvss_score=7.5,
                        confidence=0.9,
                        validation_hint=f"telnet {target} {port}, then MAIL FROM/RCPT TO",
                    )
                )

            # VRFY enabled
            if info["vrfy_enabled"]:
                result.findings.append(
                    ModuleFinding(
                        title=f"SMTP VRFY User Enumeration on Port {port}",
                        description=(
                            f"VRFY command is enabled on {target}:{port}. "
                            f"Verified users: {', '.join(info['verified_users'])}"
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category="Protocol Enumeration",
                        evidence="VRFY responded with 250/251/252 for: "
                                 + ", ".join(info["verified_users"]),
                        impact="Attacker can enumerate valid local usernames for brute-force "
                               "or social engineering.",
                        remediation="Disable VRFY: in Postfix set 'disable_vrfy_command = yes'. "
                                    "In Exim: set acl_smtp_vrfy to deny.",
                        cwe_id="CWE-200",
                        cvss_score=5.3,
                        confidence=0.85,
                    )
                )
                for user in info["verified_users"]:
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.EMAIL,
                            value=f"{user}@{target}",
                            metadata={"source": "smtp_vrfy", "port": port},
                        )
                    )

            # EXPN enabled
            if info["expn_enabled"]:
                result.findings.append(
                    ModuleFinding(
                        title=f"SMTP EXPN Mailing List Disclosure on Port {port}",
                        description=f"EXPN command is enabled on {target}:{port}, "
                                    "allowing mailing list member enumeration.",
                        severity=FindingSeverity.MEDIUM,
                        category="Protocol Enumeration",
                        evidence="EXPN postmaster returned 250/251",
                        impact="Attacker can enumerate members of distribution lists.",
                        remediation="Disable EXPN command on the mail server.",
                        cwe_id="CWE-200",
                        cvss_score=5.3,
                        confidence=0.8,
                    )
                )

            # Banner info disclosure
            if info["banner"]:
                result.findings.append(
                    ModuleFinding(
                        title=f"SMTP Banner Disclosure on Port {port}",
                        description=f"SMTP banner reveals server software/version: {info['banner']}",
                        severity=FindingSeverity.LOW,
                        category="Protocol Enumeration",
                        evidence=f"Banner: {info['banner']}",
                        impact="Server software and version info aids targeted exploitation.",
                        remediation="Customize SMTP banner to remove version information.",
                        cwe_id="CWE-200",
                        confidence=0.9,
                    )
                )

        result.raw_output["smtp_ports"] = port_results
        return result


# ===================================================================
# RPC Enumeration
# ===================================================================

class RpcEnumModule(BaseModule):
    """Enumerate RPC services, NFS exports, and anonymous access."""

    @property
    def name(self) -> str:
        return "rpc_enum"

    @property
    def display_name(self) -> str:
        return "RPC Enumeration"

    @property
    def description(self) -> str:
        return "Enumerate RPC services, NFS exports, and check for anonymous access"

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Protocol Enumeration"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        rpc_services: list[dict[str, str]] = []
        nfs_exports: list[dict[str, str]] = []
        anon_rpc = False

        # ------------------------------------------------------------------
        # 1. rpcinfo
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Running rpcinfo...")

        rpcinfo_out, rpcinfo_err, rpcinfo_rc = await self._run_command(
            ["rpcinfo", "-p", target], timeout=30
        )
        result.raw_output["rpcinfo"] = rpcinfo_out

        if rpcinfo_rc == 0 and rpcinfo_out.strip():
            # "  100000  4  tcp  111  portmapper"
            for line in rpcinfo_out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].isdigit():
                    svc = {
                        "program": parts[0],
                        "version": parts[1],
                        "proto": parts[2],
                        "port": parts[3],
                        "name": " ".join(parts[4:]),
                    }
                    rpc_services.append(svc)
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SERVICE,
                            value=f"rpc://{target}:{svc['port']}/{svc['name']}",
                            metadata={
                                "program": svc["program"],
                                "version": svc["version"],
                                "protocol": svc["proto"],
                            },
                        )
                    )

        # ------------------------------------------------------------------
        # 2. showmount — NFS exports
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Checking NFS exports...")

        showmount_out, _, showmount_rc = await self._run_command(
            ["showmount", "-e", target], timeout=30
        )
        result.raw_output["showmount"] = showmount_out

        if showmount_rc == 0 and showmount_out.strip():
            for line in showmount_out.splitlines():
                # "/share  host1,host2" or "/share  *" or "/share (everyone)"
                m = re.match(r"(/\S+)\s+(.*)", line.strip())
                if m:
                    export_path = m.group(1)
                    allowed = m.group(2).strip()
                    export = {"path": export_path, "allowed": allowed}
                    nfs_exports.append(export)

                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SERVICE,
                            value=f"nfs://{target}{export_path}",
                            metadata={
                                "export_path": export_path,
                                "allowed_hosts": allowed,
                                "protocol": "nfs",
                            },
                        )
                    )

        # ------------------------------------------------------------------
        # 3. rpcclient — anonymous access + share enum
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Trying anonymous RPC access...")

        srvinfo_out, _, srvinfo_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "srvinfo"], timeout=20
        )
        result.raw_output["rpcclient_srvinfo"] = srvinfo_out

        if srvinfo_rc == 0 and srvinfo_out.strip() and "NT_STATUS" not in srvinfo_out:
            anon_rpc = True

        share_out, _, share_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "netshareenumall"], timeout=20
        )
        result.raw_output["rpcclient_shares"] = share_out

        if share_rc == 0 and share_out.strip() and "NT_STATUS" not in share_out:
            anon_rpc = True

        # ------------------------------------------------------------------
        # 4. Fallback: nmap RPC/NFS scripts
        # ------------------------------------------------------------------
        if not rpc_services and not nfs_exports:
            if progress_callback:
                await progress_callback("Falling back to nmap RPC/NFS scripts...")

            nmap_out, _, nmap_rc = await self._run_command(
                [
                    "nmap", "-p", "111,2049",
                    "--script", "rpc-grind,nfs-ls,nfs-showmount,nfs-statfs",
                    "-oX", "-", target,
                ],
                timeout=90,
            )
            result.raw_output["nmap_xml"] = nmap_out

            if nmap_rc == 0:
                root = _parse_nmap_xml(nmap_out)
                if root is not None:
                    for script in root.iter("script"):
                        sid = script.get("id", "")
                        output = script.get("output", "")
                        if sid == "nfs-showmount":
                            for m in re.finditer(r"(/\S+)\s+(.*)", output):
                                export = {"path": m.group(1), "allowed": m.group(2).strip()}
                                nfs_exports.append(export)
                                result.assets.append(
                                    ModuleAsset(
                                        asset_type=AssetType.SERVICE,
                                        value=f"nfs://{target}{export['path']}",
                                        metadata={
                                            "export_path": export["path"],
                                            "allowed_hosts": export["allowed"],
                                            "protocol": "nfs",
                                        },
                                    )
                                )

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        # World-readable NFS exports
        for export in nfs_exports:
            allowed = export.get("allowed", "")
            path = export.get("path", "")

            if "*" in allowed or "everyone" in allowed.lower() or not allowed:
                result.findings.append(
                    ModuleFinding(
                        title=f"World-Readable NFS Export: {path}",
                        description=(
                            f"NFS export {path} on {target} is accessible to all hosts."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="Protocol Enumeration",
                        evidence=f"showmount -e: {path}  {allowed}",
                        impact="Any host can mount and read/write files on this export. "
                               "May contain sensitive configs, credentials, or source code.",
                        remediation="Restrict NFS export to specific IP addresses or subnets "
                                    "in /etc/exports. Apply proper UID mapping.",
                        cwe_id="CWE-284",
                        cvss_score=7.5,
                        confidence=0.9,
                        validation_hint=f"mount -t nfs {target}:{path} /mnt/test",
                    )
                )

        # Check for no_root_squash — requires mounting or deeper inspection
        # We flag it if nmap nfs-ls output mentions root ownership
        nmap_nfs = result.raw_output.get("nmap_xml", "")
        if "no_root_squash" in nmap_nfs.lower() or "no_root_squash" in showmount_out.lower():
            result.findings.append(
                ModuleFinding(
                    title="NFS Export with no_root_squash",
                    description=(
                        f"An NFS export on {target} has no_root_squash enabled, "
                        "allowing remote root to act as root on the share."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    category="Protocol Enumeration",
                    evidence="no_root_squash detected in NFS export options",
                    impact="Remote attacker can write SUID binaries or overwrite system files "
                           "as root — leads to full system compromise.",
                    remediation="Enable root_squash on all NFS exports. Map remote root to "
                                "nfsnobody.",
                    cwe_id="CWE-269",
                    cvss_score=9.0,
                    confidence=0.85,
                    validation_hint="Mount the export as root and check file ownership.",
                )
            )

        # Anonymous RPC access
        if anon_rpc:
            result.findings.append(
                ModuleFinding(
                    title="Anonymous RPC Access Allowed",
                    description=f"RPC services on {target} allow anonymous/null session access.",
                    severity=FindingSeverity.MEDIUM,
                    category="Protocol Enumeration",
                    evidence=f"rpcclient -U '' -N {target} -c 'srvinfo' succeeded",
                    impact="Attacker can enumerate server info and shares without credentials.",
                    remediation="Restrict anonymous access to RPC services via GPO or firewall.",
                    cwe_id="CWE-284",
                    confidence=0.8,
                )
            )

        result.raw_output["summary"] = {
            "rpc_services": len(rpc_services),
            "nfs_exports": len(nfs_exports),
            "anonymous_rpc": anon_rpc,
        }

        return result
