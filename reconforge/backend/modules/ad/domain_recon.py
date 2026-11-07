"""Active Directory domain reconnaissance modules."""
from __future__ import annotations

import logging
import re
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


# ===================================================================
# AD DNS Enumeration
# ===================================================================

class AdDnsModule(BaseModule):
    """Map AD infrastructure via SRV record enumeration."""

    @property
    def name(self) -> str:
        return "ad_dns"

    @property
    def display_name(self) -> str:
        return "AD DNS Enumeration"

    @property
    def description(self) -> str:
        return "Enumerate AD Domain Controllers, GC servers, and sites via DNS SRV records"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Reconnaissance"

    _SRV_QUERIES = {
        "LDAP (Domain Controllers)": "_ldap._tcp.{domain}",
        "Kerberos KDC": "_kerberos._tcp.{domain}",
        "Global Catalog": "_gc._tcp.{domain}",
        "Kerberos Password Change": "_kpasswd._tcp.{domain}",
        "DC Locator": "_ldap._tcp.dc._msdcs.{domain}",
        "PDC Emulator": "_ldap._tcp.pdc._msdcs.{domain}",
        "GC Locator": "_ldap._tcp.gc._msdcs.{domain}",
    }

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        dc_set: set[str] = set()
        gc_set: set[str] = set()
        srv_results: dict[str, list[str]] = {}

        for label, template in self._SRV_QUERIES.items():
            query = template.format(domain=domain)
            if progress_callback:
                await progress_callback(f"Querying {query}...")

            records = await self._resolve_dns(query, "SRV")

            hosts: list[str] = []
            for record in records:
                # SRV record format: "priority weight port target"
                parts = str(record).split()
                if len(parts) >= 4:
                    hostname = parts[3].rstrip(".")
                else:
                    hostname = str(record).rstrip(".")
                if hostname:
                    hosts.append(hostname)

            srv_results[label] = hosts

            for host in hosts:
                # Resolve A record for each host
                ips = await self._resolve_dns(host, "A")

                is_dc = "Domain Controller" in label or "DC Locator" in label or "PDC" in label
                is_gc = "Global Catalog" in label or "GC Locator" in label

                if is_dc:
                    dc_set.add(host)
                if is_gc:
                    gc_set.add(host)

                for ip in ips:
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.IP,
                            value=ip,
                            metadata={
                                "hostname": host,
                                "role": label,
                                "domain": domain,
                            },
                        )
                    )

                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SERVICE,
                        value=host,
                        metadata={
                            "role": label,
                            "domain": domain,
                            "ips": ips,
                            "protocol": "ldap" if "LDAP" in label else "kerberos",
                        },
                    )
                )

        # Summary finding
        if dc_set or gc_set:
            evidence_lines = []
            for label, hosts in srv_results.items():
                if hosts:
                    evidence_lines.append(f"{label}: {', '.join(hosts)}")

            result.findings.append(
                ModuleFinding(
                    title=f"AD Infrastructure Map — {domain}",
                    description=(
                        f"Identified {len(dc_set)} Domain Controller(s) and "
                        f"{len(gc_set)} Global Catalog server(s) for {domain}."
                    ),
                    severity=FindingSeverity.INFO,
                    category="AD Reconnaissance",
                    evidence="\n".join(evidence_lines),
                    raw_data={
                        "domain_controllers": sorted(dc_set),
                        "global_catalogs": sorted(gc_set),
                        "srv_records": srv_results,
                    },
                    impact="Identifies key AD infrastructure targets for further enumeration.",
                    remediation="Restrict DNS zone transfers. Consider split-horizon DNS to "
                                "limit internal SRV record exposure.",
                    confidence=0.95,
                )
            )
        else:
            result.findings.append(
                ModuleFinding(
                    title=f"No AD SRV Records Found for {domain}",
                    description="DNS SRV record queries returned no results. Domain may "
                                "not be an AD domain or DNS is filtered.",
                    severity=FindingSeverity.INFO,
                    category="AD Reconnaissance",
                    evidence=f"All SRV queries for {domain} returned empty",
                    confidence=0.7,
                )
            )

        result.raw_output["srv_results"] = srv_results
        result.raw_output["domain_controllers"] = sorted(dc_set)
        result.raw_output["global_catalogs"] = sorted(gc_set)

        return result


# ===================================================================
# LDAP Enumeration
# ===================================================================

class LdapEnumModule(BaseModule):
    """Attempt anonymous LDAP bind and enumerate AD objects."""

    @property
    def name(self) -> str:
        return "ldap_enum"

    @property
    def display_name(self) -> str:
        return "LDAP Enumeration"

    @property
    def description(self) -> str:
        return "Anonymous LDAP bind and enumeration of users, groups, computers, and OUs"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Reconnaissance"

    @property
    def timeout(self) -> int:
        return 180

    # userAccountControl flag masks
    _UAC_DONT_EXPIRE_PASSWORD = 0x10000
    _UAC_PASSWD_NOTREQD = 0x0020
    _UAC_ACCOUNTDISABLE = 0x0002

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        bound = False
        base_dn = ""
        domain_info: dict[str, Any] = {}
        users: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        computers: list[dict[str, Any]] = []
        ous: list[str] = []

        try:
            from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE
        except ImportError:
            result.error = "ldap3 library not installed — pip install ldap3"
            return result

        # ------------------------------------------------------------------
        # 1. Anonymous bind + rootDSE
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Attempting anonymous LDAP bind...")

        try:
            server = Server(target, get_info=ALL, connect_timeout=15)
            conn = Connection(server, authentication=ANONYMOUS, read_only=True)
            bound = conn.bind()
        except Exception as exc:
            result.raw_output["bind_error"] = str(exc)
            bound = False

        if not bound:
            result.findings.append(
                ModuleFinding(
                    title="Anonymous LDAP Bind Rejected",
                    description=f"LDAP on {target} does not allow anonymous binding.",
                    severity=FindingSeverity.INFO,
                    category="AD Reconnaissance",
                    evidence=f"bind() returned False or raised: {result.raw_output.get('bind_error', 'rejected')}",
                    confidence=0.85,
                )
            )
            return result

        # Extract rootDSE info
        try:
            if server.info:
                si = server.info
                base_dn = str(si.other.get("defaultNamingContext", [""])[0]) if hasattr(si, "other") and si.other else ""
                domain_info = {
                    "defaultNamingContext": base_dn,
                    "schemaNamingContext": str(si.other.get("schemaNamingContext", [""])[0]) if si.other else "",
                    "configurationNamingContext": str(si.other.get("configurationNamingContext", [""])[0]) if si.other else "",
                    "domainFunctionality": str(si.other.get("domainFunctionality", [""])[0]) if si.other else "",
                    "forestFunctionality": str(si.other.get("forestFunctionality", [""])[0]) if si.other else "",
                }
        except Exception:
            pass

        if not base_dn:
            # Derive from domain name
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))

        result.raw_output["domain_info"] = domain_info
        result.raw_output["base_dn"] = base_dn

        # Anonymous bind worked — HIGH finding
        result.findings.append(
            ModuleFinding(
                title="Anonymous LDAP Bind Allowed",
                description=(
                    f"LDAP on {target} permits anonymous binding. "
                    f"Base DN: {base_dn}"
                ),
                severity=FindingSeverity.HIGH,
                category="AD Reconnaissance",
                evidence=f"Anonymous bind succeeded\nBase DN: {base_dn}\n"
                         f"Domain Functionality: {domain_info.get('domainFunctionality', 'unknown')}",
                impact="Full directory enumeration without credentials — users, groups, "
                       "computers, OUs, and trust relationships are exposed.",
                remediation="Disable anonymous LDAP binds. Configure "
                            "dsHeuristics to restrict anonymous access. "
                            "Require LDAP signing and channel binding.",
                cwe_id="CWE-284",
                cvss_score=7.5,
                confidence=0.95,
                validation_hint=f"ldapsearch -x -H ldap://{target} -b '{base_dn}' '(objectClass=user)'",
            )
        )

        # ------------------------------------------------------------------
        # 2. Enumerate users
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Enumerating users...")

        try:
            conn.search(
                base_dn,
                "(objectClass=user)",
                search_scope=SUBTREE,
                attributes=[
                    "sAMAccountName", "mail", "memberOf",
                    "userAccountControl", "lastLogon", "pwdLastSet",
                    "description",
                ],
                size_limit=1000,
            )
            for entry in conn.entries:
                uac_raw = entry.userAccountControl.value if hasattr(entry, "userAccountControl") and entry.userAccountControl else 0
                try:
                    uac = int(uac_raw) if uac_raw else 0
                except (ValueError, TypeError):
                    uac = 0

                user = {
                    "sAMAccountName": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                    "mail": str(entry.mail) if hasattr(entry, "mail") and entry.mail else "",
                    "memberOf": [str(g) for g in entry.memberOf] if hasattr(entry, "memberOf") and entry.memberOf else [],
                    "uac": uac,
                    "disabled": bool(uac & self._UAC_ACCOUNTDISABLE),
                    "dont_expire": bool(uac & self._UAC_DONT_EXPIRE_PASSWORD),
                    "passwd_notreqd": bool(uac & self._UAC_PASSWD_NOTREQD),
                    "description": str(entry.description) if hasattr(entry, "description") and entry.description else "",
                }
                if user["sAMAccountName"]:
                    users.append(user)
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.PERSON,
                            value=user["sAMAccountName"],
                            metadata={
                                "mail": user["mail"],
                                "disabled": user["disabled"],
                                "dont_expire": user["dont_expire"],
                                "passwd_notreqd": user["passwd_notreqd"],
                                "domain": domain,
                            },
                        )
                    )
        except Exception as exc:
            logger.debug("User enumeration error: %s", exc)

        # ------------------------------------------------------------------
        # 3. Enumerate groups
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Enumerating groups...")

        try:
            conn.search(
                base_dn,
                "(objectClass=group)",
                search_scope=SUBTREE,
                attributes=["cn", "member", "description"],
                size_limit=500,
            )
            for entry in conn.entries:
                group = {
                    "cn": str(entry.cn) if hasattr(entry, "cn") else "",
                    "members": len(entry.member) if hasattr(entry, "member") and entry.member else 0,
                    "description": str(entry.description) if hasattr(entry, "description") and entry.description else "",
                }
                if group["cn"]:
                    groups.append(group)
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SERVICE,
                            value=f"group:{group['cn']}",
                            metadata={
                                "member_count": group["members"],
                                "description": group["description"],
                                "domain": domain,
                            },
                        )
                    )
        except Exception as exc:
            logger.debug("Group enumeration error: %s", exc)

        # ------------------------------------------------------------------
        # 4. Enumerate computers
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Enumerating computers...")

        try:
            conn.search(
                base_dn,
                "(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=["dNSHostName", "operatingSystem", "operatingSystemVersion"],
                size_limit=500,
            )
            for entry in conn.entries:
                comp = {
                    "dNSHostName": str(entry.dNSHostName) if hasattr(entry, "dNSHostName") and entry.dNSHostName else "",
                    "os": str(entry.operatingSystem) if hasattr(entry, "operatingSystem") and entry.operatingSystem else "",
                    "os_version": str(entry.operatingSystemVersion) if hasattr(entry, "operatingSystemVersion") and entry.operatingSystemVersion else "",
                }
                if comp["dNSHostName"]:
                    computers.append(comp)
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.DOMAIN,
                            value=comp["dNSHostName"],
                            metadata={
                                "os": comp["os"],
                                "os_version": comp["os_version"],
                                "domain": domain,
                            },
                        )
                    )
        except Exception as exc:
            logger.debug("Computer enumeration error: %s", exc)

        # ------------------------------------------------------------------
        # 5. Enumerate OUs
        # ------------------------------------------------------------------
        try:
            conn.search(
                base_dn,
                "(objectClass=organizationalUnit)",
                search_scope=SUBTREE,
                attributes=["ou"],
                size_limit=200,
            )
            for entry in conn.entries:
                ou_name = str(entry.ou) if hasattr(entry, "ou") and entry.ou else ""
                if ou_name:
                    ous.append(ou_name)
        except Exception:
            pass

        # Unbind
        try:
            conn.unbind()
        except Exception:
            pass

        # ------------------------------------------------------------------
        # Findings from enumerated data
        # ------------------------------------------------------------------

        # Users with DONT_EXPIRE_PASSWORD
        no_expire = [u for u in users if u["dont_expire"] and not u["disabled"]]
        if no_expire:
            result.findings.append(
                ModuleFinding(
                    title=f"{len(no_expire)} Users with Non-Expiring Passwords",
                    description="Active accounts have DONT_EXPIRE_PASSWORD flag set.",
                    severity=FindingSeverity.MEDIUM,
                    category="AD Reconnaissance",
                    evidence="Users: " + ", ".join(u["sAMAccountName"] for u in no_expire[:20]),
                    impact="Passwords that never expire increase window for credential "
                           "compromise via brute-force or credential stuffing.",
                    remediation="Review and remove DONT_EXPIRE_PASSWORD flag. Enforce "
                                "password rotation via Fine-Grained Password Policy.",
                    cwe_id="CWE-262",
                    confidence=0.9,
                )
            )

        # Users with PASSWD_NOTREQD
        no_pwd = [u for u in users if u["passwd_notreqd"] and not u["disabled"]]
        if no_pwd:
            result.findings.append(
                ModuleFinding(
                    title=f"{len(no_pwd)} Users with PASSWD_NOTREQD Flag",
                    description="Active accounts have PASSWD_NOTREQD set — password may be blank.",
                    severity=FindingSeverity.HIGH,
                    category="AD Reconnaissance",
                    evidence="Users: " + ", ".join(u["sAMAccountName"] for u in no_pwd[:20]),
                    impact="Accounts may have empty passwords, allowing trivial authentication.",
                    remediation="Clear PASSWD_NOTREQD flag and enforce minimum password length.",
                    cwe_id="CWE-521",
                    cvss_score=7.5,
                    confidence=0.85,
                )
            )

        # Disabled accounts still in privileged groups
        disabled_in_groups = [
            u for u in users
            if u["disabled"] and u["memberOf"]
            and any("admin" in g.lower() for g in u["memberOf"])
        ]
        if disabled_in_groups:
            result.findings.append(
                ModuleFinding(
                    title=f"{len(disabled_in_groups)} Disabled Accounts in Admin Groups",
                    description="Disabled accounts remain members of privileged groups.",
                    severity=FindingSeverity.LOW,
                    category="AD Reconnaissance",
                    evidence="Accounts: " + ", ".join(
                        u["sAMAccountName"] for u in disabled_in_groups[:10]
                    ),
                    impact="If re-enabled, these accounts instantly gain admin privileges. "
                           "Stale group memberships violate least privilege.",
                    remediation="Remove disabled accounts from all security groups.",
                    confidence=0.75,
                )
            )

        result.raw_output["summary"] = {
            "users": len(users),
            "groups": len(groups),
            "computers": len(computers),
            "ous": len(ous),
        }

        return result


# ===================================================================
# Null Session Check
# ===================================================================

class NullSessionModule(BaseModule):
    """Check for null/anonymous SMB and RPC access to AD."""

    @property
    def name(self) -> str:
        return "null_session"

    @property
    def display_name(self) -> str:
        return "Null Session Check"

    @property
    def description(self) -> str:
        return "Test for null/anonymous SMB and RPC session access to Active Directory"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Reconnaissance"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        smb_null = False
        rpc_null = False
        discovered_users: list[str] = []
        discovered_groups: list[str] = []
        discovered_shares: list[str] = []
        domain_info: str = ""

        # ------------------------------------------------------------------
        # 1. smbclient null session
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Testing SMB null session...")

        smb_out, smb_err, smb_rc = await self._run_command(
            ["smbclient", "-L", f"//{target}", "-N"], timeout=30
        )
        result.raw_output["smbclient"] = smb_out + smb_err

        if smb_rc == 0 and smb_out.strip() and "NT_STATUS" not in smb_out:
            smb_null = True
            for m in re.finditer(r"\s+(\S+)\s+(Disk|IPC|Printer)", smb_out):
                sname = m.group(1)
                if sname not in discovered_shares:
                    discovered_shares.append(sname)

        # ------------------------------------------------------------------
        # 2. rpcclient — enumdomusers
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Testing RPC null session — user enumeration...")

        rpc_users_out, _, rpc_users_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"], timeout=30
        )
        result.raw_output["rpcclient_users"] = rpc_users_out

        if rpc_users_rc == 0 and rpc_users_out.strip() and "NT_STATUS" not in rpc_users_out:
            rpc_null = True
            for m in re.finditer(r"user:\[([^\]]+)\]", rpc_users_out):
                uname = m.group(1)
                if uname not in discovered_users:
                    discovered_users.append(uname)

        # ------------------------------------------------------------------
        # 3. rpcclient — querydominfo
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Querying domain info via RPC...")

        dom_out, _, dom_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "querydominfo"], timeout=30
        )
        result.raw_output["rpcclient_dominfo"] = dom_out

        if dom_rc == 0 and dom_out.strip() and "NT_STATUS" not in dom_out:
            rpc_null = True
            domain_info = dom_out.strip()

        # ------------------------------------------------------------------
        # 4. rpcclient — enumdomgroups
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Enumerating groups via RPC...")

        grp_out, _, grp_rc = await self._run_command(
            ["rpcclient", "-U", "", "-N", target, "-c", "enumdomgroups"], timeout=30
        )
        result.raw_output["rpcclient_groups"] = grp_out

        if grp_rc == 0 and grp_out.strip() and "NT_STATUS" not in grp_out:
            rpc_null = True
            for m in re.finditer(r"group:\[([^\]]+)\]", grp_out):
                gname = m.group(1)
                if gname not in discovered_groups:
                    discovered_groups.append(gname)

        # ------------------------------------------------------------------
        # 5. net rpc info (alternative)
        # ------------------------------------------------------------------
        net_out, _, net_rc = await self._run_command(
            ["net", "rpc", "info", "-I", target, "-U", "\"\"/\"\""], timeout=20
        )
        result.raw_output["net_rpc_info"] = net_out

        if net_rc == 0 and net_out.strip() and "NT_STATUS" not in net_out:
            rpc_null = True

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        if smb_null:
            result.findings.append(
                ModuleFinding(
                    title="Null Session via SMB",
                    description=(
                        f"SMB null session succeeds on {target}. "
                        f"Shares enumerated: {', '.join(discovered_shares) or 'none listed'}."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="AD Reconnaissance",
                    evidence=f"smbclient -L //{target} -N returned share list",
                    raw_data={"shares": discovered_shares},
                    impact="Unauthenticated access to share listing aids attacker reconnaissance.",
                    remediation="Disable anonymous SMB access. Set RestrictAnonymous=2 via GPO.",
                    cwe_id="CWE-284",
                    cvss_score=7.5,
                    confidence=0.9,
                )
            )

        if rpc_null:
            result.findings.append(
                ModuleFinding(
                    title="Null Session via RPC",
                    description=(
                        f"RPC null session succeeds on {target}. "
                        f"Enumerated {len(discovered_users)} user(s) and "
                        f"{len(discovered_groups)} group(s)."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="AD Reconnaissance",
                    evidence=(
                        f"rpcclient -U '' -N {target} succeeded\n"
                        f"Users: {', '.join(discovered_users[:20]) or 'none'}\n"
                        f"Groups: {', '.join(discovered_groups[:20]) or 'none'}"
                    ),
                    raw_data={"users": discovered_users, "groups": discovered_groups},
                    impact="Full user/group enumeration without credentials enables "
                           "password spraying and privilege escalation planning.",
                    remediation="Disable anonymous RPC access. Set RestrictAnonymousSAM=1 "
                                "and RestrictAnonymous=2 via GPO.",
                    cwe_id="CWE-284",
                    cvss_score=7.5,
                    confidence=0.9,
                )
            )

        if discovered_users:
            result.findings.append(
                ModuleFinding(
                    title=f"User Enumeration via Null Session — {len(discovered_users)} Users",
                    description="Domain users enumerated without authentication.",
                    severity=FindingSeverity.MEDIUM,
                    category="AD Reconnaissance",
                    evidence="Users: " + ", ".join(discovered_users[:30]),
                    impact="User list enables targeted password spraying and social engineering.",
                    remediation="Restrict anonymous enumeration of SAM accounts.",
                    cwe_id="CWE-200",
                    confidence=0.9,
                )
            )

        if discovered_shares:
            result.findings.append(
                ModuleFinding(
                    title=f"Share Listing via Null Session — {len(discovered_shares)} Shares",
                    description="SMB shares enumerated without authentication.",
                    severity=FindingSeverity.MEDIUM,
                    category="AD Reconnaissance",
                    evidence="Shares: " + ", ".join(discovered_shares),
                    impact="Share names reveal internal resources and potential data access points.",
                    remediation="Restrict anonymous share enumeration.",
                    cwe_id="CWE-200",
                    confidence=0.85,
                )
            )

        if not smb_null and not rpc_null:
            result.findings.append(
                ModuleFinding(
                    title="Null Session Rejected",
                    description=f"Both SMB and RPC null sessions are blocked on {target}.",
                    severity=FindingSeverity.INFO,
                    category="AD Reconnaissance",
                    evidence="All null session attempts returned NT_STATUS_ACCESS_DENIED or failed",
                    confidence=0.85,
                )
            )

        # Assets
        for uname in discovered_users:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERSON,
                    value=uname,
                    metadata={"source": "null_session", "host": target},
                )
            )
        for sname in discovered_shares:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"smb://{target}/{sname}",
                    metadata={"share_name": sname, "protocol": "smb"},
                )
            )

        result.raw_output["summary"] = {
            "smb_null": smb_null,
            "rpc_null": rpc_null,
            "users": len(discovered_users),
            "groups": len(discovered_groups),
            "shares": len(discovered_shares),
        }

        return result


# ===================================================================
# Domain Trust Mapping
# ===================================================================

class DomainTrustModule(BaseModule):
    """Map AD domain trusts and evaluate trust security posture."""

    @property
    def name(self) -> str:
        return "domain_trust"

    @property
    def display_name(self) -> str:
        return "Domain Trust Mapping"

    @property
    def description(self) -> str:
        return "Enumerate AD domain trusts, direction, transitivity, and SID filtering"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Reconnaissance"

    # Trust direction constants
    _TRUST_DIR = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}

    # Trust attribute flags
    _TRUST_ATTR_NON_TRANSITIVE = 0x1
    _TRUST_ATTR_FILTER_SIDS = 0x4
    _TRUST_ATTR_FOREST_TRANSITIVE = 0x8

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        trusts: list[dict[str, Any]] = []
        trust_found = False

        # ------------------------------------------------------------------
        # 1. LDAP query for trustedDomain objects
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Querying LDAP for domain trusts...")

        try:
            from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE

            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            system_dn = f"CN=System,{base_dn}"

            server = Server(target, get_info=ALL, connect_timeout=15)
            conn = Connection(server, authentication=ANONYMOUS, read_only=True)
            bound = conn.bind()

            if bound:
                conn.search(
                    system_dn,
                    "(objectClass=trustedDomain)",
                    search_scope=SUBTREE,
                    attributes=[
                        "trustPartner", "trustDirection", "trustType",
                        "trustAttributes", "flatName", "securityIdentifier",
                    ],
                    size_limit=100,
                )
                for entry in conn.entries:
                    partner = str(entry.trustPartner) if hasattr(entry, "trustPartner") and entry.trustPartner else ""
                    try:
                        direction = int(entry.trustDirection.value) if hasattr(entry, "trustDirection") and entry.trustDirection else 0
                    except (ValueError, TypeError):
                        direction = 0
                    try:
                        attrs = int(entry.trustAttributes.value) if hasattr(entry, "trustAttributes") and entry.trustAttributes else 0
                    except (ValueError, TypeError):
                        attrs = 0
                    try:
                        ttype = int(entry.trustType.value) if hasattr(entry, "trustType") and entry.trustType else 0
                    except (ValueError, TypeError):
                        ttype = 0

                    flat = str(entry.flatName) if hasattr(entry, "flatName") and entry.flatName else ""

                    trust = {
                        "partner": partner,
                        "direction": direction,
                        "direction_label": self._TRUST_DIR.get(direction, f"Unknown({direction})"),
                        "type": ttype,
                        "attributes": attrs,
                        "flat_name": flat,
                        "transitive": not bool(attrs & self._TRUST_ATTR_NON_TRANSITIVE),
                        "sid_filtering": bool(attrs & self._TRUST_ATTR_FILTER_SIDS),
                        "forest_transitive": bool(attrs & self._TRUST_ATTR_FOREST_TRANSITIVE),
                    }
                    trusts.append(trust)
                    trust_found = True

                conn.unbind()
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("LDAP trust query error: %s", exc)

        # ------------------------------------------------------------------
        # 2. Fallback: nltest
        # ------------------------------------------------------------------
        if not trust_found:
            if progress_callback:
                await progress_callback("Trying nltest for trust enumeration...")

            nl_out, _, nl_rc = await self._run_command(
                ["nltest", "/domain_trusts", "/all_trusts", f"/server:{target}"],
                timeout=30,
            )
            result.raw_output["nltest"] = nl_out

            if nl_rc == 0 and nl_out.strip():
                for line in nl_out.splitlines():
                    line = line.strip()
                    if not line or line.startswith("The command"):
                        continue
                    # "partner.domain ( flags ) ..."
                    parts = line.split()
                    if parts:
                        trust = {
                            "partner": parts[0],
                            "raw_line": line,
                            "direction": 0,
                            "direction_label": "Unknown",
                            "transitive": "Trans" in line,
                            "sid_filtering": False,
                            "forest_transitive": "Forest" in line,
                        }
                        # Parse direction from flags
                        if "Direct Outbound" in line:
                            trust["direction"] = 2
                            trust["direction_label"] = "Outbound"
                        elif "Direct Inbound" in line:
                            trust["direction"] = 1
                            trust["direction_label"] = "Inbound"
                        elif "Attr:" in line and "0x20" not in line:
                            trust["direction"] = 3
                            trust["direction_label"] = "Bidirectional"
                        trusts.append(trust)
                        trust_found = True

        # ------------------------------------------------------------------
        # 3. Fallback: rpcclient dsenumdomtrusts
        # ------------------------------------------------------------------
        if not trust_found:
            if progress_callback:
                await progress_callback("Trying rpcclient for trust enumeration...")

            rpc_out, _, rpc_rc = await self._run_command(
                ["rpcclient", "-U", "", "-N", target, "-c", "dsenumdomtrusts"],
                timeout=30,
            )
            result.raw_output["rpcclient_trusts"] = rpc_out

            if rpc_rc == 0 and rpc_out.strip() and "NT_STATUS" not in rpc_out:
                for line in rpc_out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if parts:
                        trust = {
                            "partner": parts[0],
                            "raw_line": line,
                            "direction": 0,
                            "direction_label": "Unknown",
                            "transitive": False,
                            "sid_filtering": False,
                            "forest_transitive": False,
                        }
                        trusts.append(trust)
                        trust_found = True

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        for trust in trusts:
            partner = trust.get("partner", "unknown")

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.DOMAIN,
                    value=partner,
                    metadata={
                        "trust_direction": trust.get("direction_label", "Unknown"),
                        "transitive": trust.get("transitive", False),
                        "sid_filtering": trust.get("sid_filtering", False),
                        "source_domain": domain,
                    },
                )
            )

            # Bidirectional trust without SID filtering
            if trust.get("direction") == 3 and not trust.get("sid_filtering"):
                result.findings.append(
                    ModuleFinding(
                        title=f"Bidirectional Trust Without SID Filtering: {partner}",
                        description=(
                            f"Bidirectional trust with {partner} does not enforce SID filtering. "
                            "Allows SID history injection for cross-domain privilege escalation."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="AD Reconnaissance",
                        evidence=(
                            f"Trust: {domain} <-> {partner}\n"
                            f"Direction: Bidirectional\nSID Filtering: Disabled"
                        ),
                        impact="Attacker compromising either domain can forge tickets with "
                               "SID history to escalate to Domain Admin in the trusted domain.",
                        remediation="Enable SID filtering (quarantine) on the trust. "
                                    "Run: netdom trust /d:{domain} {partner} /quarantine:yes",
                        cwe_id="CWE-269",
                        cvss_score=8.0,
                        confidence=0.8,
                    )
                )

            # Transitive trust
            elif trust.get("transitive") and trust.get("direction") in (2, 3):
                result.findings.append(
                    ModuleFinding(
                        title=f"Transitive Trust: {partner}",
                        description=(
                            f"Trust with {partner} is transitive — trust extends to "
                            "all domains trusted by the partner."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category="AD Reconnaissance",
                        evidence=(
                            f"Trust: {domain} -> {partner}\n"
                            f"Direction: {trust.get('direction_label', 'Unknown')}\n"
                            f"Transitive: True"
                        ),
                        impact="Compromise of any domain in the trust chain can propagate. "
                               "Increases attack surface beyond the direct trust partner.",
                        remediation="Evaluate if transitive trust is required. "
                                    "Consider creating external (non-transitive) trusts instead.",
                        cwe_id="CWE-269",
                        confidence=0.75,
                    )
                )

            # External trust without SID filtering
            if trust.get("direction") in (1, 2) and not trust.get("sid_filtering"):
                # Only flag if not already flagged above (bidirectional)
                if trust.get("direction") != 3:
                    result.findings.append(
                        ModuleFinding(
                            title=f"External Trust Without SID Filtering: {partner}",
                            description=(
                                f"{trust.get('direction_label', '')} trust with {partner} "
                                "lacks SID filtering."
                            ),
                            severity=FindingSeverity.HIGH,
                            category="AD Reconnaissance",
                            evidence=(
                                f"Trust: {domain} -> {partner}\n"
                                f"Direction: {trust.get('direction_label', 'Unknown')}\n"
                                f"SID Filtering: Disabled"
                            ),
                            impact="SID history injection possible across trust boundary.",
                            remediation="Enable SID filtering on this trust relationship.",
                            cwe_id="CWE-269",
                            cvss_score=7.5,
                            confidence=0.8,
                        )
                    )

        if not trusts:
            result.findings.append(
                ModuleFinding(
                    title="No Domain Trusts Found",
                    description=f"No trust relationships discovered for {domain}.",
                    severity=FindingSeverity.INFO,
                    category="AD Reconnaissance",
                    evidence="All trust enumeration methods returned empty",
                    confidence=0.7,
                )
            )

        result.raw_output["trusts"] = trusts
        return result
