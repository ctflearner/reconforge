"""Active Directory authentication reconnaissance modules."""
from __future__ import annotations

import logging
import os
import re
import tempfile
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
# Kerberos User Enumeration
# ===================================================================

class KerberosEnumModule(BaseModule):
    """Enumerate valid AD usernames via Kerberos pre-authentication."""

    @property
    def name(self) -> str:
        return "kerberos_enum"

    @property
    def display_name(self) -> str:
        return "Kerberos User Enumeration"

    @property
    def description(self) -> str:
        return "Enumerate valid domain usernames via Kerberos without authentication"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Authentication"

    @property
    def timeout(self) -> int:
        return 300

    _BUILTIN_USERS = [
        "administrator", "admin", "guest", "krbtgt", "test", "user",
        "backup", "service", "sql", "web", "mail", "ftp", "iis", "http",
        "svc_sql", "svc_web", "svc_backup", "helpdesk", "support",
        "scanner", "monitor", "oracle", "postgres",
    ]

    _WORDLIST_PATHS = [
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-ints-only.txt",
        "/usr/share/wordlists/dirb/others/names.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ]

    async def _find_wordlist(self) -> str | None:
        """Return first available wordlist path, or None."""
        for path in self._WORDLIST_PATHS:
            if os.path.isfile(path):
                return path
        return None

    async def _write_builtin_wordlist(self) -> str:
        """Write built-in usernames to a temp file, return path."""
        fd, path = tempfile.mkstemp(prefix="kerb_users_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(self._BUILTIN_USERS) + "\n")
        except Exception:
            os.close(fd)
            raise
        return path

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        valid_users: list[str] = []
        asrep_candidates: list[str] = []
        temp_wordlist: str | None = None

        # Pick wordlist
        wordlist = await self._find_wordlist()
        if not wordlist:
            wordlist = await self._write_builtin_wordlist()
            temp_wordlist = wordlist

        try:
            # ------------------------------------------------------------------
            # 1. Try kerbrute
            # ------------------------------------------------------------------
            if progress_callback:
                await progress_callback("Running kerbrute user enumeration...")

            kb_out, kb_err, kb_rc = await self._run_command(
                ["kerbrute", "userenum", "--dc", target, "-d", domain, wordlist],
                timeout=240,
            )
            result.raw_output["kerbrute"] = kb_out + kb_err

            if kb_rc != -1 and "Command not found" not in kb_err:
                # Parse kerbrute output: "[+] VALID USERNAME:  user@domain"
                for line in (kb_out + kb_err).splitlines():
                    m = re.search(r"VALID USERNAME:\s+(\S+?)@", line, re.I)
                    if m:
                        uname = m.group(1).strip()
                        if uname.lower() not in [u.lower() for u in valid_users]:
                            valid_users.append(uname)
                    # AS-REP roastable
                    if "no preauth" in line.lower() or "DONT_REQ_PREAUTH" in line:
                        m2 = re.search(r"(\S+?)@", line)
                        if m2:
                            asrep_candidates.append(m2.group(1).strip())
            else:
                # ------------------------------------------------------------------
                # 2. Fallback: nmap krb5-enum-users
                # ------------------------------------------------------------------
                if progress_callback:
                    await progress_callback("Falling back to nmap krb5-enum-users...")

                nmap_out, _, nmap_rc = await self._run_command(
                    [
                        "nmap", "-p", "88",
                        "--script", "krb5-enum-users",
                        "--script-args", f"krb5-enum-users.realm={domain}",
                        "-oX", "-", target,
                    ],
                    timeout=120,
                )
                result.raw_output["nmap_xml"] = nmap_out

                if nmap_rc == 0 and nmap_out.strip():
                    # Parse from script output
                    for m in re.finditer(r"Valid.*?:\s*(\S+?)@", nmap_out + nmap_out, re.I):
                        uname = m.group(1).strip()
                        if uname.lower() not in [u.lower() for u in valid_users]:
                            valid_users.append(uname)
                    # Also parse <elem> tags in XML
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(nmap_out)
                        for script in root.iter("script"):
                            if script.get("id") == "krb5-enum-users":
                                for elem in script.findall(".//elem"):
                                    val = (elem.text or "").strip()
                                    if "@" in val:
                                        uname = val.split("@")[0]
                                        if uname.lower() not in [u.lower() for u in valid_users]:
                                            valid_users.append(uname)
                    except Exception:
                        pass

        finally:
            # Cleanup temp wordlist
            if temp_wordlist and os.path.exists(temp_wordlist):
                try:
                    os.unlink(temp_wordlist)
                except Exception:
                    pass

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        if valid_users:
            result.findings.append(
                ModuleFinding(
                    title=f"Kerberos User Enumeration — {len(valid_users)} Valid Users",
                    description=(
                        f"Enumerated {len(valid_users)} valid domain user(s) via Kerberos "
                        f"pre-authentication on {target}."
                    ),
                    severity=FindingSeverity.INFO,
                    category="AD Authentication",
                    evidence="Valid users:\n" + "\n".join(f"  {u}" for u in valid_users[:50]),
                    raw_data={"valid_users": valid_users},
                    impact="Valid username list enables targeted password spraying, "
                           "AS-REP roasting, and social engineering.",
                    remediation="This is inherent to Kerberos; mitigate with account lockout "
                                "policies, strong passwords, and monitoring for enumeration.",
                    confidence=0.9,
                )
            )

        if asrep_candidates:
            result.findings.append(
                ModuleFinding(
                    title=f"AS-REP Roastable Users Detected — {len(asrep_candidates)}",
                    description=(
                        f"Users with DONT_REQ_PREAUTH found during enumeration: "
                        f"{', '.join(asrep_candidates)}. These should be investigated "
                        "with the AS-REP Roasting module."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="AD Authentication",
                    evidence="AS-REP roastable: " + ", ".join(asrep_candidates),
                    impact="Offline password cracking possible without any credentials.",
                    remediation="Enable Kerberos pre-authentication for these accounts.",
                    cwe_id="CWE-287",
                    cvss_score=7.5,
                    confidence=0.85,
                    validation_hint="Run AS-REP Roasting module for hash extraction.",
                )
            )

        for uname in valid_users:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERSON,
                    value=uname,
                    metadata={
                        "source": "kerberos_enum",
                        "domain": domain,
                        "asrep_roastable": uname in asrep_candidates,
                    },
                )
            )

        result.raw_output["summary"] = {
            "valid_users": len(valid_users),
            "asrep_candidates": len(asrep_candidates),
        }

        return result


# ===================================================================
# AS-REP Roasting
# ===================================================================

class AsrepRoastModule(BaseModule):
    """Extract AS-REP hashes from accounts without Kerberos pre-auth."""

    @property
    def name(self) -> str:
        return "asrep_roast"

    @property
    def display_name(self) -> str:
        return "AS-REP Roasting"

    @property
    def description(self) -> str:
        return "Extract AS-REP hashes from accounts with DONT_REQ_PREAUTH for offline cracking"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Authentication"

    _IMPACKET_PATHS = [
        "impacket-GetNPUsers",
        "/usr/bin/impacket-GetNPUsers",
        "/usr/share/doc/python3-impacket/examples/GetNPUsers.py",
        "GetNPUsers.py",
    ]

    _DEFAULT_USERS = [
        "administrator", "admin", "guest", "krbtgt", "backup",
        "service", "svc_sql", "svc_web", "svc_backup", "test",
        "user", "helpdesk", "support", "scanner", "monitor",
    ]

    async def _find_impacket(self) -> str | None:
        """Locate GetNPUsers binary/script."""
        for path in self._IMPACKET_PATHS:
            out, _, rc = await self._run_command(["which", path], timeout=5)
            if rc == 0 and out.strip():
                return out.strip()
            if os.path.isfile(path):
                return path
        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        hashes: list[dict[str, str]] = []
        vulnerable_users: list[str] = []

        # Build user list from scan_context or defaults
        user_list: list[str] = scan_context.get("users", [])
        if not user_list:
            user_list = self._DEFAULT_USERS

        # Write user file
        fd, user_file = tempfile.mkstemp(prefix="asrep_users_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(user_list) + "\n")
        except Exception:
            os.close(fd)
            result.error = "Failed to create temp user file"
            return result

        try:
            # ------------------------------------------------------------------
            # 1. Try impacket GetNPUsers
            # ------------------------------------------------------------------
            impacket_bin = await self._find_impacket()

            if impacket_bin:
                if progress_callback:
                    await progress_callback("Running GetNPUsers (AS-REP Roasting)...")

                # Determine if it's a Python script or binary
                cmd: list[str]
                if impacket_bin.endswith(".py"):
                    cmd = [
                        "python3", impacket_bin,
                        f"{domain}/",
                        "-dc-ip", target,
                        "-no-pass",
                        "-usersfile", user_file,
                        "-format", "hashcat",
                    ]
                else:
                    cmd = [
                        impacket_bin,
                        f"{domain}/",
                        "-dc-ip", target,
                        "-no-pass",
                        "-usersfile", user_file,
                        "-format", "hashcat",
                    ]

                out, err, rc = await self._run_command(cmd, timeout=120)
                result.raw_output["getnpusers"] = out + err

                # Parse hashes: $krb5asrep$23$user@DOMAIN:...
                for line in (out + err).splitlines():
                    line = line.strip()
                    if line.startswith("$krb5asrep$"):
                        # Extract username from hash
                        m = re.match(r"\$krb5asrep\$\d+\$([^@:]+)", line)
                        username = m.group(1) if m else "unknown"
                        hashes.append({"user": username, "hash": line})
                        if username not in vulnerable_users:
                            vulnerable_users.append(username)
                    elif "DONT_REQ_PREAUTH" in line or "UF_DONT_REQUIRE_PREAUTH" in line:
                        m = re.search(r"(\S+)\s+.*DONT_REQ_PREAUTH", line)
                        if m:
                            uname = m.group(1)
                            if uname not in vulnerable_users:
                                vulnerable_users.append(uname)

            else:
                # ------------------------------------------------------------------
                # 2. Fallback: nmap
                # ------------------------------------------------------------------
                if progress_callback:
                    await progress_callback("impacket not found, trying nmap fallback...")

                nmap_out, _, nmap_rc = await self._run_command(
                    [
                        "nmap", "-p", "88",
                        "--script", "krb5-enum-users",
                        "--script-args", f"krb5-enum-users.realm={domain}",
                        "-oX", "-", target,
                    ],
                    timeout=120,
                )
                result.raw_output["nmap_xml"] = nmap_out
                result.raw_output["note"] = (
                    "impacket-GetNPUsers not found. nmap krb5-enum-users cannot "
                    "extract AS-REP hashes directly. Install impacket for full AS-REP roasting."
                )

                if nmap_rc == 0:
                    # nmap can sometimes identify users, but not extract hashes
                    for m in re.finditer(r"Valid.*?:\s*(\S+?)@", nmap_out, re.I):
                        uname = m.group(1).strip()
                        if uname not in vulnerable_users:
                            vulnerable_users.append(uname)

        finally:
            if os.path.exists(user_file):
                try:
                    os.unlink(user_file)
                except Exception:
                    pass

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        for h in hashes:
            result.findings.append(
                ModuleFinding(
                    title=f"AS-REP Roastable: {h['user']}",
                    description=(
                        f"Account '{h['user']}' has Kerberos pre-authentication disabled. "
                        "AS-REP hash extracted for offline cracking."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="AD Authentication",
                    evidence=f"Hash: {h['hash'][:80]}...",
                    raw_data={"hash": h["hash"]},
                    impact="Offline password cracking possible. If password is weak, "
                           "attacker gains domain credentials without any prior access.",
                    remediation="Enable Kerberos pre-authentication: "
                                "Set-ADAccountControl -Identity {user} -DoesNotRequirePreAuth $false",
                    cwe_id="CWE-287",
                    cvss_score=7.5,
                    confidence=0.95,
                    validation_hint=f"hashcat -m 18200 hash.txt wordlist.txt",
                )
            )

        if vulnerable_users and not hashes:
            result.findings.append(
                ModuleFinding(
                    title=f"Potential AS-REP Roastable Users — {len(vulnerable_users)}",
                    description=(
                        "Users identified that may have pre-authentication disabled, "
                        "but hash extraction requires impacket."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="AD Authentication",
                    evidence="Users: " + ", ".join(vulnerable_users),
                    impact="Offline cracking possible if hashes can be extracted.",
                    remediation="Install impacket and rerun. Enable pre-auth for these accounts.",
                    cwe_id="CWE-287",
                    confidence=0.6,
                )
            )

        if not hashes and not vulnerable_users:
            result.findings.append(
                ModuleFinding(
                    title="No AS-REP Roastable Accounts Found",
                    description="No accounts with DONT_REQ_PREAUTH were identified.",
                    severity=FindingSeverity.INFO,
                    category="AD Authentication",
                    evidence="GetNPUsers returned no hashes for tested usernames",
                    confidence=0.7,
                )
            )

        for uname in vulnerable_users:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERSON,
                    value=uname,
                    metadata={
                        "asrep_roastable": True,
                        "domain": domain,
                        "hash_extracted": uname in [h["user"] for h in hashes],
                    },
                )
            )

        result.raw_output["summary"] = {
            "hashes_extracted": len(hashes),
            "vulnerable_users": len(vulnerable_users),
        }

        return result


# ===================================================================
# Password Policy Audit
# ===================================================================

class PasswordPolicyModule(BaseModule):
    """Audit AD domain password and lockout policies."""

    @property
    def name(self) -> str:
        return "password_policy"

    @property
    def display_name(self) -> str:
        return "Password Policy Audit"

    @property
    def description(self) -> str:
        return "Audit AD password length, complexity, lockout, and age policies"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Authentication"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        policy: dict[str, Any] = {}
        policy_source = ""

        # ------------------------------------------------------------------
        # 1. Try LDAP query
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Querying password policy via LDAP...")

        try:
            from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE

            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            server = Server(target, get_info=ALL, connect_timeout=15)
            conn = Connection(server, authentication=ANONYMOUS, read_only=True)

            if conn.bind():
                conn.search(
                    base_dn,
                    "(objectClass=domain)",
                    search_scope=SUBTREE,
                    attributes=[
                        "minPwdLength", "maxPwdAge", "minPwdAge",
                        "pwdHistoryLength", "lockoutThreshold",
                        "lockoutDuration", "lockoutObservationWindow",
                        "pwdProperties",
                    ],
                    size_limit=1,
                )
                if conn.entries:
                    entry = conn.entries[0]

                    def _int_attr(name: str) -> int | None:
                        val = getattr(entry, name, None)
                        if val and val.value is not None:
                            try:
                                return int(val.value)
                            except (ValueError, TypeError):
                                return None
                        return None

                    policy["minPwdLength"] = _int_attr("minPwdLength")
                    policy["pwdHistoryLength"] = _int_attr("pwdHistoryLength")
                    policy["lockoutThreshold"] = _int_attr("lockoutThreshold")
                    policy["pwdProperties"] = _int_attr("pwdProperties")

                    # AD stores time values as negative 100-nanosecond intervals
                    for time_attr in ("maxPwdAge", "minPwdAge", "lockoutDuration", "lockoutObservationWindow"):
                        raw = _int_attr(time_attr)
                        if raw is not None and raw != 0:
                            # Convert to minutes (absolute value / 600000000)
                            minutes = abs(raw) / 600_000_000
                            policy[time_attr] = round(minutes)
                            policy[f"{time_attr}_days"] = round(minutes / 1440, 1)
                        else:
                            policy[time_attr] = raw

                    policy_source = "ldap"
                conn.unbind()
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("LDAP password policy error: %s", exc)

        # ------------------------------------------------------------------
        # 2. Fallback: rpcclient
        # ------------------------------------------------------------------
        if not policy_source:
            if progress_callback:
                await progress_callback("Trying rpcclient for password policy...")

            rpc_out, _, rpc_rc = await self._run_command(
                ["rpcclient", "-U", "", "-N", target, "-c", "getdompwinfo"],
                timeout=30,
            )
            result.raw_output["rpcclient_pwinfo"] = rpc_out

            if rpc_rc == 0 and rpc_out.strip() and "NT_STATUS" not in rpc_out:
                policy_source = "rpcclient"
                # Parse: "min_password_length: 7" etc.
                for line in rpc_out.splitlines():
                    m = re.match(r"(\w+):\s*(.+)", line.strip())
                    if m:
                        key, val = m.group(1), m.group(2).strip()
                        if "password_length" in key:
                            try:
                                policy["minPwdLength"] = int(val)
                            except ValueError:
                                pass
                        elif "password_properties" in key:
                            # Parse hex value
                            try:
                                policy["pwdProperties"] = int(val, 0)
                            except ValueError:
                                pass

        # ------------------------------------------------------------------
        # 3. Fallback: crackmapexec
        # ------------------------------------------------------------------
        if not policy_source:
            if progress_callback:
                await progress_callback("Trying crackmapexec for password policy...")

            cme_out, cme_err, cme_rc = await self._run_command(
                ["crackmapexec", "smb", target, "--pass-pol"],
                timeout=30,
            )
            result.raw_output["crackmapexec"] = cme_out + cme_err

            if cme_rc == 0 and (cme_out + cme_err).strip():
                policy_source = "crackmapexec"
                combined = cme_out + cme_err
                ml = re.search(r"Minimum password length:\s*(\d+)", combined)
                if ml:
                    policy["minPwdLength"] = int(ml.group(1))
                lt = re.search(r"Account Lockout Threshold:\s*(\d+)", combined)
                if lt:
                    policy["lockoutThreshold"] = int(lt.group(1))
                ph = re.search(r"Password History Length:\s*(\d+)", combined)
                if ph:
                    policy["pwdHistoryLength"] = int(ph.group(1))
                ma = re.search(r"Maximum password age.*?(\d+)\s*day", combined, re.I)
                if ma:
                    policy["maxPwdAge_days"] = float(ma.group(1))
                if "DOMAIN_PASSWORD_COMPLEX" in combined:
                    policy["complexity"] = True
                elif "No complexity" in combined.lower():
                    policy["complexity"] = False

        # ------------------------------------------------------------------
        # 4. Fallback: enum4linux
        # ------------------------------------------------------------------
        if not policy_source:
            if progress_callback:
                await progress_callback("Trying enum4linux...")

            e4l_out, _, e4l_rc = await self._run_command(
                ["enum4linux", "-P", target],
                timeout=60,
            )
            result.raw_output["enum4linux"] = e4l_out

            if e4l_rc == 0 and e4l_out.strip():
                policy_source = "enum4linux"
                ml = re.search(r"Minimum password length:\s*(\d+)", e4l_out)
                if ml:
                    policy["minPwdLength"] = int(ml.group(1))
                lt = re.search(r"Account Lockout Threshold:\s*(\d+)", e4l_out)
                if lt:
                    policy["lockoutThreshold"] = int(lt.group(1))

        # ------------------------------------------------------------------
        # Evaluate policy & generate findings
        # ------------------------------------------------------------------

        if not policy_source:
            result.error = "Could not retrieve password policy — all methods failed"
            return result

        result.raw_output["policy"] = policy
        result.raw_output["source"] = policy_source

        min_len = policy.get("minPwdLength")
        lockout = policy.get("lockoutThreshold")
        history = policy.get("pwdHistoryLength")
        max_age_days = policy.get("maxPwdAge_days")
        pwd_props = policy.get("pwdProperties")

        # Complexity from pwdProperties bitmask (bit 0 = complexity required)
        complexity = policy.get("complexity")
        if complexity is None and pwd_props is not None:
            complexity = bool(pwd_props & 0x1)
            policy["complexity"] = complexity

        # --- Min length ---
        if min_len is not None:
            if min_len < 8:
                result.findings.append(
                    ModuleFinding(
                        title=f"Weak Minimum Password Length: {min_len}",
                        description=f"Domain requires only {min_len} character minimum password.",
                        severity=FindingSeverity.MEDIUM,
                        category="AD Authentication",
                        evidence=f"minPwdLength: {min_len} (source: {policy_source})",
                        impact="Short passwords are trivially crackable. "
                               "Passwords under 8 characters fall to brute-force in hours.",
                        remediation="Set minimum password length to at least 12 characters "
                                    "via Default Domain Policy GPO.",
                        cwe_id="CWE-521",
                        cvss_score=5.3,
                        confidence=0.9,
                    )
                )
            elif min_len < 12:
                result.findings.append(
                    ModuleFinding(
                        title=f"Minimum Password Length Could Be Stronger: {min_len}",
                        description=f"Domain requires {min_len} character minimum. "
                                    "NIST recommends 12+ for privileged accounts.",
                        severity=FindingSeverity.LOW,
                        category="AD Authentication",
                        evidence=f"minPwdLength: {min_len}",
                        impact="Moderate-length passwords are crackable with GPU resources.",
                        remediation="Increase minimum length to 12+. Consider passphrases.",
                        cwe_id="CWE-521",
                        confidence=0.8,
                    )
                )

        # --- Complexity ---
        if complexity is False:
            result.findings.append(
                ModuleFinding(
                    title="Password Complexity Not Required",
                    description="Domain does not enforce password complexity requirements.",
                    severity=FindingSeverity.MEDIUM,
                    category="AD Authentication",
                    evidence=f"pwdProperties: {pwd_props} — complexity bit not set",
                    impact="Users can set simple passwords (all lowercase, dictionary words).",
                    remediation="Enable 'Password must meet complexity requirements' in GPO.",
                    cwe_id="CWE-521",
                    cvss_score=5.3,
                    confidence=0.85,
                )
            )

        # --- Lockout ---
        if lockout is not None:
            if lockout == 0:
                result.findings.append(
                    ModuleFinding(
                        title="No Account Lockout Policy",
                        description="Account lockout threshold is 0 — accounts never lock out.",
                        severity=FindingSeverity.HIGH,
                        category="AD Authentication",
                        evidence=f"lockoutThreshold: 0 (source: {policy_source})",
                        impact="Unlimited password guessing attacks. Brute-force and spray "
                               "attacks face no lockout barrier.",
                        remediation="Set lockout threshold to 5-10 attempts. Configure "
                                    "lockout duration of 30+ minutes.",
                        cwe_id="CWE-307",
                        cvss_score=7.5,
                        confidence=0.95,
                    )
                )
            elif lockout < 5:
                lockout_dur = policy.get("lockoutDuration")
                if lockout_dur is not None and lockout_dur < 30:
                    result.findings.append(
                        ModuleFinding(
                            title=f"Low Lockout Threshold ({lockout}) with Short Duration ({lockout_dur}min)",
                            description="Lockout policy has low threshold with short duration.",
                            severity=FindingSeverity.INFO,
                            category="AD Authentication",
                            evidence=f"Threshold: {lockout}, Duration: {lockout_dur} min",
                            impact="Short lockout allows slow spray attacks to succeed.",
                            remediation="Increase lockout duration to 30+ minutes.",
                            confidence=0.75,
                        )
                    )

        # --- Password age ---
        if max_age_days is not None and max_age_days > 365:
            result.findings.append(
                ModuleFinding(
                    title=f"Long Maximum Password Age: {max_age_days} Days",
                    description=f"Passwords can be used for {max_age_days} days without rotation.",
                    severity=FindingSeverity.LOW,
                    category="AD Authentication",
                    evidence=f"maxPwdAge: {max_age_days} days",
                    impact="Compromised passwords remain valid for extended periods.",
                    remediation="Set maximum password age to 90-180 days for standard accounts. "
                                "Consider shorter rotation for privileged accounts.",
                    confidence=0.8,
                )
            )

        # --- Password history ---
        if history is not None and history < 5:
            result.findings.append(
                ModuleFinding(
                    title=f"Weak Password History: {history}",
                    description=f"Password history enforces only {history} previous password(s).",
                    severity=FindingSeverity.LOW,
                    category="AD Authentication",
                    evidence=f"pwdHistoryLength: {history}",
                    impact="Users can cycle through a small set of passwords and reuse them.",
                    remediation="Set password history to at least 12-24 remembered passwords.",
                    confidence=0.8,
                )
            )

        # --- Summary finding ---
        policy_summary = []
        if min_len is not None:
            policy_summary.append(f"Min length: {min_len}")
        if complexity is not None:
            policy_summary.append(f"Complexity: {'Enabled' if complexity else 'Disabled'}")
        if lockout is not None:
            policy_summary.append(f"Lockout threshold: {lockout}")
        if max_age_days is not None:
            policy_summary.append(f"Max age: {max_age_days} days")
        if history is not None:
            policy_summary.append(f"History: {history}")

        result.findings.append(
            ModuleFinding(
                title=f"Password Policy Summary — {domain}",
                description="Domain password policy retrieved and evaluated.",
                severity=FindingSeverity.INFO,
                category="AD Authentication",
                evidence="\n".join(policy_summary),
                raw_data=policy,
                confidence=0.9,
            )
        )

        return result


# ===================================================================
# AD Certificate Services Audit
# ===================================================================

class AdcsCheckModule(BaseModule):
    """Audit AD Certificate Services for ESC vulnerabilities."""

    @property
    def name(self) -> str:
        return "adcs_check"

    @property
    def display_name(self) -> str:
        return "AD Certificate Services Audit"

    @property
    def description(self) -> str:
        return "Audit ADCS for ESC1-ESC8 privilege escalation vulnerabilities"

    @property
    def target_types(self) -> list[str]:
        return ["active_directory"]

    @property
    def category(self) -> str:
        return "AD Authentication"

    @property
    def timeout(self) -> int:
        return 300

    _CERTIPY_PATHS = ["certipy", "certipy-ad", "/usr/bin/certipy", "/usr/local/bin/certipy"]

    _ESC_DESCRIPTIONS = {
        "ESC1": (
            "Template allows enrollee to specify a Subject Alternative Name (SAN) "
            "and has Client Authentication EKU with low-privilege enrollment rights.",
            FindingSeverity.HIGH,
            8.0,
        ),
        "ESC2": (
            "Template has Any Purpose EKU or SubCA certificate type, "
            "allowing enrollment for any purpose.",
            FindingSeverity.HIGH,
            7.5,
        ),
        "ESC3": (
            "Template has Certificate Request Agent EKU allowing enrollment "
            "on behalf of other users via a second template.",
            FindingSeverity.HIGH,
            7.5,
        ),
        "ESC4": (
            "Template has overly permissive ACL (GenericAll, WriteDACL, or WriteOwner) "
            "allowing low-privileged users to modify the template.",
            FindingSeverity.HIGH,
            7.5,
        ),
        "ESC6": (
            "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing any "
            "enrollee to specify arbitrary SANs in certificate requests.",
            FindingSeverity.HIGH,
            8.0,
        ),
        "ESC8": (
            "AD CS web enrollment endpoint is accessible via HTTP, enabling "
            "NTLM relay attacks to enroll certificates as the relayed user.",
            FindingSeverity.HIGH,
            8.0,
        ),
    }

    async def _find_certipy(self) -> str | None:
        """Locate certipy binary."""
        for path in self._CERTIPY_PATHS:
            out, _, rc = await self._run_command(["which", path], timeout=5)
            if rc == 0 and out.strip():
                return out.strip()
        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        domain = scan_context.get("domain", target)
        esc_findings: list[dict[str, Any]] = []
        cas: list[str] = []
        vulnerable_templates: list[dict[str, str]] = []

        # ------------------------------------------------------------------
        # 1. Try certipy
        # ------------------------------------------------------------------
        certipy_bin = await self._find_certipy()

        if certipy_bin:
            if progress_callback:
                await progress_callback("Running certipy find (ADCS audit)...")

            out, err, rc = await self._run_command(
                [certipy_bin, "find", "-u", "", "-p", "", "-dc-ip", target,
                 "-vulnerable", "-stdout"],
                timeout=180,
            )
            result.raw_output["certipy"] = out + err

            if rc == 0 or out.strip():
                combined = out + err

                # Parse CA names
                for m in re.finditer(r"CA Name\s*:\s*(.+)", combined):
                    ca_name = m.group(1).strip()
                    if ca_name not in cas:
                        cas.append(ca_name)

                # Parse ESC vulnerabilities
                # Certipy groups findings by template name and lists ESC types
                current_template = ""
                for line in combined.splitlines():
                    tmpl_match = re.match(r"\s*Template Name\s*:\s*(.+)", line)
                    if tmpl_match:
                        current_template = tmpl_match.group(1).strip()

                    for esc_id in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC8"):
                        if esc_id in line and ("Vulnerab" in line or "Enabled" in line or esc_id in line):
                            # Avoid duplicate
                            key = f"{current_template}:{esc_id}"
                            if not any(e.get("key") == key for e in esc_findings):
                                esc_findings.append({
                                    "key": key,
                                    "esc": esc_id,
                                    "template": current_template,
                                    "raw": line.strip(),
                                })
                                if current_template:
                                    vulnerable_templates.append({
                                        "template": current_template,
                                        "esc": esc_id,
                                    })

                # Check for EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)
                if "EDITF_ATTRIBUTESUBJECTALTNAME2" in combined:
                    if not any(e["esc"] == "ESC6" for e in esc_findings):
                        esc_findings.append({
                            "key": ":ESC6",
                            "esc": "ESC6",
                            "template": "",
                            "raw": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag set",
                        })

                # Check for HTTP enrollment (ESC8)
                if re.search(r"Web Enrollment\s*:\s*Enabled", combined, re.I):
                    if not any(e["esc"] == "ESC8" for e in esc_findings):
                        esc_findings.append({
                            "key": ":ESC8",
                            "esc": "ESC8",
                            "template": "",
                            "raw": "HTTP web enrollment endpoint enabled",
                        })

        # ------------------------------------------------------------------
        # 2. Fallback: LDAP query for enrollment services
        # ------------------------------------------------------------------
        if not cas:
            if progress_callback:
                await progress_callback("Querying LDAP for ADCS enrollment services...")

            try:
                from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE

                base_dn = ",".join(f"DC={p}" for p in domain.split("."))
                config_dn = f"CN=Configuration,{base_dn}"

                server = Server(target, get_info=ALL, connect_timeout=15)
                conn = Connection(server, authentication=ANONYMOUS, read_only=True)

                if conn.bind():
                    # Find CAs
                    conn.search(
                        config_dn,
                        "(objectClass=pKIEnrollmentService)",
                        search_scope=SUBTREE,
                        attributes=["cn", "dNSHostName", "certificateTemplates"],
                        size_limit=50,
                    )
                    for entry in conn.entries:
                        ca_name = str(entry.cn) if hasattr(entry, "cn") and entry.cn else ""
                        if ca_name and ca_name not in cas:
                            cas.append(ca_name)
                            dns_host = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") and entry.dNSHostName else ""
                            templates = [str(t) for t in entry.certificateTemplates] if hasattr(entry, "certificateTemplates") and entry.certificateTemplates else []
                            result.raw_output[f"ca_{ca_name}"] = {
                                "dns_host": dns_host,
                                "templates": templates,
                            }

                    # Query certificate templates for dangerous settings
                    conn.search(
                        config_dn,
                        "(objectClass=pKICertificateTemplate)",
                        search_scope=SUBTREE,
                        attributes=[
                            "cn", "msPKI-Certificate-Name-Flag",
                            "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag",
                            "nTSecurityDescriptor",
                        ],
                        size_limit=200,
                    )
                    for entry in conn.entries:
                        tmpl_name = str(entry.cn) if hasattr(entry, "cn") and entry.cn else ""
                        name_flag = 0
                        try:
                            nf_attr = getattr(entry, "msPKI-Certificate-Name-Flag", None)
                            if nf_attr and nf_attr.value is not None:
                                name_flag = int(nf_attr.value)
                        except (ValueError, TypeError):
                            pass

                        ekus = []
                        try:
                            eku_attr = getattr(entry, "pKIExtendedKeyUsage", None)
                            if eku_attr and eku_attr.values:
                                ekus = [str(e) for e in eku_attr.values]
                        except Exception:
                            pass

                        # ESC1: ENROLLEE_SUPPLIES_SUBJECT (0x1) + Client Auth EKU
                        client_auth_eku = "1.3.6.1.5.5.7.3.2"
                        any_purpose_eku = "2.5.29.37.0"

                        if (name_flag & 0x1) and client_auth_eku in ekus:
                            esc_findings.append({
                                "key": f"{tmpl_name}:ESC1",
                                "esc": "ESC1",
                                "template": tmpl_name,
                                "raw": f"ENROLLEE_SUPPLIES_SUBJECT + Client Auth in {tmpl_name}",
                            })
                            vulnerable_templates.append({
                                "template": tmpl_name,
                                "esc": "ESC1",
                            })

                        # ESC2: Any Purpose EKU
                        if any_purpose_eku in ekus or not ekus:
                            esc_findings.append({
                                "key": f"{tmpl_name}:ESC2",
                                "esc": "ESC2",
                                "template": tmpl_name,
                                "raw": f"Any Purpose / no EKU restriction in {tmpl_name}",
                            })
                            vulnerable_templates.append({
                                "template": tmpl_name,
                                "esc": "ESC2",
                            })

                    conn.unbind()
            except ImportError:
                pass
            except Exception as exc:
                logger.debug("LDAP ADCS query error: %s", exc)

        # ------------------------------------------------------------------
        # 3. Check for HTTP enrollment (ESC8) via HTTP
        # ------------------------------------------------------------------
        if progress_callback:
            await progress_callback("Checking for ADCS HTTP enrollment (ESC8)...")

        for scheme in ("http", "https"):
            url = f"{scheme}://{target}/certsrv/"
            resp = await self._http_get(url, timeout=10)
            if resp.get("status") in (200, 401, 403):
                if not any(e["esc"] == "ESC8" for e in esc_findings):
                    esc_findings.append({
                        "key": ":ESC8",
                        "esc": "ESC8",
                        "template": "",
                        "raw": f"HTTP enrollment at {url} (status {resp['status']})",
                    })
                break

        # ------------------------------------------------------------------
        # Findings
        # ------------------------------------------------------------------

        for esc in esc_findings:
            esc_id = esc["esc"]
            template = esc.get("template", "")
            desc_tuple = self._ESC_DESCRIPTIONS.get(esc_id)

            if desc_tuple:
                desc_text, severity, cvss = desc_tuple
            else:
                desc_text = f"{esc_id} vulnerability detected."
                severity = FindingSeverity.HIGH
                cvss = 7.5

            # ESC1 with domain admin path = CRITICAL
            if esc_id == "ESC1":
                severity = FindingSeverity.CRITICAL
                cvss = 9.0

            title = f"ADCS {esc_id}"
            if template:
                title += f" — Template: {template}"

            result.findings.append(
                ModuleFinding(
                    title=title,
                    description=desc_text,
                    severity=severity,
                    category="AD Authentication",
                    evidence=esc.get("raw", ""),
                    raw_data=esc,
                    impact="Privilege escalation to Domain Admin via certificate abuse. "
                           f"{esc_id} allows forging certificates or impersonating users.",
                    remediation=(
                        f"Remediate {esc_id}: "
                        + {
                            "ESC1": "Remove ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment permissions.",
                            "ESC2": "Remove Any Purpose EKU. Set explicit EKU restrictions.",
                            "ESC3": "Restrict Certificate Request Agent enrollment. Require CA manager approval.",
                            "ESC4": "Fix template ACLs. Remove GenericAll/WriteDACL/WriteOwner for low-priv users.",
                            "ESC6": "Disable EDITF_ATTRIBUTESUBJECTALTNAME2: certutil -config 'CA' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                            "ESC8": "Disable HTTP enrollment or require HTTPS with EPA. Apply KB5005413.",
                        }.get(esc_id, "Review and remediate ADCS configuration.")
                    ),
                    cwe_id="CWE-295",
                    cvss_score=cvss,
                    confidence=0.8,
                )
            )

            if template:
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.PERMISSION,
                        value=f"cert_template:{template}",
                        metadata={
                            "esc_type": esc_id,
                            "vulnerable": True,
                            "domain": domain,
                        },
                    )
                )

        # CA assets
        for ca in cas:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"adcs://{target}/{ca}",
                    metadata={
                        "ca_name": ca,
                        "domain": domain,
                        "protocol": "adcs",
                    },
                )
            )

        if not esc_findings and not cas:
            result.findings.append(
                ModuleFinding(
                    title="No ADCS Found or Not Accessible",
                    description=f"No AD Certificate Services detected on {target}.",
                    severity=FindingSeverity.INFO,
                    category="AD Authentication",
                    evidence="certipy and LDAP queries returned no enrollment services",
                    confidence=0.6,
                )
            )
        elif not esc_findings and cas:
            result.findings.append(
                ModuleFinding(
                    title=f"ADCS Found — No ESC Vulnerabilities Detected",
                    description=f"CA(s) found ({', '.join(cas)}) but no common ESC "
                                "vulnerabilities were identified.",
                    severity=FindingSeverity.INFO,
                    category="AD Authentication",
                    evidence=f"CAs: {', '.join(cas)}",
                    confidence=0.7,
                )
            )

        result.raw_output["summary"] = {
            "cas": cas,
            "esc_findings": len(esc_findings),
            "vulnerable_templates": vulnerable_templates,
        }

        return result
