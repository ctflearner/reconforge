"""Thick-client security analysis modules — CVE lookup, unsafe APIs, crypto, privileges, updates."""
from __future__ import annotations

import json
import logging
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

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

def _detect_binary_type(file_path: str) -> str:
    """Return 'pe', 'jar', 'dotnet', or 'unknown' based on magic bytes / extension."""
    ext = Path(file_path).suffix.lower()
    if ext in (".jar", ".war", ".ear"):
        return "jar"
    if ext in (".dll", ".exe", ".sys"):
        try:
            with open(file_path, "rb") as f:
                magic = f.read(2)
            if magic == b"MZ":
                return "pe"
        except OSError:
            pass
        return "pe"
    if ext in (".msi",):
        return "pe"
    return "unknown"


def _decompiled_root(target: str) -> Path:
    """Return expected decompiled output directory for a binary."""
    stem = Path(target).stem
    return Path(settings.decompiled_dir) / stem


def _walk_source_files(root: Path, extensions: tuple[str, ...] = (".cs", ".java", ".kt", ".vb", ".js", ".py", ".xml", ".config", ".json", ".properties", ".yml", ".yaml")) -> list[Path]:
    """Yield all source-like files under *root*."""
    results: list[Path] = []
    if not root.exists():
        return results
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.lower().endswith(e) for e in extensions):
                results.append(Path(dirpath) / fn)
    return results


def _search_files_for_patterns(
    files: list[Path],
    patterns: list[tuple[str, re.Pattern[str], str, str]],
    max_hits_per_pattern: int = 50,
) -> list[dict[str, Any]]:
    """Search *files* for compiled regex patterns.

    Each entry in *patterns* is (label, compiled_re, risk_description, remediation).
    Returns list of hit dicts with file, line, snippet, label, description, remediation.
    """
    hits: list[dict[str, Any]] = []
    hit_counts: dict[str, int] = {}
    for fpath in files:
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for label, pat, desc, remed in patterns:
                if hit_counts.get(label, 0) >= max_hits_per_pattern:
                    continue
                m = pat.search(line)
                if m:
                    hit_counts[label] = hit_counts.get(label, 0) + 1
                    hits.append({
                        "file": str(fpath),
                        "line": line_no,
                        "snippet": line.strip()[:300],
                        "match": m.group(0)[:200],
                        "label": label,
                        "description": desc,
                        "remediation": remed,
                    })
    return hits


# ===================================================================
# 1. DependencyCveModule
# ===================================================================

class DependencyCveModule(BaseModule):
    """List bundled DLLs/JARs, extract versions, query OSV for known CVEs."""

    @property
    def name(self) -> str:
        return "thick_dependency_cve"

    @property
    def display_name(self) -> str:
        return "Dependency CVE Check"

    @property
    def description(self) -> str:
        return "List imported/bundled libraries and query OSV for known CVEs"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "security_analysis"

    @property
    def timeout(self) -> int:
        return 180

    # ---- internals ----

    async def _list_pe_imports(self, target: str) -> list[dict[str, Any]]:
        """Use pefile to enumerate imported DLLs and their metadata."""
        libs: list[dict[str, Any]] = []
        try:
            import pefile
            pe = pefile.PE(target, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="replace")
                    libs.append({"name": dll_name, "version": None, "type": "pe_import"})
            pe.close()
        except ImportError:
            logger.debug("pefile not installed — falling back to strings")
            stdout, _, rc = await self._run_command(["strings", target], timeout=30)
            if rc == 0:
                for m in re.finditer(r'([A-Za-z0-9_]+\.dll)', stdout, re.I):
                    libs.append({"name": m.group(1), "version": None, "type": "strings"})
        except Exception as exc:
            logger.warning("pefile parse error: %s", exc)
        return libs

    async def _list_pe_bundled(self, target: str) -> list[dict[str, Any]]:
        """Find .dll files next to the binary."""
        libs: list[dict[str, Any]] = []
        parent = Path(target).parent
        if parent.exists():
            for f in parent.glob("*.dll"):
                ver = await self._extract_pe_version(str(f))
                libs.append({"name": f.name, "version": ver, "type": "bundled"})
        return libs

    async def _extract_pe_version(self, dll_path: str) -> str | None:
        try:
            import pefile
            pe = pefile.PE(dll_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            if hasattr(pe, "VS_FIXEDFILEINFO"):
                info = pe.VS_FIXEDFILEINFO[0]
                ver = "{}.{}.{}.{}".format(
                    (info.FileVersionMS >> 16) & 0xFFFF,
                    info.FileVersionMS & 0xFFFF,
                    (info.FileVersionLS >> 16) & 0xFFFF,
                    info.FileVersionLS & 0xFFFF,
                )
                pe.close()
                return ver
            pe.close()
        except Exception:
            pass
        return None

    async def _list_jar_entries(self, target: str) -> list[dict[str, Any]]:
        """List JARs inside a JAR/WAR or in the same directory."""
        libs: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(target, "r") as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".jar"):
                        # Try to extract version from filename like lib-1.2.3.jar
                        base = Path(name).stem
                        ver_m = re.search(r'[-_](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', base)
                        ver = ver_m.group(1) if ver_m else None
                        libs.append({"name": Path(name).name, "version": ver, "type": "embedded_jar"})
                # Parse MANIFEST.MF for Bundle-Version
                if "META-INF/MANIFEST.MF" in zf.namelist():
                    mf = zf.read("META-INF/MANIFEST.MF").decode(errors="replace")
                    bv = re.search(r"Bundle-Version:\s*(\S+)", mf)
                    if bv:
                        libs.append({"name": Path(target).name, "version": bv.group(1), "type": "self"})
        except Exception as exc:
            logger.debug("JAR listing error: %s", exc)

        # Also find .jar files next to target
        parent = Path(target).parent
        if parent.exists():
            for f in parent.glob("*.jar"):
                if str(f) == target:
                    continue
                base = f.stem
                ver_m = re.search(r'[-_](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', base)
                ver = ver_m.group(1) if ver_m else None
                libs.append({"name": f.name, "version": ver, "type": "bundled"})

        return libs

    async def _query_osv(self, package_name: str, version: str | None, ecosystem: str) -> list[dict[str, Any]]:
        """Query OSV API for vulnerabilities. Returns list of vuln dicts."""
        payload: dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        resp = await self._http_post(
            "https://api.osv.dev/v1/query",
            json_data=payload,
            timeout=15,
        )

        if resp.get("status") != 200:
            return []

        try:
            data = json.loads(resp["body"])
        except (json.JSONDecodeError, KeyError):
            return []

        return data.get("vulns", [])

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        btype = _detect_binary_type(target)

        if progress_callback:
            await progress_callback("Enumerating dependencies...")

        all_libs: list[dict[str, Any]] = []

        if btype == "pe":
            all_libs.extend(await self._list_pe_imports(target))
            all_libs.extend(await self._list_pe_bundled(target))
        elif btype == "jar":
            all_libs.extend(await self._list_jar_entries(target))
        else:
            # Try both
            all_libs.extend(await self._list_pe_imports(target))
            all_libs.extend(await self._list_jar_entries(target))

        # Deduplicate by name
        seen: set[str] = set()
        unique_libs: list[dict[str, Any]] = []
        for lib in all_libs:
            key = lib["name"].lower()
            if key not in seen:
                seen.add(key)
                unique_libs.append(lib)

        result.raw_output["libraries"] = unique_libs
        result.raw_output["total_libraries"] = len(unique_libs)

        for lib in unique_libs:
            result.assets.append(ModuleAsset(
                asset_type=AssetType.COMPONENT,
                value=lib["name"],
                metadata={"version": lib.get("version"), "source": lib.get("type")},
            ))

        # Query OSV for versioned libraries
        if progress_callback:
            await progress_callback("Querying OSV for known CVEs...")

        total_cves = 0
        versioned = [l for l in unique_libs if l.get("version")]
        for lib in versioned[:30]:  # cap queries
            # Derive ecosystem
            name_lower = lib["name"].lower()
            if name_lower.endswith(".jar"):
                ecosystem = "Maven"
                pkg_name = lib["name"].replace(".jar", "")
                # Strip version suffix from name for Maven lookup
                pkg_name = re.sub(r'[-_]\d+\..*$', '', pkg_name)
            elif name_lower.endswith(".dll"):
                ecosystem = "NuGet"
                pkg_name = lib["name"].replace(".dll", "")
            else:
                ecosystem = "NuGet"
                pkg_name = lib["name"]

            vulns = await self._query_osv(pkg_name, lib["version"], ecosystem)

            for vuln in vulns:
                total_cves += 1
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary", vuln.get("details", "No description")[:500])
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

                # Determine severity from database_specific or severity field
                sev_str = "MEDIUM"
                if vuln.get("database_specific", {}).get("severity"):
                    sev_str = vuln["database_specific"]["severity"].upper()
                elif vuln.get("severity"):
                    for s in vuln["severity"]:
                        if s.get("type") == "CVSS_V3":
                            score_m = re.search(r'CVSS:3\.\d+/AV:\w/.*', s.get("score", ""))
                            # Parse base score from vector — rough heuristic
                            sev_str = "MEDIUM"

                severity_map = {
                    "CRITICAL": FindingSeverity.CRITICAL,
                    "HIGH": FindingSeverity.HIGH,
                    "MODERATE": FindingSeverity.MEDIUM,
                    "MEDIUM": FindingSeverity.MEDIUM,
                    "LOW": FindingSeverity.LOW,
                }
                severity = severity_map.get(sev_str, FindingSeverity.MEDIUM)

                result.findings.append(ModuleFinding(
                    title=f"Known CVE in {lib['name']}: {cve_id}",
                    description=f"{summary[:400]}",
                    severity=severity,
                    category="security_analysis",
                    evidence=f"Library: {lib['name']}\nVersion: {lib['version']}\n"
                             f"Vuln ID: {vuln_id}\nAliases: {', '.join(aliases[:5])}\n"
                             f"References: {', '.join(r.get('url','') for r in vuln.get('references', [])[:3])}",
                    impact=f"Known vulnerability in bundled library {lib['name']} v{lib['version']}.",
                    remediation=f"Update {lib['name']} to a patched version. "
                                f"See: https://osv.dev/vulnerability/{vuln_id}",
                    cwe_id="CWE-1104",
                    confidence=0.9,
                    raw_data={"osv_id": vuln_id, "aliases": aliases},
                ))

        if not total_cves:
            result.findings.append(ModuleFinding(
                title="No Known CVEs in Versioned Dependencies",
                description=f"Queried OSV for {len(versioned)} versioned libraries — no known vulnerabilities found.",
                severity=FindingSeverity.INFO,
                category="security_analysis",
                evidence=f"Libraries checked: {len(versioned)}",
                impact="No known CVEs does not guarantee safety — versions may be imprecise.",
                remediation="Manually verify critical library versions.",
                confidence=0.7,
            ))

        return result


# ===================================================================
# 2. UnsafeApiModule
# ===================================================================

_UNSAFE_API_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    # ---- .NET / Win32 ----
    (
        "DLL Injection: LoadLibrary",
        re.compile(r'\b(LoadLibrary|LoadLibraryEx|LoadLibraryW|LoadLibraryA)\s*\(', re.I),
        "Dynamic library loading — DLL injection / DLL hijacking risk.",
        "Use full absolute paths for DLL loading. Implement DLL search order hardening.",
    ),
    (
        "Command Injection: CreateProcess",
        re.compile(r'\b(CreateProcess|CreateProcessW|CreateProcessA)\s*\(', re.I),
        "Process creation — potential command injection if arguments are user-controlled.",
        "Validate and sanitize all arguments. Avoid shell=true. Use parameterized execution.",
    ),
    (
        "Command Injection: ShellExecute",
        re.compile(r'\b(ShellExecute|ShellExecuteEx|ShellExecuteW)\s*\(', re.I),
        "Shell execution — command injection risk with user-controlled inputs.",
        "Avoid ShellExecute with user input. Use CreateProcess with explicit argument list.",
    ),
    (
        "Code Injection: Process.Start",
        re.compile(r'\bProcess\.Start\s*\(', re.I),
        ".NET process execution — command injection risk.",
        "Validate all arguments. Never pass unsanitized user input.",
    ),
    (
        "Deserialization: BinaryFormatter",
        re.compile(r'\b(BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter)\b'),
        "Dangerous .NET deserialization — remote code execution risk.",
        "Replace BinaryFormatter with System.Text.Json or DataContractSerializer with known types. "
        "See: https://aka.ms/binaryformatter",
    ),
    (
        "Deserialization: Marshal",
        re.compile(r'\bMarshal\.(PtrToStructure|ReadByte|Copy|GetObjectForNativeVariant|GetObjectForIUnknown)\b'),
        "Marshal operations with potential unsafe memory access.",
        "Validate all pointer sources. Use SafeHandle where possible.",
    ),
    (
        "Deserialization: XmlSerializer type",
        re.compile(r'new\s+XmlSerializer\s*\(\s*[^)]*typeof\s*\(\s*[^)]+\)', re.I),
        "XmlSerializer with dynamic type — potential XXE or type confusion.",
        "Use fixed types. Disable DTD processing in XmlReaderSettings.",
    ),
    # ---- Java ----
    (
        "Command Injection: Runtime.exec",
        re.compile(r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\('),
        "Java command execution — command injection risk.",
        "Use ProcessBuilder with explicit argument list. Never concatenate user input into commands.",
    ),
    (
        "Command Injection: ProcessBuilder",
        re.compile(r'new\s+ProcessBuilder\s*\('),
        "Java process builder — verify arguments are not user-controlled.",
        "Validate all arguments. Do not pass shell metacharacters.",
    ),
    (
        "Deserialization: ObjectInputStream",
        re.compile(r'\b(ObjectInputStream|readObject|readUnshared)\s*\('),
        "Java deserialization — RCE via gadget chains (ysoserial).",
        "Use allowlisted ObjectInputFilter (JEP 290). Avoid deserializing untrusted data.",
    ),
    (
        "Deserialization: XMLDecoder",
        re.compile(r'\bXMLDecoder\b'),
        "Java XMLDecoder — arbitrary code execution via crafted XML.",
        "Remove XMLDecoder usage. Use safe XML parsers.",
    ),
    # ---- Python (.NET IronPython / embedded) ----
    (
        "Code Injection: eval/exec",
        re.compile(r'\b(eval|exec)\s*\('),
        "Dynamic code evaluation — code injection if input is user-controlled.",
        "Remove eval/exec. Use ast.literal_eval for safe evaluation of literals.",
    ),
    # ---- SQL injection via concatenation ----
    (
        "SQL Injection: String Concatenation",
        re.compile(
            r'(?:'
            r'["\'](?:SELECT|INSERT|UPDATE|DELETE|EXEC|EXECUTE|DROP)\s[^"\']*["\']\s*\+\s*'
            r'|'
            r'["\'](?:SELECT|INSERT|UPDATE|DELETE|EXEC|EXECUTE|DROP)\s[^"\']*["\']\s*&\s*'
            r'|'
            r'string\.Format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|EXEC)\s'
            r'|'
            r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s.*?\{0\}'
            r')',
            re.I,
        ),
        "SQL query built via string concatenation — SQL injection risk.",
        "Use parameterized queries (SqlParameter, PreparedStatement). Never concatenate user input into SQL.",
    ),
    (
        "SQL Injection: String Format in query",
        re.compile(
            r'(?:executeQuery|executeUpdate|ExecuteNonQuery|ExecuteReader|ExecuteScalar)\s*\('
            r'[^)]*(?:\+|String\.Format|string\.Format|\.format\()',
            re.I,
        ),
        "SQL execution with formatted/concatenated string — SQL injection risk.",
        "Use parameterized queries.",
    ),
    # ---- Path traversal ----
    (
        "Path Traversal: User input in file path",
        re.compile(r'(?:File\.(?:Open|Read|Write|Copy|Move|Delete)|new\s+FileStream|new\s+StreamReader)\s*\([^)]*(?:\+|String\.Format|string\.Format)', re.I),
        "File operation with dynamically constructed path — path traversal risk.",
        "Validate and canonicalize file paths. Use Path.GetFullPath and check against allowed base directory.",
    ),
    # ---- LDAP injection ----
    (
        "LDAP Injection",
        re.compile(r'(?:DirectorySearcher|SearchRequest)\s*\([^)]*(?:\+|String\.Format)', re.I),
        "LDAP query with concatenated input — LDAP injection risk.",
        "Use parameterized LDAP filters.",
    ),
]


class UnsafeApiModule(BaseModule):
    """Scan decompiled source for dangerous API calls."""

    @property
    def name(self) -> str:
        return "thick_unsafe_api"

    @property
    def display_name(self) -> str:
        return "Unsafe API Detection"

    @property
    def description(self) -> str:
        return "Detect dangerous function calls (command injection, deserialization, SQLi) in decompiled code"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "security_analysis"

    @property
    def timeout(self) -> int:
        return 120

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        decompiled = _decompiled_root(target)

        if not decompiled.exists():
            result.error = (
                f"Decompiled directory not found at {decompiled}. "
                "Run ThickDecompileModule first."
            )
            return result

        if progress_callback:
            await progress_callback("Scanning decompiled code for unsafe API calls...")

        source_files = _walk_source_files(decompiled)
        if not source_files:
            result.error = f"No source files found under {decompiled}"
            return result

        hits = _search_files_for_patterns(source_files, _UNSAFE_API_PATTERNS, max_hits_per_pattern=30)

        result.raw_output["total_hits"] = len(hits)
        result.raw_output["files_scanned"] = len(source_files)

        # Group hits by label
        by_label: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_label.setdefault(h["label"], []).append(h)

        severity_map: dict[str, FindingSeverity] = {
            "DLL Injection": FindingSeverity.HIGH,
            "Command Injection": FindingSeverity.HIGH,
            "Code Injection": FindingSeverity.HIGH,
            "Deserialization": FindingSeverity.CRITICAL,
            "SQL Injection": FindingSeverity.HIGH,
            "Path Traversal": FindingSeverity.MEDIUM,
            "LDAP Injection": FindingSeverity.HIGH,
        }

        cwe_map: dict[str, str] = {
            "DLL Injection": "CWE-427",
            "Command Injection": "CWE-78",
            "Code Injection": "CWE-94",
            "Deserialization": "CWE-502",
            "SQL Injection": "CWE-89",
            "Path Traversal": "CWE-22",
            "LDAP Injection": "CWE-90",
        }

        for label, label_hits in by_label.items():
            # Determine severity from label prefix
            sev = FindingSeverity.MEDIUM
            cwe = ""
            for prefix, s in severity_map.items():
                if label.startswith(prefix):
                    sev = s
                    cwe = cwe_map.get(prefix, "")
                    break

            # Build evidence from first several hits
            evidence_lines: list[str] = []
            for h in label_hits[:10]:
                rel_path = h["file"].replace(str(decompiled) + "/", "")
                evidence_lines.append(f"  {rel_path}:{h['line']}  {h['snippet']}")

            if len(label_hits) > 10:
                evidence_lines.append(f"  ... and {len(label_hits) - 10} more occurrences")

            result.findings.append(ModuleFinding(
                title=f"{label} ({len(label_hits)} occurrence{'s' if len(label_hits)!=1 else ''})",
                description=label_hits[0]["description"],
                severity=sev,
                category="security_analysis",
                evidence="\n".join(evidence_lines),
                impact=f"Potential exploitation via {label.split(':')[0].strip().lower()}.",
                remediation=label_hits[0]["remediation"],
                cwe_id=cwe,
                confidence=0.7,
                validation_hint="Review each hit in context to confirm user-controlled input reaches the sink.",
            ))

        if not hits:
            result.findings.append(ModuleFinding(
                title="No Unsafe API Calls Detected",
                description=f"Scanned {len(source_files)} files — no known dangerous API patterns found.",
                severity=FindingSeverity.INFO,
                category="security_analysis",
                evidence=f"Files scanned: {len(source_files)}",
                impact="N/A",
                remediation="N/A",
                confidence=0.6,
            ))

        return result


# ===================================================================
# 3. ThickCryptoModule
# ===================================================================

_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str], str, str, str, float]] = [
    # (title, pattern, description, impact, remediation, cvss)
    (
        "Weak Cipher: DES",
        re.compile(r'\b(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|DES\.Create|Cipher\.getInstance\s*\(\s*"DES(?:/|\s*")|new\s+DESKeySpec)\b', re.I),
        "DES / 3DES cipher usage detected. DES has a 56-bit key and is cryptographically broken.",
        "Data encrypted with DES can be brute-forced. 3DES is deprecated by NIST as of 2023.",
        "Migrate to AES-256-GCM or ChaCha20-Poly1305.",
        5.3,
    ),
    (
        "Weak Mode: ECB",
        re.compile(r'(?:CipherMode\.ECB|"AES/ECB|"DES/ECB|"DESede/ECB|RijndaelManaged.*?Mode\s*=\s*CipherMode\.ECB|Cipher\.getInstance\s*\(\s*"[^"]*?/ECB)', re.I | re.S),
        "ECB block cipher mode detected. ECB does not provide semantic security — identical plaintext blocks produce identical ciphertext.",
        "Attacker can detect patterns in encrypted data, enabling partial or full plaintext recovery.",
        "Use CBC with random IV, or preferably GCM/CCM for authenticated encryption.",
        5.3,
    ),
    (
        "Weak Hash: MD5",
        re.compile(r'\b(?:MD5CryptoServiceProvider|MD5\.Create|MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)|HashAlgorithm\.Create\s*\(\s*"MD5"\s*\))\b'),
        "MD5 hash usage detected. MD5 is cryptographically broken — collisions can be generated in seconds.",
        "Signatures, integrity checks, or password hashes using MD5 can be forged or cracked trivially.",
        "Use SHA-256 or SHA-3 for integrity. Use bcrypt/scrypt/Argon2 for passwords.",
        5.3,
    ),
    (
        "Weak Hash: SHA-1",
        re.compile(r'\b(?:SHA1Managed|SHA1CryptoServiceProvider|SHA1\.Create|MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)|HashAlgorithm\.Create\s*\(\s*"SHA1"\s*\))\b'),
        "SHA-1 hash usage detected. SHA-1 has practical collision attacks (SHAttered).",
        "Digital signatures or integrity checks using SHA-1 can be forged.",
        "Migrate to SHA-256 or SHA-3.",
        4.3,
    ),
    (
        "Hardcoded Crypto Key",
        re.compile(
            r'(?:'
            r'new\s+(?:SecretKeySpec|DESKeySpec)\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|")'
            r'|'
            r'(?:Key|key|SECRET|secret|AesKey|aesKey|EncryptionKey)\s*=\s*(?:"[A-Za-z0-9+/=]{8,}"|new\s+byte\s*\[\s*\]\s*\{)'
            r'|'
            r'Encoding\.(?:UTF8|ASCII)\.GetBytes\s*\(\s*"[^"]{8,}"'
            r')',
            re.I,
        ),
        "Hardcoded cryptographic key detected. Key embedded in source code.",
        "Attacker who decompiles the binary obtains the encryption key, defeating all encryption.",
        "Store keys in secure key management (Azure Key Vault, AWS KMS, Android Keystore). "
        "Never embed keys in source code.",
        8.0,
    ),
    (
        "Hardcoded IV / Nonce",
        re.compile(
            r'(?:IV|iv|nonce|Nonce)\s*=\s*(?:new\s+byte\s*\[\s*\]\s*\{|"[A-Za-z0-9+/=]{8,}")',
            re.I,
        ),
        "Hardcoded initialization vector / nonce. Reusing IVs breaks CBC/GCM security guarantees.",
        "Predictable IVs enable known-plaintext attacks on CBC and complete GCM key recovery.",
        "Generate a cryptographically random IV for each encryption operation.",
        6.5,
    ),
    (
        "Insecure Random: System.Random / java.util.Random",
        re.compile(r'\b(?:new\s+Random\s*\(|System\.Random|java\.util\.Random)\b'),
        "Non-cryptographic PRNG used. System.Random / java.util.Random are predictable.",
        "If used for tokens, keys, or nonces, attacker can predict future values from observed output.",
        "Use System.Security.Cryptography.RandomNumberGenerator (.NET) or java.security.SecureRandom (Java).",
        5.3,
    ),
    (
        "Custom Crypto: XOR Cipher",
        re.compile(
            r'(?:'
            r'(?:encrypt|decrypt|cipher|obfuscate)[^{;]*\bfor\s*\([^)]+\)[^{]*\{[^}]*\^'
            r'|'
            r'\[\s*i\s*\]\s*(?:\^=|\^)\s*(?:key|Key|secret|password)'
            r')',
            re.I,
        ),
        "Potential XOR-based custom cipher detected. XOR encryption is trivially reversible.",
        "Custom XOR ciphers provide zero real security — attacker recovers key with known plaintext.",
        "Use standard cryptographic libraries (AES-GCM, ChaCha20-Poly1305).",
        7.5,
    ),
    (
        "Disabled Certificate Validation",
        re.compile(
            r'(?:'
            r'ServerCertificateValidationCallback\s*=\s*(?:\(\s*[^)]*\)\s*=>\s*true|delegate[^{]*\{\s*return\s+true)'
            r'|'
            r'TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\s*\(\s*(?:ALLOW_ALL|NoopHostnameVerifier)'
            r'|'
            r'checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}'
            r'|'
            r'X509TrustManager[^}]*checkServerTrusted[^}]*\{\s*\}'
            r')',
            re.I | re.S,
        ),
        "Certificate validation disabled — accepts any TLS certificate including self-signed / MITM.",
        "Complete TLS MITM possible. Attacker on the network can intercept all HTTPS traffic.",
        "Remove custom certificate callbacks. Use system trust store. Pin certificates if needed.",
        8.5,
    ),
    (
        "Plaintext Password Storage",
        re.compile(
            r'(?:'
            r'(?:password|passwd|pwd)\s*=\s*"[^"]{3,}"'
            r'|'
            r'(?:Password|ConnectionString)[^;]*=[^;]*(?:password|pwd)\s*='
            r')',
            re.I,
        ),
        "Plaintext password or credential found in source code.",
        "Credentials extracted from decompiled binary allow unauthorized access.",
        "Remove hardcoded credentials. Use secure vaults, environment variables, or credential managers.",
        8.5,
    ),
]


class ThickCryptoModule(BaseModule):
    """Audit decompiled code for weak or insecure cryptography patterns."""

    @property
    def name(self) -> str:
        return "thick_crypto"

    @property
    def display_name(self) -> str:
        return "Cryptography Audit"

    @property
    def description(self) -> str:
        return "Detect weak ciphers, broken hashes, hardcoded keys, and custom crypto in decompiled code"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "security_analysis"

    @property
    def timeout(self) -> int:
        return 120

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        decompiled = _decompiled_root(target)

        if not decompiled.exists():
            result.error = f"Decompiled directory not found at {decompiled}. Run ThickDecompileModule first."
            return result

        if progress_callback:
            await progress_callback("Scanning for weak cryptography patterns...")

        source_files = _walk_source_files(decompiled)
        if not source_files:
            result.error = f"No source files found under {decompiled}"
            return result

        # Convert _CRYPTO_PATTERNS into the format _search_files_for_patterns expects
        search_patterns: list[tuple[str, re.Pattern[str], str, str]] = [
            (title, pat, desc, remed)
            for title, pat, desc, _impact, remed, _cvss in _CRYPTO_PATTERNS
        ]

        hits = _search_files_for_patterns(source_files, search_patterns, max_hits_per_pattern=25)

        result.raw_output["total_hits"] = len(hits)
        result.raw_output["files_scanned"] = len(source_files)

        # Group by label and emit findings
        by_label: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_label.setdefault(h["label"], []).append(h)

        # Build a lookup for the extra fields
        extra_lookup: dict[str, tuple[str, float]] = {
            title: (impact, cvss)
            for title, _pat, _desc, impact, _remed, cvss in _CRYPTO_PATTERNS
        }

        for label, label_hits in by_label.items():
            impact_str, cvss = extra_lookup.get(label, ("Weak cryptography in use.", 5.0))

            if cvss >= 8.0:
                sev = FindingSeverity.HIGH
            elif cvss >= 5.0:
                sev = FindingSeverity.MEDIUM
            else:
                sev = FindingSeverity.LOW

            evidence_lines: list[str] = []
            for h in label_hits[:8]:
                rel_path = h["file"].replace(str(decompiled) + "/", "")
                evidence_lines.append(f"  {rel_path}:{h['line']}  {h['snippet']}")
            if len(label_hits) > 8:
                evidence_lines.append(f"  ... and {len(label_hits) - 8} more")

            result.findings.append(ModuleFinding(
                title=f"{label} ({len(label_hits)} occurrence{'s' if len(label_hits)!=1 else ''})",
                description=label_hits[0]["description"],
                severity=sev,
                category="security_analysis",
                evidence="\n".join(evidence_lines),
                impact=impact_str,
                remediation=label_hits[0]["remediation"],
                cwe_id="CWE-327",
                cvss_score=cvss,
                confidence=0.75,
                validation_hint="Review each occurrence to confirm it is reachable and handles sensitive data.",
            ))

        if not hits:
            result.findings.append(ModuleFinding(
                title="No Weak Cryptography Detected",
                description=f"Scanned {len(source_files)} files — no known weak crypto patterns found.",
                severity=FindingSeverity.INFO,
                category="security_analysis",
                evidence=f"Files scanned: {len(source_files)}",
                impact="N/A",
                remediation="N/A",
                confidence=0.6,
            ))

        return result


# ===================================================================
# 4. PrivilegeAnalysisModule
# ===================================================================

class PrivilegeAnalysisModule(BaseModule):
    """Analyse privilege requirements — UAC manifest, service installs, driver loading."""

    @property
    def name(self) -> str:
        return "thick_privilege"

    @property
    def display_name(self) -> str:
        return "Privilege Analysis"

    @property
    def description(self) -> str:
        return "Check UAC manifest, service install patterns, driver loading, and privilege escalation vectors"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "security_analysis"

    @property
    def timeout(self) -> int:
        return 60

    async def _extract_pe_manifest(self, target: str) -> str | None:
        """Extract embedded manifest XML from PE resource or raw bytes."""
        # Try pefile resource extraction
        try:
            import pefile
            pe = pefile.PE(target, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    # RT_MANIFEST = 24
                    rid = res_type.struct.Id
                    if rid == 24:
                        for res_id in res_type.directory.entries:
                            for res_lang in res_id.directory.entries:
                                data = pe.get_data(
                                    res_lang.data.struct.OffsetToData,
                                    res_lang.data.struct.Size,
                                )
                                pe.close()
                                return data.decode(errors="replace")
            pe.close()
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("pefile manifest extraction error: %s", exc)

        # Fallback: search for <assembly> in raw binary
        try:
            with open(target, "rb") as f:
                raw = f.read()
            # Find XML manifest by looking for the assembly element
            start = raw.find(b"<assembly")
            if start == -1:
                start = raw.find(b"<Assembly")
            if start != -1:
                end = raw.find(b"</assembly>", start)
                if end == -1:
                    end = raw.find(b"</Assembly>", start)
                if end != -1:
                    return raw[start:end + len(b"</assembly>")].decode(errors="replace")
        except OSError:
            pass

        return None

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        btype = _detect_binary_type(target)
        decompiled = _decompiled_root(target)

        if progress_callback:
            await progress_callback("Analysing privilege requirements...")

        # ------ PE analysis ------
        if btype == "pe":
            manifest_xml = await self._extract_pe_manifest(target)

            if manifest_xml:
                result.raw_output["uac_manifest"] = manifest_xml[:5000]

                # Parse requestedExecutionLevel
                exec_level = None
                ui_access = False
                level_m = re.search(r'requestedExecutionLevel\s+level="([^"]+)"', manifest_xml)
                if level_m:
                    exec_level = level_m.group(1)
                ui_m = re.search(r'uiAccess="(true)"', manifest_xml, re.I)
                if ui_m:
                    ui_access = True

                result.raw_output["execution_level"] = exec_level
                result.raw_output["ui_access"] = ui_access

                if exec_level == "requireAdministrator":
                    result.findings.append(ModuleFinding(
                        title="Requires Administrator Privileges",
                        description="UAC manifest specifies requestedExecutionLevel=requireAdministrator. "
                                    "Application always runs with full admin rights.",
                        severity=FindingSeverity.MEDIUM,
                        category="security_analysis",
                        evidence=f'requestedExecutionLevel level="{exec_level}"',
                        impact="Running as admin increases blast radius of any vulnerability — "
                               "bugs become system-level compromises.",
                        remediation="Reduce to asInvoker where possible. Split privileged operations into a separate helper.",
                        cwe_id="CWE-250",
                        cvss_score=5.0,
                        confidence=0.95,
                    ))
                elif exec_level == "highestAvailable":
                    result.findings.append(ModuleFinding(
                        title="Requests Highest Available Privileges",
                        description="UAC manifest specifies requestedExecutionLevel=highestAvailable. "
                                    "If run by an admin, the app gets full admin rights.",
                        severity=FindingSeverity.LOW,
                        category="security_analysis",
                        evidence=f'requestedExecutionLevel level="{exec_level}"',
                        impact="Unnecessarily elevated privileges if admin runs the app.",
                        remediation="Use asInvoker and elevate only specific operations.",
                        cwe_id="CWE-250",
                        confidence=0.9,
                    ))
                elif exec_level == "asInvoker" or exec_level is None:
                    result.findings.append(ModuleFinding(
                        title="Standard User Privileges (asInvoker)",
                        description="Application runs with standard user privileges.",
                        severity=FindingSeverity.INFO,
                        category="security_analysis",
                        evidence=f'requestedExecutionLevel level="{exec_level or "asInvoker (default)"}"',
                        impact="Good — follows principle of least privilege.",
                        remediation="N/A",
                        confidence=0.9,
                    ))

                if ui_access:
                    result.findings.append(ModuleFinding(
                        title="UIAccess Enabled",
                        description="Application has uiAccess=true — can send input to higher-privilege windows.",
                        severity=FindingSeverity.MEDIUM,
                        category="security_analysis",
                        evidence='uiAccess="true" in manifest',
                        impact="Can interact with elevated UI windows — potential privilege escalation vector.",
                        remediation="Remove uiAccess unless specifically required (e.g., accessibility tools).",
                        cwe_id="CWE-269",
                        confidence=0.85,
                    ))
            else:
                result.findings.append(ModuleFinding(
                    title="No Embedded UAC Manifest",
                    description="PE has no embedded manifest — Windows applies default execution level.",
                    severity=FindingSeverity.INFO,
                    category="security_analysis",
                    evidence="No <assembly> manifest found in PE",
                    impact="Default behavior varies by OS version. May trigger UAC heuristics for installers.",
                    remediation="Add an explicit manifest to declare execution level.",
                    confidence=0.7,
                ))

        # ------ Scan decompiled code for privilege patterns ------
        source_files = _walk_source_files(decompiled) if decompiled.exists() else []

        priv_patterns: list[tuple[str, re.Pattern[str], str, str]] = [
            (
                "Service Install: CreateService / sc create",
                re.compile(r'\b(?:CreateService|CreateServiceW|CreateServiceA|sc\s+create|ServiceInstaller|InstallUtil)\b', re.I),
                "Code installs a Windows service — runs with SYSTEM privileges.",
                "Ensure service binary path is not writable by non-admin users (unquoted service path / DLL hijack).",
            ),
            (
                "Driver Loading: NtLoadDriver / LoadDriver",
                re.compile(r'\b(?:NtLoadDriver|ZwLoadDriver|LoadDriver|DeviceIoControl)\b', re.I),
                "Kernel driver loading detected — highest privilege operation.",
                "Verify driver is signed and loaded from protected path.",
            ),
            (
                "Registry Write: HKLM",
                re.compile(r'\b(?:Registry\.LocalMachine|HKEY_LOCAL_MACHINE|HKLM\\|RegistryKey\.OpenSubKey\s*\([^)]*true\))\b', re.I),
                "Writing to HKLM registry — requires admin and persists system-wide.",
                "Use HKCU where possible. Document required registry changes.",
            ),
            (
                "Named Pipe Server",
                re.compile(r'\b(?:NamedPipeServerStream|CreateNamedPipe|CreateNamedPipeW)\b', re.I),
                "Named pipe server — potential privilege escalation via impersonation.",
                "Set proper ACLs on pipe. Do not impersonate client without validation.",
            ),
            (
                "Token Manipulation",
                re.compile(r'\b(?:AdjustTokenPrivileges|ImpersonateLoggedOnUser|DuplicateToken|SetThreadToken|OpenProcessToken)\b', re.I),
                "Token manipulation functions — potential privilege escalation.",
                "Ensure token operations follow least privilege. Validate all handles.",
            ),
        ]

        # Java-specific privilege patterns
        java_priv_patterns: list[tuple[str, re.Pattern[str], str, str]] = [
            (
                "Java sudo/runas Execution",
                re.compile(r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*(?:"sudo|"runas|"pkexec)', re.I),
                "Java code executes privileged commands via sudo/runas.",
                "Avoid invoking sudo from application code. Use OS-level service management instead.",
            ),
            (
                "Java SecurityManager Bypass",
                re.compile(r'\b(?:System\.setSecurityManager\s*\(\s*null\s*\)|AccessController\.doPrivileged)\b'),
                "SecurityManager disabled or privileged action executed.",
                "Do not disable SecurityManager. Use doPrivileged with minimal scope.",
            ),
        ]

        all_priv_patterns = priv_patterns + java_priv_patterns

        if source_files:
            if progress_callback:
                await progress_callback("Scanning for privilege escalation patterns...")

            hits = _search_files_for_patterns(source_files, all_priv_patterns, max_hits_per_pattern=20)

            by_label: dict[str, list[dict[str, Any]]] = {}
            for h in hits:
                by_label.setdefault(h["label"], []).append(h)

            for label, label_hits in by_label.items():
                evidence_lines: list[str] = []
                for h in label_hits[:6]:
                    rel_path = h["file"].replace(str(decompiled) + "/", "")
                    evidence_lines.append(f"  {rel_path}:{h['line']}  {h['snippet']}")
                if len(label_hits) > 6:
                    evidence_lines.append(f"  ... and {len(label_hits) - 6} more")

                result.findings.append(ModuleFinding(
                    title=f"{label} ({len(label_hits)} occurrence{'s' if len(label_hits)!=1 else ''})",
                    description=label_hits[0]["description"],
                    severity=FindingSeverity.MEDIUM,
                    category="security_analysis",
                    evidence="\n".join(evidence_lines),
                    impact="Elevated privilege operations increase attack surface.",
                    remediation=label_hits[0]["remediation"],
                    cwe_id="CWE-250",
                    confidence=0.7,
                ))

        # --- Also check for raw strings indicating privilege in non-decompiled binary ---
        if not source_files or btype == "pe":
            stdout, _, rc = await self._run_command(["strings", "-n", "8", target], timeout=30)
            if rc == 0 and stdout:
                if "requireAdministrator" in stdout and not result.raw_output.get("execution_level"):
                    result.raw_output["strings_exec_level"] = "requireAdministrator"
                if re.search(r'SeDebugPrivilege|SeTcbPrivilege|SeBackupPrivilege', stdout):
                    result.findings.append(ModuleFinding(
                        title="Sensitive Privilege Constants in Binary",
                        description="Binary contains references to sensitive Windows privileges "
                                    "(SeDebugPrivilege, SeTcbPrivilege, etc.).",
                        severity=FindingSeverity.MEDIUM,
                        category="security_analysis",
                        evidence="Found via strings extraction from binary.",
                        impact="Application may request/use sensitive system privileges.",
                        remediation="Verify these privileges are necessary. Remove unused privilege requests.",
                        cwe_id="CWE-250",
                        confidence=0.6,
                    ))

        return result


# ===================================================================
# 5. UpdateMechanismModule
# ===================================================================

class UpdateMechanismModule(BaseModule):
    """Detect insecure software update mechanisms — supply chain risk."""

    @property
    def name(self) -> str:
        return "thick_update_mechanism"

    @property
    def display_name(self) -> str:
        return "Update Mechanism Audit"

    @property
    def description(self) -> str:
        return "Detect insecure update channels — HTTP updates, missing cert validation, unsigned packages"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "security_analysis"

    @property
    def timeout(self) -> int:
        return 90

    # Patterns that indicate update-related code
    _UPDATE_URL_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
        (
            "Update Check URL",
            re.compile(
                r'(?:update|upgrade|patch|version|release|download|latest|check)[^"\']{0,40}'
                r'(?:https?://[^\s"\'<>]+)',
                re.I,
            ),
            "URL associated with software update mechanism found.",
            "Ensure all update URLs use HTTPS with certificate validation.",
        ),
        (
            "HTTP Update URL (No TLS)",
            re.compile(
                r'http://[^\s"\'<>]*(?:update|upgrade|patch|download|release|latest|version|\.msi|\.exe|\.zip|\.msp)',
                re.I,
            ),
            "Software update URL uses plain HTTP without TLS — MITM can inject malicious updates.",
            "Switch to HTTPS. Implement certificate pinning for update channel.",
        ),
    ]

    _UPDATE_CODE_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
        (
            "Auto-Update Framework: Squirrel",
            re.compile(r'\b(?:Squirrel|UpdateManager|GithubUpdateManager|CheckForUpdate|DownloadReleases|ApplyReleases)\b'),
            "Squirrel.Windows auto-update framework detected.",
            "Verify Squirrel is configured with HTTPS and package signing.",
        ),
        (
            "Auto-Update Framework: ClickOnce",
            re.compile(r'\b(?:ApplicationDeployment|IsNetworkDeployed|CheckForUpdate|CheckForDetailedUpdate)\b'),
            "ClickOnce deployment / update detected.",
            "Ensure ClickOnce manifests are signed. Use HTTPS deployment URL.",
        ),
        (
            "Auto-Update: WinSparkle / Sparkle",
            re.compile(r'\b(?:WinSparkle|Sparkle|SUUpdater|win_sparkle_init|appcast\.xml)\b', re.I),
            "WinSparkle / Sparkle auto-update framework detected.",
            "Ensure appcast feed uses HTTPS. Verify DSA/EdDSA signatures on updates.",
        ),
        (
            "Auto-Update: Electron autoUpdater",
            re.compile(r'\b(?:autoUpdater|electron-updater|update-electron-app|setFeedURL|checkForUpdates)\b'),
            "Electron auto-update mechanism detected.",
            "Ensure feed URL uses HTTPS. Enable code signing verification.",
        ),
        (
            "Version Comparison Logic",
            re.compile(
                r'(?:(?:current|local|installed)[\w]*[Vv]ersion.*?(?:compare|<|>|!=|==).*?(?:remote|server|latest|new)[\w]*[Vv]ersion'
                r'|'
                r'(?:remote|server|latest|new)[\w]*[Vv]ersion.*?(?:compare|<|>|!=|==).*?(?:current|local|installed)[\w]*[Vv]ersion)',
                re.I,
            ),
            "Version comparison logic — part of update checking mechanism.",
            "Ensure version info comes from authenticated, integrity-verified source.",
        ),
        (
            "Download and Execute Pattern",
            re.compile(
                r'(?:WebClient|HttpClient|HttpWebRequest|wget|curl|Download(?:File|Data|String))'
                r'[^;]{0,200}'
                r'(?:Process\.Start|CreateProcess|ShellExecute|exec|Runtime\.exec)',
                re.I | re.S,
            ),
            "Download-and-execute pattern detected — common in update mechanisms.",
            "Verify integrity (hash/signature) of downloaded file before execution.",
        ),
        (
            "Missing Signature Verification",
            re.compile(
                r'(?:Download(?:File|Data|Async)|WebClient\.Download|HttpClient\.Get)'
                r'[^;]{0,300}'
                r'(?:\.exe|\.msi|\.dll|\.zip|\.tar)',
                re.I | re.S,
            ),
            "File download without visible signature/hash verification.",
            "Add cryptographic signature verification (Authenticode, GPG) before using downloaded files.",
        ),
        (
            "Certificate Validation Disabled in Update",
            re.compile(
                r'(?:update|upgrade|patch|download)[^{};]{0,200}'
                r'(?:ServerCertificateValidationCallback|ALLOW_ALL|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{[\s]*\})',
                re.I | re.S,
            ),
            "Certificate validation disabled in update-related code — MITM on update channel.",
            "Enable proper certificate validation. Pin update server certificate.",
        ),
    ]

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        decompiled = _decompiled_root(target)

        # ----- Search decompiled source -----
        source_files = _walk_source_files(decompiled) if decompiled.exists() else []

        if progress_callback:
            await progress_callback("Scanning for update mechanism patterns...")

        all_patterns = self._UPDATE_URL_PATTERNS + self._UPDATE_CODE_PATTERNS
        hits: list[dict[str, Any]] = []

        if source_files:
            hits = _search_files_for_patterns(source_files, all_patterns, max_hits_per_pattern=20)

        # ----- Also search raw strings from binary -----
        stdout, _, rc = await self._run_command(["strings", "-n", "10", target], timeout=30)
        string_hits: list[dict[str, Any]] = []
        if rc == 0 and stdout:
            lines = stdout.splitlines()
            for line_no, line in enumerate(lines, 1):
                for label, pat, desc, remed in all_patterns:
                    m = pat.search(line)
                    if m:
                        string_hits.append({
                            "file": f"<binary strings>",
                            "line": line_no,
                            "snippet": line.strip()[:300],
                            "match": m.group(0)[:200],
                            "label": label,
                            "description": desc,
                            "remediation": remed,
                        })

        all_hits = hits + string_hits
        result.raw_output["total_hits"] = len(all_hits)
        result.raw_output["source_files_scanned"] = len(source_files)

        # Collect update URLs
        update_urls: list[str] = []
        http_urls: list[str] = []
        url_re = re.compile(r'https?://[^\s"\'<>]+', re.I)
        for h in all_hits:
            urls = url_re.findall(h.get("snippet", "") + " " + h.get("match", ""))
            for u in urls:
                if any(kw in u.lower() for kw in ("update", "upgrade", "patch", "download", "release", "latest", "version")):
                    update_urls.append(u)
                    if u.startswith("http://"):
                        http_urls.append(u)
                    result.assets.append(ModuleAsset(
                        asset_type=AssetType.ENDPOINT,
                        value=u,
                        metadata={"type": "update_url", "tls": u.startswith("https://")},
                    ))

        result.raw_output["update_urls"] = list(set(update_urls))

        # ------ Generate findings ------

        # HTTP update URLs = HIGH
        if http_urls:
            result.findings.append(ModuleFinding(
                title=f"Insecure HTTP Update Channel ({len(set(http_urls))} URL{'s' if len(set(http_urls))!=1 else ''})",
                description="Software update mechanism uses plain HTTP without TLS encryption. "
                            "An attacker on the network can MITM the update and inject a malicious binary.",
                severity=FindingSeverity.HIGH,
                category="security_analysis",
                evidence="HTTP update URLs found:\n" + "\n".join(f"  {u}" for u in sorted(set(http_urls))[:10]),
                impact="Supply chain attack — MITM attacker replaces legitimate update with malware. "
                       "All users who update become compromised.",
                remediation="Switch all update URLs to HTTPS. Implement certificate pinning. "
                            "Sign update packages and verify signatures before applying.",
                cwe_id="CWE-494",
                cvss_score=8.1,
                owasp_category="A08: Software and Data Integrity Failures",
                confidence=0.85,
                validation_hint="Intercept update traffic with Burp/mitmproxy to confirm HTTP usage.",
            ))

        # Group remaining code pattern hits
        by_label: dict[str, list[dict[str, Any]]] = {}
        for h in all_hits:
            if h["label"] != "HTTP Update URL (No TLS)":  # Already reported above
                by_label.setdefault(h["label"], []).append(h)

        high_severity_labels = {
            "Certificate Validation Disabled in Update",
            "Download and Execute Pattern",
            "Missing Signature Verification",
        }

        for label, label_hits in by_label.items():
            sev = FindingSeverity.HIGH if label in high_severity_labels else FindingSeverity.MEDIUM

            evidence_lines: list[str] = []
            for h in label_hits[:8]:
                source = h["file"]
                if decompiled.exists():
                    source = source.replace(str(decompiled) + "/", "")
                evidence_lines.append(f"  {source}:{h['line']}  {h['snippet']}")
            if len(label_hits) > 8:
                evidence_lines.append(f"  ... and {len(label_hits) - 8} more")

            result.findings.append(ModuleFinding(
                title=f"{label} ({len(label_hits)} occurrence{'s' if len(label_hits)!=1 else ''})",
                description=label_hits[0]["description"],
                severity=sev,
                category="security_analysis",
                evidence="\n".join(evidence_lines),
                impact="Insecure update mechanism enables supply chain attacks.",
                remediation=label_hits[0]["remediation"],
                cwe_id="CWE-494",
                confidence=0.7,
            ))

        if not all_hits:
            result.findings.append(ModuleFinding(
                title="No Update Mechanism Detected",
                description="No software update patterns found in decompiled code or binary strings.",
                severity=FindingSeverity.INFO,
                category="security_analysis",
                evidence=f"Files scanned: {len(source_files)}, binary strings checked: {rc == 0}",
                impact="App may lack auto-update — users stuck on vulnerable versions.",
                remediation="Consider implementing a secure auto-update mechanism.",
                confidence=0.5,
            ))

        return result
