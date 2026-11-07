"""Thick-client binary analysis modules — PE, JAR, .NET metadata and security checks."""
from __future__ import annotations

import collections
import datetime
import logging
import math
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Callable

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

try:
    import pefile  # type: ignore[import-untyped]

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_file_type(path: str) -> str:
    """Return 'pe', 'jar', 'dotnet', or 'unknown' based on extension and magic bytes."""
    p = Path(path)
    ext = p.suffix.lower()

    if ext in (".jar", ".war", ".ear"):
        return "jar"

    if ext in (".exe", ".dll", ".sys", ".ocx", ".scr"):
        # Try to distinguish .NET from native PE
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                if magic != b"MZ":
                    return "unknown"
                # Quick .NET check — look for the CLR header directory entry
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) < 4:
                    return "pe"
                pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
                f.seek(pe_offset)
                sig = f.read(4)
                if sig != b"PE\x00\x00":
                    return "pe"
                # Skip COFF header (20 bytes) to optional header
                f.seek(pe_offset + 4 + 20)
                opt_magic = f.read(2)
                if len(opt_magic) < 2:
                    return "pe"
                is_pe32_plus = struct.unpack("<H", opt_magic)[0] == 0x20B
                # COM descriptor RVA is at offset 208 (PE32) or 224 (PE32+) from optional header start
                clr_offset = (pe_offset + 4 + 20) + (224 if is_pe32_plus else 208)
                f.seek(clr_offset)
                clr_rva_bytes = f.read(4)
                if len(clr_rva_bytes) == 4:
                    clr_rva = struct.unpack("<I", clr_rva_bytes)[0]
                    if clr_rva != 0:
                        return "dotnet"
        except Exception:
            pass
        return "pe"

    return "unknown"


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq: dict[int, int] = collections.Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Module 1: BinaryMetadataModule
# ---------------------------------------------------------------------------

class BinaryMetadataModule(BaseModule):
    """Extract metadata from PE, JAR, or .NET binaries and flag suspicious indicators."""

    @property
    def name(self) -> str:
        return "thick_metadata"

    @property
    def display_name(self) -> str:
        return "Binary Metadata"

    @property
    def description(self) -> str:
        return "Parse PE headers, JAR manifests, or .NET assembly info for metadata and suspicious indicators"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "binary_analysis"

    @property
    def timeout(self) -> int:
        return 90

    # ---- PE analysis with pefile ----

    def _analyse_pe(self, path: str, result: ModuleResult) -> None:
        if not HAS_PEFILE:
            result.findings.append(
                ModuleFinding(
                    title="pefile Library Not Available",
                    description="Install `pefile` for PE header analysis: pip install pefile",
                    severity=FindingSeverity.INFO,
                    category="binary_analysis",
                    evidence="ImportError: pefile",
                    impact="PE metadata extraction skipped.",
                    remediation="pip install pefile",
                    confidence=1.0,
                )
            )
            return

        try:
            pe = pefile.PE(path, fast_load=False)
        except pefile.PEFormatError as exc:
            result.error = f"PE parse error: {exc}"
            return
        except Exception as exc:
            result.error = f"Error opening PE: {exc}"
            return

        meta: dict[str, Any] = {}

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
            meta["compile_time"] = compile_time
            meta["compile_timestamp_raw"] = ts
        except (OSError, ValueError):
            meta["compile_time"] = f"raw={ts}"

        # Machine type
        machine_map = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
        meta["machine"] = machine_map.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

        # Entry point
        meta["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Linker version
        meta["linker_version"] = (
            f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
        )

        # Sections
        sections_info: list[dict[str, Any]] = []
        for sec in pe.sections:
            sec_name = sec.Name.rstrip(b"\x00").decode(errors="replace")
            entropy = sec.get_entropy()
            sections_info.append({
                "name": sec_name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": round(entropy, 3),
                "characteristics": hex(sec.Characteristics),
            })
        meta["sections"] = sections_info

        # Imports (DLL names)
        imported_dlls: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace")
                imported_dlls.append(dll_name)
        meta["imported_dlls"] = imported_dlls

        # Debug info presence
        has_debug = hasattr(pe, "DIRECTORY_ENTRY_DEBUG") and len(pe.DIRECTORY_ENTRY_DEBUG) > 0
        meta["has_debug_info"] = has_debug
        if has_debug:
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(dbg, "entry") and hasattr(dbg.entry, "PdbFileName"):
                    pdb = dbg.entry.PdbFileName.rstrip(b"\x00").decode(errors="replace")
                    meta["pdb_path"] = pdb
                    break

        # .NET detection
        meta["is_dotnet"] = (
            hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY")
            and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14
            and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
        )

        result.raw_output["pe_metadata"] = meta
        pe.close()

        # ---- Suspicious indicators ----

        # Recent compile (within 30 days)
        if ts:
            try:
                compile_dt = datetime.datetime.utcfromtimestamp(ts)
                age_days = (datetime.datetime.utcnow() - compile_dt).days
                if 0 <= age_days <= 30:
                    result.findings.append(
                        ModuleFinding(
                            title="Recently Compiled Binary",
                            description=f"Binary was compiled {age_days} day(s) ago ({meta['compile_time']}). "
                            "Very recent compilation can indicate a custom-built or modified binary.",
                            severity=FindingSeverity.INFO,
                            category="binary_analysis",
                            evidence=f"Compile timestamp: {meta['compile_time']}",
                            impact="May indicate custom malware, repackaged software, or active development.",
                            remediation="Verify origin and integrity of the binary.",
                            confidence=0.6,
                        )
                    )
                elif ts == 0 or age_days < 0 or age_days > 36500:
                    result.findings.append(
                        ModuleFinding(
                            title="Suspicious Compile Timestamp",
                            description=f"Compile timestamp is zero, negative, or unreasonably old/future (raw={ts}). "
                            "Often indicates timestamp stomping to hinder forensics.",
                            severity=FindingSeverity.MEDIUM,
                            category="binary_analysis",
                            evidence=f"Raw timestamp: {ts}",
                            impact="Timestamp manipulation is a common anti-forensic technique.",
                            remediation="Investigate binary provenance through other means.",
                            cwe_id="CWE-116",
                            confidence=0.7,
                        )
                    )
            except Exception:
                pass

        # Debug symbols in release binary
        if has_debug and meta.get("pdb_path"):
            result.findings.append(
                ModuleFinding(
                    title="Debug Symbols Present",
                    description=f"Binary contains debug symbols (PDB path: {meta.get('pdb_path', 'N/A')}). "
                    "This aids reverse engineering significantly.",
                    severity=FindingSeverity.LOW,
                    category="binary_analysis",
                    evidence=f"PDB: {meta.get('pdb_path', 'N/A')}",
                    impact="Debug symbols make reverse engineering trivial — function names, types, "
                    "and source file paths are exposed.",
                    remediation="Strip debug symbols from release builds.",
                    cwe_id="CWE-489",
                    confidence=0.9,
                )
            )

        # Unusual sections
        normal_sections = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata",
                          ".idata", ".edata", ".tls", ".bss", ".CRT", ".gfids", ".00cfg"}
        for s in sections_info:
            sname = s["name"]
            if sname and sname not in normal_sections and not sname.startswith("."):
                result.findings.append(
                    ModuleFinding(
                        title=f"Unusual PE Section: {sname}",
                        description=f"PE section '{sname}' is not a standard section name. "
                        "May indicate packing, obfuscation, or code injection.",
                        severity=FindingSeverity.LOW,
                        category="binary_analysis",
                        evidence=f"Section: {sname}, Size: {s['raw_size']}, Entropy: {s['entropy']}",
                        impact="Non-standard sections may contain packed/obfuscated code.",
                        remediation="Investigate section contents. Unpack if necessary.",
                        confidence=0.5,
                    )
                )

        # Assets for imported DLLs
        for dll in imported_dlls:
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.COMPONENT,
                    value=dll,
                    metadata={"type": "imported_dll"},
                )
            )

    # ---- JAR analysis ----

    def _analyse_jar(self, path: str, result: ModuleResult) -> None:
        meta: dict[str, Any] = {}
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                meta["entry_count"] = len(names)

                # MANIFEST.MF
                manifest_text = ""
                for candidate in ("META-INF/MANIFEST.MF", "meta-inf/manifest.mf"):
                    if candidate in names:
                        manifest_text = zf.read(candidate).decode(errors="replace")
                        break

                if manifest_text:
                    meta["manifest_raw"] = manifest_text[:5000]
                    for line in manifest_text.splitlines():
                        if ":" in line:
                            k, _, v = line.partition(":")
                            k = k.strip()
                            v = v.strip()
                            if k in ("Main-Class", "Implementation-Version", "Bundle-Version",
                                     "Created-By", "Build-Jdk", "Built-By"):
                                meta[k] = v

                # Check for .class files (compiled Java)
                class_count = sum(1 for n in names if n.endswith(".class"))
                meta["class_file_count"] = class_count

                # Check for .dll inside (Xamarin / embedded native)
                dll_count = sum(1 for n in names if n.lower().endswith(".dll"))
                meta["embedded_dll_count"] = dll_count

                # Check for signing files
                sf_files = [n for n in names if n.startswith("META-INF/") and n.endswith(".SF")]
                meta["signed"] = len(sf_files) > 0
                meta["signature_files"] = sf_files

        except zipfile.BadZipFile:
            result.error = "Not a valid ZIP/JAR file"
            return
        except Exception as exc:
            result.error = f"JAR analysis error: {exc}"
            return

        result.raw_output["jar_metadata"] = meta

        if meta.get("Built-By"):
            result.findings.append(
                ModuleFinding(
                    title="Build User Disclosed in JAR Manifest",
                    description=f"Built-By header reveals the build user: {meta['Built-By']}",
                    severity=FindingSeverity.LOW,
                    category="binary_analysis",
                    evidence=f"Built-By: {meta['Built-By']}",
                    impact="Reveals internal username, aiding targeted attacks.",
                    remediation="Remove Built-By from manifest in release builds.",
                    cwe_id="CWE-200",
                    confidence=0.85,
                )
            )

        if meta.get("Build-Jdk"):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=f"JDK {meta['Build-Jdk']}",
                    metadata={"type": "build_jdk", "version": meta["Build-Jdk"]},
                )
            )

    # ---- .NET analysis ----

    async def _analyse_dotnet(self, path: str, result: ModuleResult) -> None:
        meta: dict[str, Any] = {"runtime": ".NET"}

        # Try monodis or ildasm for assembly info
        for tool in ("monodis", "ikdasm"):
            stdout, stderr, rc = await self._run_command([tool, "--assembly", path], timeout=30)
            if rc == 0 and stdout.strip():
                meta["assembly_info_raw"] = stdout[:3000]
                for line in stdout.splitlines():
                    line = line.strip()
                    if line.startswith(".ver"):
                        ver_m = re.search(r"(\d+:\d+:\d+:\d+)", line)
                        if ver_m:
                            meta["assembly_version"] = ver_m.group(1).replace(":", ".")
                    elif "culture" in line.lower():
                        meta["culture"] = line
                break

        # Try strings-based .NET metadata extraction as fallback
        try:
            with open(path, "rb") as f:
                raw = f.read()
            # Look for .NET version string
            ver_m = re.search(rb"v\d+\.\d+\.\d+", raw)
            if ver_m:
                meta["clr_version"] = ver_m.group(0).decode(errors="replace")
            # Look for assembly attributes in raw strings
            for attr_pattern in (rb"AssemblyVersion\(\"([^\"]+)\"\)", rb"AssemblyFileVersion\(\"([^\"]+)\"\)"):
                m = re.search(attr_pattern, raw)
                if m:
                    key = "AssemblyVersion" if b"AssemblyVersion" in attr_pattern else "AssemblyFileVersion"
                    meta[key] = m.group(1).decode(errors="replace")
        except Exception as exc:
            logger.debug("Raw .NET metadata extraction failed: %s", exc)

        result.raw_output["dotnet_metadata"] = meta

        # Also run the PE analyser since .NET is PE-based
        self._analyse_pe(path, result)

    # ---- run ----

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)

        if not Path(file_path).exists():
            result.error = f"File not found: {file_path}"
            return result

        ftype = _detect_file_type(file_path)
        result.raw_output["detected_type"] = ftype

        if progress_callback:
            await progress_callback(f"Analysing {ftype} binary metadata...")

        if ftype == "pe":
            self._analyse_pe(file_path, result)
        elif ftype == "dotnet":
            await self._analyse_dotnet(file_path, result)
        elif ftype == "jar":
            self._analyse_jar(file_path, result)
        else:
            # Try PE first, fall back to JAR
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(file_path, fast_load=True)
                    pe.close()
                    self._analyse_pe(file_path, result)
                    return result
                except Exception:
                    pass
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    _ = zf.namelist()
                self._analyse_jar(file_path, result)
            except Exception:
                result.error = f"Could not determine binary type for: {file_path}"

        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.FILE,
                value=file_path,
                metadata={"type": ftype, **{k: v for k, v in result.raw_output.items() if isinstance(v, str)}},
            )
        )

        return result


# ---------------------------------------------------------------------------
# Module 2: StringsExtractModule
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s\"'<>]{5,200}", re.I)
_FTP_RE = re.compile(r"ftp://[^\s\"'<>]{5,200}", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WIN_PATH_RE = re.compile(r"[A-Z]:\\[\w\\. -]{3,200}", re.I)
_UNIX_PATH_RE = re.compile(r"(?:/etc/|/usr/|/var/|/tmp/|/home/|/opt/)[\w/._-]{2,200}")
_REG_KEY_RE = re.compile(r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\w\\._-]{3,200}", re.I)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CRED_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api_key|apikey|api-key|auth|credential|"
    r"private.key|access.key|client.secret)\s*[=:]\s*['\"]?([^\s'\"]{3,100})",
    re.I,
)
_CONN_STR_RE = re.compile(
    r"(?:jdbc:|mongodb://|mysql://|postgresql://|redis://|amqp://|Data Source=|Server=)[^\s\"']{5,300}",
    re.I,
)


class StringsExtractModule(BaseModule):
    """Extract and classify interesting strings from a binary."""

    @property
    def name(self) -> str:
        return "thick_strings"

    @property
    def display_name(self) -> str:
        return "Strings Extraction"

    @property
    def description(self) -> str:
        return "Extract URLs, IPs, paths, registry keys, emails, and credential patterns from binary strings"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "binary_analysis"

    @property
    def timeout(self) -> int:
        return 120

    async def _extract_strings(self, path: str, min_len: int = 4) -> list[str]:
        """Get printable strings via the `strings` command, or Python fallback."""
        # Try GNU strings first (captures both ASCII and UTF-16LE)
        stdout, _, rc = await self._run_command(
            ["strings", "-a", "-n", str(min_len), path], timeout=60
        )
        if rc == 0 and stdout.strip():
            lines = stdout.splitlines()
            # Also grab UTF-16LE (Windows wide strings)
            stdout_w, _, rc_w = await self._run_command(
                ["strings", "-a", "-el", "-n", str(min_len), path], timeout=60
            )
            if rc_w == 0 and stdout_w.strip():
                lines.extend(stdout_w.splitlines())
            return lines

        # Python fallback: extract ASCII printable sequences
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except Exception:
            return []

        result: list[str] = []
        pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        for m in pattern.finditer(raw):
            result.append(m.group(0).decode("ascii", errors="replace"))
        return result

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)

        if not Path(file_path).exists():
            result.error = f"File not found: {file_path}"
            return result

        if progress_callback:
            await progress_callback("Extracting strings from binary...")

        strings = await self._extract_strings(file_path)
        if not strings:
            result.findings.append(
                ModuleFinding(
                    title="No Strings Extracted",
                    description="Could not extract readable strings — binary may be packed or encrypted.",
                    severity=FindingSeverity.INFO,
                    category="binary_analysis",
                    evidence="strings command returned empty",
                    impact="Analysis limited without string data.",
                    remediation="Try unpacking the binary first.",
                    confidence=0.8,
                )
            )
            return result

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for s in strings:
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                unique.append(s)

        big_text = "\n".join(unique)
        result.raw_output["total_unique_strings"] = len(unique)

        # ---- URLs ----
        urls: set[str] = set()
        for m in _URL_RE.finditer(big_text):
            urls.add(m.group(0))
        for m in _FTP_RE.finditer(big_text):
            urls.add(m.group(0))
        for u in urls:
            result.assets.append(
                ModuleAsset(asset_type=AssetType.URL, value=u, metadata={"source": "binary_strings"})
            )

        # ---- IPs ----
        ips: set[str] = set()
        for m in _IP_RE.finditer(big_text):
            ip = m.group(0)
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                # Skip common non-routable noise like version strings
                if ip not in ("0.0.0.0", "255.255.255.255") and not ip.startswith("0."):
                    ips.add(ip)
        for ip in ips:
            result.assets.append(
                ModuleAsset(asset_type=AssetType.IP, value=ip, metadata={"source": "binary_strings"})
            )

        # ---- File paths ----
        win_paths: set[str] = set()
        unix_paths: set[str] = set()
        for m in _WIN_PATH_RE.finditer(big_text):
            win_paths.add(m.group(0))
        for m in _UNIX_PATH_RE.finditer(big_text):
            unix_paths.add(m.group(0))

        # ---- Registry keys ----
        reg_keys: set[str] = set()
        for m in _REG_KEY_RE.finditer(big_text):
            reg_keys.add(m.group(0))

        # ---- Emails ----
        emails: set[str] = set()
        for m in _EMAIL_RE.finditer(big_text):
            em = m.group(0)
            if not em.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                emails.add(em)
        for em in emails:
            result.assets.append(
                ModuleAsset(asset_type=AssetType.EMAIL, value=em, metadata={"source": "binary_strings"})
            )

        # ---- Credential patterns ----
        creds: list[dict[str, str]] = []
        for m in _CRED_RE.finditer(big_text):
            full = m.group(0)
            value = m.group(1)
            creds.append({"match": full, "value": value})
        for m in _CONN_STR_RE.finditer(big_text):
            creds.append({"match": m.group(0), "value": m.group(0)})
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=m.group(0),
                    metadata={"type": "connection_string", "source": "binary_strings"},
                )
            )

        result.raw_output["extracted"] = {
            "urls": len(urls),
            "ips": len(ips),
            "win_paths": len(win_paths),
            "unix_paths": len(unix_paths),
            "reg_keys": len(reg_keys),
            "emails": len(emails),
            "credential_patterns": len(creds),
        }

        # ---- Findings ----
        if urls:
            sample = list(urls)[:20]
            result.findings.append(
                ModuleFinding(
                    title=f"{len(urls)} URL(s) Found in Binary Strings",
                    description="URLs extracted from binary strings — may reveal API endpoints, "
                    "update servers, or C2 infrastructure.",
                    severity=FindingSeverity.INFO,
                    category="binary_analysis",
                    evidence="\n".join(sample),
                    impact="Embedded URLs expose backend infrastructure and attack surface.",
                    remediation="Review each URL for sensitive endpoints or insecure protocols.",
                    confidence=0.85,
                )
            )

        if ips:
            sample = list(ips)[:20]
            result.findings.append(
                ModuleFinding(
                    title=f"{len(ips)} IP Address(es) Found in Binary Strings",
                    description="Hard-coded IP addresses found — may indicate internal infrastructure.",
                    severity=FindingSeverity.LOW,
                    category="binary_analysis",
                    evidence="\n".join(sample),
                    impact="Hardcoded IPs reveal infrastructure and may enable direct targeting.",
                    remediation="Use DNS names instead of hardcoded IPs. Review each for sensitivity.",
                    cwe_id="CWE-798",
                    confidence=0.7,
                )
            )

        if creds:
            evidence_lines = [c["match"][:200] for c in creds[:15]]
            result.findings.append(
                ModuleFinding(
                    title=f"{len(creds)} Credential/Secret Pattern(s) in Binary Strings",
                    description="Patterns matching password, token, or connection string assignments "
                    "found in binary strings.",
                    severity=FindingSeverity.HIGH,
                    category="binary_analysis",
                    evidence="\n".join(evidence_lines),
                    impact="Hardcoded credentials enable authentication bypass and lateral movement.",
                    remediation="Remove hardcoded credentials. Use secure vaults or environment variables.",
                    cwe_id="CWE-798",
                    cvss_score=7.5,
                    confidence=0.6,
                    validation_hint="Verify strings are actual credentials, not variable names or placeholders.",
                )
            )
            for c in creds:
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SECRET,
                        value=c["match"][:300],
                        metadata={"source": "binary_strings"},
                    )
                )

        if reg_keys:
            result.findings.append(
                ModuleFinding(
                    title=f"{len(reg_keys)} Registry Key Reference(s)",
                    description="Windows registry key references found — may reveal persistence, "
                    "configuration, or privilege behavior.",
                    severity=FindingSeverity.INFO,
                    category="binary_analysis",
                    evidence="\n".join(list(reg_keys)[:15]),
                    impact="Registry keys can reveal persistence mechanisms and sensitive config.",
                    remediation="Review for sensitive data storage in registry.",
                    confidence=0.8,
                )
            )

        return result


# ---------------------------------------------------------------------------
# Module 3: CodeSigningModule
# ---------------------------------------------------------------------------

class CodeSigningModule(BaseModule):
    """Verify digital signatures for PE and JAR binaries."""

    @property
    def name(self) -> str:
        return "thick_code_signing"

    @property
    def display_name(self) -> str:
        return "Code Signing Check"

    @property
    def description(self) -> str:
        return "Verify Authenticode (PE) or JAR signing and report certificate details"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "binary_analysis"

    @property
    def timeout(self) -> int:
        return 60

    async def _check_pe_signature(self, path: str, result: ModuleResult) -> None:
        """Check PE Authenticode signature via osslsigncode or sigcheck."""
        sign_info: dict[str, Any] = {"signed": False}

        # Try osslsigncode (Linux-friendly)
        stdout, stderr, rc = await self._run_command(
            ["osslsigncode", "verify", path], timeout=30
        )
        if rc != -1:  # command found
            sign_info["tool"] = "osslsigncode"
            sign_info["raw_output"] = (stdout + stderr)[:3000]
            if "Signature verification: ok" in stdout or rc == 0:
                sign_info["signed"] = True
                sign_info["verified"] = True
            elif "MISMATCH" in stdout.upper() or "FAILED" in stdout.upper():
                sign_info["signed"] = True
                sign_info["verified"] = False
            # Parse cert details
            issuer_m = re.search(r"Issuer\s*:\s*(.+)", stdout)
            if issuer_m:
                sign_info["issuer"] = issuer_m.group(1).strip()
            subject_m = re.search(r"Subject\s*:\s*(.+)", stdout)
            if subject_m:
                sign_info["subject"] = subject_m.group(1).strip()
            serial_m = re.search(r"Serial\s*:\s*(.+)", stdout)
            if serial_m:
                sign_info["serial"] = serial_m.group(1).strip()
            # Check for self-signed
            if sign_info.get("issuer") and sign_info.get("subject"):
                sign_info["self_signed"] = sign_info["issuer"] == sign_info["subject"]
        else:
            # Try sigcheck (Sysinternals, if on Windows/Wine)
            stdout, stderr, rc = await self._run_command(
                ["sigcheck", "-nobanner", path], timeout=30
            )
            if rc != -1:
                sign_info["tool"] = "sigcheck"
                sign_info["raw_output"] = stdout[:3000]
                if "Signed" in stdout:
                    sign_info["signed"] = "Signed" in stdout and "Unsigned" not in stdout
                publisher_m = re.search(r"Publisher:\s*(.+)", stdout)
                if publisher_m:
                    sign_info["subject"] = publisher_m.group(1).strip()
            else:
                # Last resort: check PE for certificate table via pefile
                if HAS_PEFILE:
                    try:
                        pe = pefile.PE(path, fast_load=True)
                        pe.parse_data_directories(
                            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                        )
                        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY:
                            sign_info["signed"] = True
                            sign_info["note"] = "Certificate table present but not verified (no verification tool)"
                        pe.close()
                    except Exception:
                        pass
                sign_info["tool"] = "pefile_basic"

        result.raw_output["pe_signature"] = sign_info

        # Findings
        if not sign_info["signed"]:
            result.findings.append(
                ModuleFinding(
                    title="Unsigned PE Binary",
                    description="The binary is not digitally signed. Cannot verify publisher identity or integrity.",
                    severity=FindingSeverity.MEDIUM,
                    category="binary_analysis",
                    evidence="No Authenticode signature found.",
                    impact="Unsigned binaries could be tampered with or replaced by an attacker.",
                    remediation="Code-sign the binary with a valid certificate from a trusted CA.",
                    cwe_id="CWE-353",
                    cvss_score=5.0,
                    confidence=0.9,
                )
            )
        else:
            if sign_info.get("verified") is False:
                result.findings.append(
                    ModuleFinding(
                        title="Invalid Code Signature",
                        description="Binary has a digital signature but verification failed — "
                        "binary may have been tampered with.",
                        severity=FindingSeverity.HIGH,
                        category="binary_analysis",
                        evidence=sign_info.get("raw_output", "")[:500],
                        impact="Signature mismatch indicates binary modification after signing.",
                        remediation="Obtain the original binary from a trusted source.",
                        cwe_id="CWE-354",
                        cvss_score=8.0,
                        confidence=0.9,
                    )
                )

            if sign_info.get("self_signed"):
                result.findings.append(
                    ModuleFinding(
                        title="Self-Signed Code Certificate",
                        description=f"Binary is signed with a self-signed certificate: "
                        f"{sign_info.get('subject', 'unknown')}",
                        severity=FindingSeverity.MEDIUM,
                        category="binary_analysis",
                        evidence=f"Issuer: {sign_info.get('issuer')}\nSubject: {sign_info.get('subject')}",
                        impact="Self-signed certs provide no third-party identity verification.",
                        remediation="Use a certificate from a trusted CA.",
                        cwe_id="CWE-295",
                        cvss_score=5.3,
                        confidence=0.85,
                    )
                )

            if sign_info.get("subject"):
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.CERTIFICATE,
                        value=sign_info["subject"],
                        metadata={
                            "issuer": sign_info.get("issuer", ""),
                            "serial": sign_info.get("serial", ""),
                            "self_signed": sign_info.get("self_signed", False),
                        },
                    )
                )

    async def _check_jar_signature(self, path: str, result: ModuleResult) -> None:
        """Check JAR signing via META-INF/*.SF and jarsigner."""
        sign_info: dict[str, Any] = {"signed": False}

        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                sf_files = [n for n in names if n.startswith("META-INF/") and n.upper().endswith(".SF")]
                rsa_files = [n for n in names if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
                sign_info["sf_files"] = sf_files
                sign_info["cert_files"] = rsa_files
                sign_info["signed"] = len(sf_files) > 0

                if sf_files:
                    sf_content = zf.read(sf_files[0]).decode(errors="replace")
                    sign_info["sf_content_snippet"] = sf_content[:1000]
                    created_m = re.search(r"Created-By:\s*(.+)", sf_content)
                    if created_m:
                        sign_info["created_by"] = created_m.group(1).strip()

        except Exception as exc:
            result.error = f"JAR read error: {exc}"
            return

        # Try jarsigner verify
        stdout, stderr, rc = await self._run_command(
            ["jarsigner", "-verify", "-verbose", "-certs", path], timeout=30
        )
        if rc != -1:
            sign_info["jarsigner_output"] = (stdout + stderr)[:3000]
            if "jar verified" in stdout.lower():
                sign_info["verified"] = True
            elif "jar is unsigned" in stdout.lower():
                sign_info["signed"] = False
                sign_info["verified"] = False
            else:
                sign_info["verified"] = False

            # Extract cert info
            cn_m = re.search(r"CN=([^,\n]+)", stdout)
            if cn_m:
                sign_info["subject_cn"] = cn_m.group(1).strip()
            issuer_m = re.search(r"Issuer:\s*(.+)", stdout)
            if issuer_m:
                sign_info["issuer"] = issuer_m.group(1).strip()
            expires_m = re.search(r"until:\s*(.+)", stdout)
            if expires_m:
                sign_info["expires"] = expires_m.group(1).strip()

        result.raw_output["jar_signature"] = sign_info

        if not sign_info["signed"]:
            result.findings.append(
                ModuleFinding(
                    title="Unsigned JAR Archive",
                    description="JAR file has no digital signature. Cannot verify publisher or integrity.",
                    severity=FindingSeverity.MEDIUM,
                    category="binary_analysis",
                    evidence="No .SF files in META-INF/",
                    impact="Unsigned JARs can be tampered with silently.",
                    remediation="Sign the JAR with jarsigner using a trusted certificate.",
                    cwe_id="CWE-353",
                    cvss_score=5.0,
                    confidence=0.9,
                )
            )
        else:
            if sign_info.get("verified") is False:
                result.findings.append(
                    ModuleFinding(
                        title="Invalid JAR Signature",
                        description="JAR is signed but verification failed.",
                        severity=FindingSeverity.HIGH,
                        category="binary_analysis",
                        evidence=sign_info.get("jarsigner_output", "")[:500],
                        impact="Signature mismatch indicates possible tampering.",
                        remediation="Obtain original from trusted source.",
                        cwe_id="CWE-354",
                        cvss_score=8.0,
                        confidence=0.85,
                    )
                )

            if sign_info.get("subject_cn"):
                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.CERTIFICATE,
                        value=sign_info["subject_cn"],
                        metadata={
                            "issuer": sign_info.get("issuer", ""),
                            "expires": sign_info.get("expires", ""),
                            "type": "jar_signing_cert",
                        },
                    )
                )

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)

        if not Path(file_path).exists():
            result.error = f"File not found: {file_path}"
            return result

        ftype = _detect_file_type(file_path)

        if progress_callback:
            await progress_callback(f"Checking code signature ({ftype})...")

        if ftype in ("pe", "dotnet"):
            await self._check_pe_signature(file_path, result)
        elif ftype == "jar":
            await self._check_jar_signature(file_path, result)
        else:
            # Try both
            await self._check_pe_signature(file_path, result)
            if result.error or not result.raw_output:
                result.error = None
                result.raw_output = {}
                await self._check_jar_signature(file_path, result)

        return result


# ---------------------------------------------------------------------------
# Module 4: PackingDetectModule
# ---------------------------------------------------------------------------

# Known packer signatures: (name, offset_or_None, byte_sequence)
_PACKER_SIGS: list[tuple[str, int | None, bytes]] = [
    ("UPX", 0, b"UPX!"),
    ("UPX", None, b"UPX0"),
    ("UPX", None, b"UPX1"),
    ("ASPack", None, b".aspack"),
    ("ASPack", None, b".adata"),
    ("PECompact", None, b"PEC2"),
    ("NSPack", None, b".nsp0"),
    ("NSPack", None, b".nsp1"),
    ("Themida", None, b".themida"),
    ("Themida", None, b"WinLicen"),
    ("VMProtect", None, b".vmp0"),
    ("VMProtect", None, b".vmp1"),
    ("VMProtect", None, b"VMProtect"),
    ("Enigma", None, b".enigma1"),
    ("Enigma", None, b".enigma2"),
    ("Armadillo", None, b".arma"),
    ("MPRESS", None, b".MPRESS1"),
    ("MPRESS", None, b".MPRESS2"),
    ("Petite", None, b".petite"),
]

# .NET-specific obfuscator signatures (in strings)
_DOTNET_OBFUSCATORS: list[tuple[str, str]] = [
    ("ConfuserEx", "ConfuserEx"),
    ("Confuser", "Confuser v"),
    (".NET Reactor", "Eziriz .NET Reactor"),
    (".NET Reactor", ".NetReactor"),
    ("Dotfuscator", "Dotfuscator"),
    ("SmartAssembly", "SmartAssembly"),
    ("Obfuscar", "Obfuscar"),
    ("Crypto Obfuscator", "CryptoObfuscator"),
    ("Babel", "Babel Obfuscator"),
    ("Agile.NET", "Agile.NET"),
    ("Spices.Net", "Spices.Net"),
    ("ILProtector", "ILProtector"),
    ("MaxtoCode", "MaxtoCode"),
]

# Java-specific obfuscator signatures
_JAVA_OBFUSCATORS: list[tuple[str, str]] = [
    ("ProGuard", "proguard"),
    ("DexGuard", "dexguard"),
    ("Allatori", "allatori"),
    ("Zelix KlassMaster", "ZKM"),
    ("yGuard", "yguard"),
    ("JBCO", "JBCO"),
    ("Stringer", "stringer"),
]


class PackingDetectModule(BaseModule):
    """Detect packers, obfuscators, and measure section entropy."""

    @property
    def name(self) -> str:
        return "thick_packing"

    @property
    def display_name(self) -> str:
        return "Packer Detection"

    @property
    def description(self) -> str:
        return "Detect binary packers, .NET/Java obfuscators, and high-entropy sections"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "binary_analysis"

    @property
    def timeout(self) -> int:
        return 60

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)

        if not Path(file_path).exists():
            result.error = f"File not found: {file_path}"
            return result

        ftype = _detect_file_type(file_path)

        if progress_callback:
            await progress_callback("Scanning for packers and obfuscators...")

        detected_packers: list[dict[str, Any]] = []

        # ---- Read raw bytes for signature scan ----
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except Exception as exc:
            result.error = f"Cannot read binary: {exc}"
            return result

        # Binary packer signatures
        for packer_name, offset, sig in _PACKER_SIGS:
            if offset is not None:
                if raw[offset:offset + len(sig)] == sig:
                    detected_packers.append({
                        "name": packer_name,
                        "evidence": f"Signature '{sig.decode(errors='replace')}' at offset {offset}",
                        "type": "packer",
                    })
            else:
                idx = raw.find(sig)
                if idx != -1:
                    detected_packers.append({
                        "name": packer_name,
                        "evidence": f"Signature '{sig.decode(errors='replace')}' at offset {idx}",
                        "type": "packer",
                    })

        # .NET obfuscator detection
        if ftype == "dotnet":
            raw_str = raw.decode(errors="replace")
            for obf_name, signature in _DOTNET_OBFUSCATORS:
                if signature.lower() in raw_str.lower():
                    detected_packers.append({
                        "name": obf_name,
                        "evidence": f"String '{signature}' found in binary",
                        "type": "obfuscator",
                    })

        # Java obfuscator detection
        if ftype == "jar":
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    all_names = "\n".join(zf.namelist())
                    manifest_text = ""
                    if "META-INF/MANIFEST.MF" in zf.namelist():
                        manifest_text = zf.read("META-INF/MANIFEST.MF").decode(errors="replace")

                    search_text = all_names + "\n" + manifest_text
                    for obf_name, signature in _JAVA_OBFUSCATORS:
                        if signature.lower() in search_text.lower():
                            detected_packers.append({
                                "name": obf_name,
                                "evidence": f"Indicator '{signature}' found in JAR",
                                "type": "obfuscator",
                            })

                    # ProGuard: look for very short class names (a.class, b.class)
                    short_classes = [n for n in zf.namelist()
                                    if n.endswith(".class") and "/" in n
                                    and len(n.split("/")[-1]) <= 7]  # e.g., "a.class"
                    if len(short_classes) > 20:
                        detected_packers.append({
                            "name": "ProGuard (likely)",
                            "evidence": f"{len(short_classes)} class files with obfuscated names",
                            "type": "obfuscator",
                        })
            except Exception:
                pass

        # ---- Section entropy analysis (PE) ----
        section_entropies: list[dict[str, Any]] = []
        high_entropy_sections: list[dict[str, Any]] = []

        if ftype in ("pe", "dotnet") and HAS_PEFILE:
            try:
                pe = pefile.PE(file_path, fast_load=False)
                for sec in pe.sections:
                    sec_name = sec.Name.rstrip(b"\x00").decode(errors="replace")
                    data = sec.get_data()
                    ent = _shannon_entropy(data)
                    sec_info = {
                        "name": sec_name,
                        "entropy": round(ent, 3),
                        "raw_size": sec.SizeOfRawData,
                        "virtual_size": sec.Misc_VirtualSize,
                    }
                    section_entropies.append(sec_info)
                    if ent > 7.0 and sec.SizeOfRawData > 1024:
                        high_entropy_sections.append(sec_info)
                pe.close()
            except Exception as exc:
                logger.debug("PE section entropy scan failed: %s", exc)
        elif ftype in ("pe", "dotnet"):
            # Without pefile, calculate overall file entropy
            ent = _shannon_entropy(raw)
            section_entropies.append({
                "name": "(whole file)",
                "entropy": round(ent, 3),
                "raw_size": len(raw),
            })
            if ent > 7.0:
                high_entropy_sections.append(section_entropies[0])

        # For JAR, calculate overall entropy
        if ftype == "jar":
            ent = _shannon_entropy(raw)
            section_entropies.append({
                "name": "(whole archive)",
                "entropy": round(ent, 3),
                "raw_size": len(raw),
            })
            # JAR is ZIP (compressed), so high entropy is normal; flag only > 7.9
            if ent > 7.9:
                high_entropy_sections.append(section_entropies[0])

        # Deduplicate packers by name
        seen_names: set[str] = set()
        unique_packers: list[dict[str, Any]] = []
        for p in detected_packers:
            if p["name"] not in seen_names:
                seen_names.add(p["name"])
                unique_packers.append(p)

        result.raw_output["packers_detected"] = unique_packers
        result.raw_output["section_entropies"] = section_entropies
        result.raw_output["high_entropy_sections"] = high_entropy_sections

        # ---- Findings ----
        for packer in unique_packers:
            sev = FindingSeverity.MEDIUM if packer["type"] == "packer" else FindingSeverity.LOW
            desc = (
                f"Detected {packer['type']}: {packer['name']}. "
                "Packed/obfuscated binaries resist static analysis and may hide malicious code."
                if packer["type"] == "packer"
                else f"Detected obfuscator: {packer['name']}. Obfuscation makes reverse engineering harder."
            )
            result.findings.append(
                ModuleFinding(
                    title=f"{packer['type'].title()} Detected: {packer['name']}",
                    description=desc,
                    severity=sev,
                    category="binary_analysis",
                    evidence=packer["evidence"],
                    impact="Packing/obfuscation hides code behavior, complicates auditing, "
                    "and is common in malware.",
                    remediation="Unpack the binary for deeper analysis. Use dynamic analysis as complement.",
                    cwe_id="CWE-116",
                    confidence=0.75,
                )
            )

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=packer["name"],
                    metadata={"type": packer["type"]},
                )
            )

        if high_entropy_sections:
            evidence_lines = [
                f"  {s['name']}: entropy={s['entropy']}, size={s['raw_size']}"
                for s in high_entropy_sections
            ]
            result.findings.append(
                ModuleFinding(
                    title=f"{len(high_entropy_sections)} High-Entropy Section(s) Detected",
                    description="Sections with entropy > 7.0 are likely encrypted or compressed — "
                    "consistent with packing even if no known packer signature was found.",
                    severity=FindingSeverity.MEDIUM,
                    category="binary_analysis",
                    evidence="High entropy sections:\n" + "\n".join(evidence_lines),
                    impact="Encrypted/compressed sections evade static analysis signatures.",
                    remediation="Unpack or decrypt sections. Use dynamic analysis.",
                    confidence=0.7,
                )
            )

        if not unique_packers and not high_entropy_sections:
            result.findings.append(
                ModuleFinding(
                    title="No Packing or Obfuscation Detected",
                    description="No known packer signatures found and section entropy is normal.",
                    severity=FindingSeverity.INFO,
                    category="binary_analysis",
                    evidence="No packer signatures matched. "
                    + (f"Max section entropy: {max(s['entropy'] for s in section_entropies):.3f}"
                       if section_entropies else "No sections analysed."),
                    impact="Binary is likely not packed — static analysis should be effective.",
                    remediation="Proceed with static analysis.",
                    confidence=0.8,
                )
            )

        return result
