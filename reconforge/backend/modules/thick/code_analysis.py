"""Thick-client code analysis modules — decompilation, secret scanning, endpoint extraction, config parsing."""
from __future__ import annotations

import configparser
import json
import logging
import math
import os
import re
import string
import tempfile
import zipfile
from collections import Counter
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

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count
    )


def _detect_binary_type(file_path: str) -> str:
    """Return 'dotnet', 'jar', or 'native' based on magic bytes / extension."""
    ext = Path(file_path).suffix.lower()
    if ext in (".jar", ".war", ".ear"):
        return "jar"
    if ext in (".exe", ".dll"):
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
            # PE with .NET metadata marker
            if b"MZ" in header[:2]:
                # Quick heuristic: look for .NET metadata signature deeper
                with open(file_path, "rb") as f:
                    chunk = f.read(8192)
                if b"mscoree.dll" in chunk or b"_CorExeMain" in chunk or b"_CorDllMain" in chunk:
                    return "dotnet"
            return "native"
        except OSError:
            return "native"
    if ext in (".msi", ".sys"):
        return "native"
    return "native"


def _collect_source_files(directory: str, extensions: tuple[str, ...] = (".cs", ".java", ".kt", ".vb", ".il", ".js", ".ts", ".py", ".xml", ".json", ".config", ".properties", ".yml", ".yaml")) -> list[str]:
    """Walk a directory and return paths matching given extensions."""
    results: list[str] = []
    try:
        for root, _dirs, files in os.walk(directory):
            for fn in files:
                if fn.lower().endswith(extensions):
                    results.append(os.path.join(root, fn))
    except OSError:
        pass
    return results


def _extract_strings_from_binary(file_path: str, min_len: int = 6) -> list[str]:
    """Python-based string extraction (portable fallback)."""
    results: list[str] = []
    printable = set(string.printable) - set("\t\n\r\x0b\x0c")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        current: list[str] = []
        for byte in data:
            ch = chr(byte) if byte < 128 else ""
            if ch in printable:
                current.append(ch)
            else:
                if len(current) >= min_len:
                    results.append("".join(current))
                current = []
        if len(current) >= min_len:
            results.append("".join(current))
    except OSError:
        pass
    return results


# ===================================================================
# Module 1: ThickDecompileModule
# ===================================================================

class ThickDecompileModule(BaseModule):
    """Decompile .NET / JAR thick-client binaries; fall back to strings for native."""

    @property
    def name(self) -> str:
        return "thick_decompile"

    @property
    def display_name(self) -> str:
        return "Thick Client Decompile"

    @property
    def description(self) -> str:
        return "Decompile .NET/JAR binaries using ILSpy, CFR, or jadx; extract strings for native"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 300

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)
        binary_type = _detect_binary_type(file_path)
        base_name = Path(file_path).stem
        out_dir = os.path.join(settings.decompiled_dir, base_name)
        os.makedirs(out_dir, exist_ok=True)

        result.raw_output["binary_type"] = binary_type
        result.raw_output["output_dir"] = out_dir

        if binary_type == "dotnet":
            success = await self._decompile_dotnet(file_path, out_dir, result, progress_callback)
        elif binary_type == "jar":
            success = await self._decompile_jar(file_path, out_dir, result, progress_callback)
        else:
            success = await self._strings_fallback(file_path, out_dir, result, progress_callback)

        # Count decompiled files
        decompiled_files = _collect_source_files(out_dir)
        result.raw_output["decompiled_file_count"] = len(decompiled_files)

        sev = FindingSeverity.INFO
        desc_extra = ""
        if not success:
            sev = FindingSeverity.LOW
            desc_extra = " Decompilation had errors — coverage may be partial."

        result.findings.append(
            ModuleFinding(
                title=f"Decompilation Complete ({binary_type})",
                description=f"Decompiled {Path(file_path).name} ({binary_type}) to {out_dir}. "
                f"{len(decompiled_files)} source file(s) recovered.{desc_extra}",
                severity=sev,
                category="code_analysis",
                evidence=f"Binary type: {binary_type}\nOutput dir: {out_dir}\n"
                f"Files recovered: {len(decompiled_files)}",
                impact="Decompiled source enables static analysis of the application.",
                remediation="Apply obfuscation and anti-tampering to release builds.",
                confidence=0.95,
            )
        )

        result.assets.append(
            ModuleAsset(
                asset_type=AssetType.FILE,
                value=out_dir,
                metadata={"type": "decompiled_source", "binary_type": binary_type, "file_count": len(decompiled_files)},
            )
        )

        return result

    async def _decompile_dotnet(self, file_path: str, out_dir: str, result: ModuleResult, progress_callback: Callable | None) -> bool:
        """Decompile .NET binary using ilspycmd, then ildasm fallback."""
        if progress_callback:
            await progress_callback("Trying ILSpy CLI (ilspycmd)...")

        stdout, stderr, rc = await self._run_command(
            ["ilspycmd", "-p", "-o", out_dir, file_path], timeout=180
        )
        if rc == 0:
            result.raw_output["decompiler"] = "ilspycmd"
            result.raw_output["decompiler_output"] = stdout[:2000]
            return True

        # Fallback: ildasm
        if progress_callback:
            await progress_callback("ILSpy unavailable, trying ildasm...")

        il_file = os.path.join(out_dir, Path(file_path).stem + ".il")
        stdout, stderr, rc = await self._run_command(
            ["ildasm", file_path, f"/output={il_file}", "/text"], timeout=120
        )
        if rc == 0 and os.path.exists(il_file):
            result.raw_output["decompiler"] = "ildasm"
            return True

        # Fallback: dotnet-ildasm
        stdout, stderr, rc = await self._run_command(
            ["dotnet-ildasm", file_path, "-o", il_file], timeout=120
        )
        if rc == 0 and os.path.exists(il_file):
            result.raw_output["decompiler"] = "dotnet-ildasm"
            return True

        # Last fallback: strings
        result.raw_output["decompiler"] = "strings_fallback"
        return await self._strings_fallback(file_path, out_dir, result, progress_callback)

    async def _decompile_jar(self, file_path: str, out_dir: str, result: ModuleResult, progress_callback: Callable | None) -> bool:
        """Decompile JAR using CFR or jadx."""
        if progress_callback:
            await progress_callback("Trying CFR decompiler...")

        stdout, stderr, rc = await self._run_command(
            ["java", "-jar", "/usr/share/cfr/cfr.jar", file_path, "--outputdir", out_dir],
            timeout=180,
        )
        if rc == 0:
            result.raw_output["decompiler"] = "cfr"
            return True

        # Try cfr via command name
        stdout, stderr, rc = await self._run_command(
            ["cfr", file_path, "--outputdir", out_dir], timeout=180
        )
        if rc == 0:
            result.raw_output["decompiler"] = "cfr"
            return True

        # Fallback: jadx
        if progress_callback:
            await progress_callback("Trying jadx decompiler...")

        stdout, stderr, rc = await self._run_command(
            ["jadx", "-d", out_dir, "--no-res", file_path], timeout=180
        )
        if rc == 0:
            result.raw_output["decompiler"] = "jadx"
            return True

        # Last fallback: extract JAR (it's a ZIP) + strings
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                zf.extractall(out_dir)
            result.raw_output["decompiler"] = "jar_extract"
            return True
        except Exception as e:
            result.raw_output["decompiler"] = "strings_fallback"
            result.raw_output["extract_error"] = str(e)
            return await self._strings_fallback(file_path, out_dir, result, progress_callback)

    async def _strings_fallback(self, file_path: str, out_dir: str, result: ModuleResult, progress_callback: Callable | None) -> bool:
        """Extract raw strings as last resort."""
        if progress_callback:
            await progress_callback("Extracting raw strings from binary...")

        # Try system strings command first
        strings_file = os.path.join(out_dir, "raw_strings.txt")
        stdout, stderr, rc = await self._run_command(
            ["strings", "-a", "-n", "6", file_path], timeout=60
        )
        if rc == 0 and stdout:
            try:
                with open(strings_file, "w", errors="replace") as f:
                    f.write(stdout)
                result.raw_output["decompiler"] = "strings"
                return True
            except OSError:
                pass

        # Python fallback
        extracted = _extract_strings_from_binary(file_path)
        if extracted:
            try:
                with open(strings_file, "w", errors="replace") as f:
                    f.write("\n".join(extracted))
                result.raw_output["decompiler"] = "python_strings"
                return True
            except OSError:
                pass

        return False


# ===================================================================
# Module 2: ThickSecretScanModule
# ===================================================================

# 40+ secret patterns adapted for .NET/Java thick clients
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    # AWS
    ("AWS Access Key ID", re.compile(r"(?:^|['\"\s=:])?(AKIA[0-9A-Z]{16})(?:['\"\s,;]|$)"), FindingSeverity.CRITICAL, "CWE-798"),
    ("AWS Secret Access Key", re.compile(r"(?:aws_secret_access_key|secret_?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), FindingSeverity.CRITICAL, "CWE-798"),
    # Google
    ("Google API Key", re.compile(r"(?:^|['\"\s=:])?(AIza[0-9A-Za-z_-]{35})(?:['\"\s,;]|$)"), FindingSeverity.HIGH, "CWE-798"),
    ("Google OAuth Client Secret", re.compile(r"client_secret['\"]?\s*[=:]\s*['\"]([A-Za-z0-9_-]{24})['\"]", re.I), FindingSeverity.HIGH, "CWE-798"),
    # Firebase
    ("Firebase URL", re.compile(r"(https://[a-z0-9-]+\.firebaseio\.com)", re.I), FindingSeverity.MEDIUM, "CWE-200"),
    ("Firebase Server Key", re.compile(r"(?:server_?key|firebase_?key)\s*[=:]\s*['\"]?(AAAA[A-Za-z0-9_-]{7,}:APA[A-Za-z0-9_-]{100,})['\"]?", re.I), FindingSeverity.CRITICAL, "CWE-798"),
    # Stripe
    ("Stripe Secret Key", re.compile(r"(sk_live_[0-9a-zA-Z]{24,})"), FindingSeverity.CRITICAL, "CWE-798"),
    ("Stripe Publishable Key", re.compile(r"(pk_live_[0-9a-zA-Z]{24,})"), FindingSeverity.MEDIUM, "CWE-200"),
    # Twilio
    ("Twilio API Key", re.compile(r"(SK[0-9a-fA-F]{32})"), FindingSeverity.HIGH, "CWE-798"),
    ("Twilio Auth Token", re.compile(r"(?:twilio|auth_token)\s*[=:]\s*['\"]?([0-9a-f]{32})['\"]?", re.I), FindingSeverity.HIGH, "CWE-798"),
    # Slack
    ("Slack Bot Token", re.compile(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})"), FindingSeverity.HIGH, "CWE-798"),
    ("Slack User Token", re.compile(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})"), FindingSeverity.HIGH, "CWE-798"),
    ("Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)"), FindingSeverity.HIGH, "CWE-798"),
    # GitHub
    ("GitHub PAT (ghp)", re.compile(r"(ghp_[A-Za-z0-9]{36,})"), FindingSeverity.HIGH, "CWE-798"),
    ("GitHub OAuth Token (gho)", re.compile(r"(gho_[A-Za-z0-9]{36,})"), FindingSeverity.HIGH, "CWE-798"),
    ("GitHub App Token (ghu)", re.compile(r"(ghu_[A-Za-z0-9]{36,})"), FindingSeverity.HIGH, "CWE-798"),
    ("GitHub Fine-Grained Token", re.compile(r"(github_pat_[A-Za-z0-9_]{80,})"), FindingSeverity.HIGH, "CWE-798"),
    # Private keys
    ("RSA Private Key", re.compile(r"(-----BEGIN RSA PRIVATE KEY-----)"), FindingSeverity.CRITICAL, "CWE-321"),
    ("EC Private Key", re.compile(r"(-----BEGIN EC PRIVATE KEY-----)"), FindingSeverity.CRITICAL, "CWE-321"),
    ("Generic Private Key", re.compile(r"(-----BEGIN PRIVATE KEY-----)"), FindingSeverity.CRITICAL, "CWE-321"),
    ("PGP Private Key", re.compile(r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"), FindingSeverity.CRITICAL, "CWE-321"),
    # JWT
    ("JWT Token", re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"), FindingSeverity.HIGH, "CWE-798"),
    # Basic Auth
    ("Basic Auth Header", re.compile(r"(?:Authorization|auth)\s*[=:]\s*['\"]?Basic\s+([A-Za-z0-9+/=]{10,})['\"]?", re.I), FindingSeverity.HIGH, "CWE-798"),
    # Database URLs
    ("JDBC Connection String", re.compile(r"(jdbc:[a-z]+://[^\s'\"]{10,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    ("MongoDB Connection String", re.compile(r"(mongodb(?:\+srv)?://[^\s'\"]{10,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    ("Redis Connection String", re.compile(r"(redis://[^\s'\"]{10,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    ("PostgreSQL Connection String", re.compile(r"(postgres(?:ql)?://[^\s'\"]{10,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    ("MySQL Connection String", re.compile(r"(mysql://[^\s'\"]{10,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    # ODBC
    ("ODBC Connection String", re.compile(r"(?:connection\s*string|data\s*source)\s*[=:]\s*['\"]?([^'\";\n]{10,}(?:password|pwd)[^'\";\n]*)['\"]?", re.I), FindingSeverity.HIGH, "CWE-798"),
    # .NET specific
    ("AppSettings Secret", re.compile(r"<add\s+key\s*=\s*['\"](?:[^'\"]*(?:secret|password|key|token|apikey|api_key|connectionstring|conn_str)[^'\"]*)['\"].*?value\s*=\s*['\"]([^'\"]+)['\"]", re.I), FindingSeverity.HIGH, "CWE-798"),
    (".NET ConnectionString", re.compile(r"<connectionStrings>.*?connectionString\s*=\s*['\"]([^'\"]+)['\"]", re.I | re.S), FindingSeverity.HIGH, "CWE-798"),
    ("ConfigurationManager Secret", re.compile(r'ConfigurationManager\.AppSettings\[\s*["\']([^"\']*(?:key|secret|password|token)[^"\']*)["\']', re.I), FindingSeverity.MEDIUM, "CWE-798"),
    # Spring/Java specific
    ("Spring Property Secret", re.compile(r"(?:spring\.[a-z.]+(?:password|secret|key|token))\s*=\s*(.{4,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    ("application.properties Secret", re.compile(r"(?:password|secret|token|apikey|api[_.]key)\s*=\s*([^\s#]{4,})", re.I), FindingSeverity.HIGH, "CWE-798"),
    # Generic password/secret assignments
    ("Hardcoded Password (assignment)", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I), FindingSeverity.HIGH, "CWE-798"),
    ("Hardcoded Secret (assignment)", re.compile(r'(?:secret|secret_key|secretkey)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I), FindingSeverity.HIGH, "CWE-798"),
    ("Hardcoded Token (assignment)", re.compile(r'(?:token|auth_token|access_token|api_token)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), FindingSeverity.HIGH, "CWE-798"),
    ("Hardcoded API Key (assignment)", re.compile(r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), FindingSeverity.HIGH, "CWE-798"),
    # SendGrid / Mailgun / Mailchimp
    ("SendGrid API Key", re.compile(r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"), FindingSeverity.HIGH, "CWE-798"),
    ("Mailgun API Key", re.compile(r"(key-[0-9a-zA-Z]{32})"), FindingSeverity.HIGH, "CWE-798"),
    ("Mailchimp API Key", re.compile(r"([0-9a-f]{32}-us\d{1,2})"), FindingSeverity.HIGH, "CWE-798"),
    # Azure
    ("Azure Storage Key", re.compile(r"(?:AccountKey|StorageAccountKey)\s*=\s*([A-Za-z0-9+/=]{44,})"), FindingSeverity.CRITICAL, "CWE-798"),
    ("Azure Connection String", re.compile(r"(DefaultEndpointsProtocol=https?;AccountName=[^\s;]+;AccountKey=[A-Za-z0-9+/=]+)", re.I), FindingSeverity.CRITICAL, "CWE-798"),
    ("Azure SAS Token", re.compile(r"(\?sv=\d{4}-\d{2}-\d{2}&[^\s'\"]{20,})"), FindingSeverity.HIGH, "CWE-798"),
    # Heroku
    ("Heroku API Key", re.compile(r"(?:heroku.*key|HEROKU_API_KEY)\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", re.I), FindingSeverity.HIGH, "CWE-798"),
    # Square
    ("Square Access Token", re.compile(r"(sq0atp-[0-9A-Za-z_-]{22,})"), FindingSeverity.HIGH, "CWE-798"),
    # NPM
    ("NPM Token", re.compile(r"(//registry\.npmjs\.org/:_authToken=\S+)"), FindingSeverity.HIGH, "CWE-798"),
    # NuGet
    ("NuGet API Key", re.compile(r"(?:nuget|api_?key)\s*[=:]\s*['\"]?([a-z0-9]{46})['\"]?", re.I), FindingSeverity.HIGH, "CWE-798"),
]


class ThickSecretScanModule(BaseModule):
    """Scan decompiled thick-client code and strings for hardcoded secrets."""

    @property
    def name(self) -> str:
        return "thick_secrets"

    @property
    def display_name(self) -> str:
        return "Thick Client Secret Scan"

    @property
    def description(self) -> str:
        return "Scan decompiled source and raw strings for API keys, passwords, tokens, and other secrets"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "code_analysis"

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
        file_path = scan_context.get("file_path", target)
        base_name = Path(file_path).stem
        decompiled_dir = os.path.join(settings.decompiled_dir, base_name)

        # Collect text to scan: decompiled files + raw strings
        texts_to_scan: list[tuple[str, str]] = []  # (source_label, content)

        if progress_callback:
            await progress_callback("Collecting source files for secret scan...")

        # Decompiled source files
        if os.path.isdir(decompiled_dir):
            for fpath in _collect_source_files(decompiled_dir):
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read(500_000)  # Cap per file
                    rel = os.path.relpath(fpath, decompiled_dir)
                    texts_to_scan.append((rel, content))
                except OSError:
                    continue

        # Raw strings from binary
        if progress_callback:
            await progress_callback("Extracting raw strings from binary...")

        stdout, _, rc = await self._run_command(["strings", "-a", "-n", "8", file_path], timeout=60)
        if rc == 0 and stdout:
            texts_to_scan.append(("raw_strings", stdout[:2_000_000]))
        else:
            raw = _extract_strings_from_binary(file_path, min_len=8)
            if raw:
                texts_to_scan.append(("raw_strings", "\n".join(raw)))

        if not texts_to_scan:
            result.error = "No source or strings available to scan"
            return result

        if progress_callback:
            await progress_callback(f"Scanning {len(texts_to_scan)} sources against {len(_SECRET_PATTERNS)} patterns...")

        seen_secrets: set[str] = set()
        total_found = 0

        for source_label, content in texts_to_scan:
            for pattern_name, pattern_re, severity, cwe in _SECRET_PATTERNS:
                for m in pattern_re.finditer(content):
                    secret_value = m.group(1) if m.lastindex else m.group(0)
                    # Deduplicate
                    dedup_key = f"{pattern_name}:{secret_value[:60]}"
                    if dedup_key in seen_secrets:
                        continue
                    seen_secrets.add(dedup_key)
                    total_found += 1

                    # Context: grab surrounding lines
                    start = max(0, m.start() - 100)
                    end = min(len(content), m.end() + 100)
                    context_snippet = content[start:end].strip()

                    # Entropy-based confidence scoring
                    entropy = _shannon_entropy(secret_value)
                    confidence = 0.6
                    if entropy > 4.0:
                        confidence = 0.9
                    elif entropy > 3.0:
                        confidence = 0.8
                    elif entropy > 2.0:
                        confidence = 0.7
                    # Boost confidence for well-known prefixes
                    if any(secret_value.startswith(pfx) for pfx in (
                        "AKIA", "AIza", "sk_live", "pk_live", "ghp_", "gho_", "xoxb-", "xoxp-",
                        "SG.", "eyJ", "-----BEGIN", "SK", "sq0atp-", "github_pat_",
                    )):
                        confidence = min(confidence + 0.1, 0.98)

                    # Mask the secret for evidence
                    if len(secret_value) > 10:
                        masked = secret_value[:6] + "..." + secret_value[-4:]
                    else:
                        masked = secret_value[:3] + "***"

                    result.findings.append(
                        ModuleFinding(
                            title=f"{pattern_name} Found",
                            description=f"Detected {pattern_name} in {source_label}.",
                            severity=severity,
                            category="code_analysis",
                            evidence=f"Pattern: {pattern_name}\nSource: {source_label}\n"
                            f"Value (masked): {masked}\nEntropy: {entropy:.2f}\n\n"
                            f"Context:\n{context_snippet[:500]}",
                            raw_data={"secret_masked": masked, "source": source_label, "entropy": entropy},
                            impact="Hardcoded secrets can be extracted from the binary and used to "
                            "access backend services, databases, or cloud resources.",
                            remediation="Remove hardcoded secrets. Use environment variables, secure "
                            "vaults (Azure Key Vault, AWS Secrets Manager), or runtime config.",
                            cwe_id=cwe,
                            cvss_score=9.0 if severity == FindingSeverity.CRITICAL else 7.5,
                            owasp_category="M9: Reverse Engineering",
                            confidence=confidence,
                            validation_hint=f"Search binary: strings <file> | grep -i '{secret_value[:8]}'",
                        )
                    )

                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SECRET,
                            value=masked,
                            metadata={
                                "type": pattern_name,
                                "source": source_label,
                                "entropy": round(entropy, 2),
                                "confidence": confidence,
                            },
                        )
                    )

        result.raw_output["total_secrets_found"] = total_found
        result.raw_output["sources_scanned"] = len(texts_to_scan)

        if total_found == 0:
            result.findings.append(
                ModuleFinding(
                    title="No Hardcoded Secrets Detected",
                    description="No secrets detected by pattern matching. Manual review recommended.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence=f"Scanned {len(texts_to_scan)} sources against {len(_SECRET_PATTERNS)} patterns.",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.7,
                )
            )

        return result


# ===================================================================
# Module 3: ThickEndpointModule
# ===================================================================

# URL / IP / hostname extraction patterns
_URL_PATTERN = re.compile(r'(https?://[^\s\'"<>(){}\[\]\\]{8,})', re.I)
_FTP_URL_PATTERN = re.compile(r'(ftps?://[^\s\'"<>(){}\[\]\\]{8,})', re.I)
_IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_HOSTNAME_PATTERN = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b')

# Framework-specific patterns
_HTTPCLIENT_PATTERN = re.compile(r'(?:HttpClient|WebClient|WebRequest|HttpWebRequest)\s*\(?\s*["\']?(https?://[^\s\'"]+)', re.I)
_RESTSHARP_PATTERN = re.compile(r'RestClient\s*\(\s*["\']?(https?://[^\s\'"]+)', re.I)
_OKHTTP_PATTERN = re.compile(r'(?:Request\.Builder|OkHttpClient).*?url\s*\(\s*["\']?(https?://[^\s\'"]+)', re.I | re.S)
_JDBC_PATTERN = re.compile(r'(jdbc:[a-z:]+//[^\s\'"]+)', re.I)
_ODBC_PATTERN = re.compile(r'(?:Data\s*Source|Server)\s*=\s*([^\s;,\'"]+)', re.I)
_WCF_PATTERN = re.compile(r'<endpoint\s+[^>]*address\s*=\s*["\']([^"\']+)["\']', re.I)
_SOAP_PATTERN = re.compile(r'<soap:address\s+location\s*=\s*["\']([^"\']+)["\']', re.I)

# Categorization hints
_ANALYTICS_DOMAINS = {
    "google-analytics.com", "analytics.google.com", "mixpanel.com",
    "amplitude.com", "segment.io", "segment.com", "app.adjust.com",
    "appsflyer.com", "branch.io", "crashlytics.com", "sentry.io",
    "bugsnag.com", "newrelic.com", "datadog-agent.com",
}
_INTERNAL_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
]


class ThickEndpointModule(BaseModule):
    """Extract URLs, IPs, and API endpoints from decompiled thick-client code."""

    @property
    def name(self) -> str:
        return "thick_endpoints"

    @property
    def display_name(self) -> str:
        return "Thick Client Endpoint Extraction"

    @property
    def description(self) -> str:
        return "Extract URLs, IPs, and API endpoints from decompiled code and binary strings"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 90

    def _categorize_url(self, url: str) -> str:
        """Categorize URL by purpose."""
        lower = url.lower()
        try:
            from urllib.parse import urlparse
            parsed = urlparse(lower)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        if any(d in host for d in _ANALYTICS_DOMAINS):
            return "analytics"
        if "api" in host or "/api/" in lower or "/v1/" in lower or "/v2/" in lower or "/v3/" in lower:
            return "api_endpoint"
        if "auth" in lower or "login" in lower or "oauth" in lower or "token" in lower:
            return "authentication"
        if "cdn" in host or "cloudfront" in host or "akamai" in host:
            return "cdn"
        if "s3.amazonaws.com" in host or "blob.core.windows.net" in host or "storage.googleapis.com" in host:
            return "cloud_storage"
        if host.endswith((".microsoft.com", ".windows.net", ".azure.com")):
            return "microsoft_service"
        if host.endswith((".googleapis.com", ".google.com")):
            return "google_service"
        if host.endswith((".amazonaws.com", ".aws.amazon.com")):
            return "aws_service"
        if "update" in lower or "upgrade" in lower or "download" in lower:
            return "update_channel"
        if "localhost" in host or "127.0.0.1" in host:
            return "localhost"
        return "third_party"

    def _is_internal_ip(self, ip: str) -> bool:
        return any(r.match(ip) for r in _INTERNAL_IP_RANGES)

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)
        base_name = Path(file_path).stem
        decompiled_dir = os.path.join(settings.decompiled_dir, base_name)

        # Collect all text
        all_text = ""

        if os.path.isdir(decompiled_dir):
            if progress_callback:
                await progress_callback("Reading decompiled source files...")
            for fpath in _collect_source_files(decompiled_dir):
                try:
                    with open(fpath, "r", errors="replace") as f:
                        all_text += f.read(300_000) + "\n"
                except OSError:
                    continue

        # Raw strings
        if progress_callback:
            await progress_callback("Extracting strings from binary...")
        stdout, _, rc = await self._run_command(["strings", "-a", "-n", "8", file_path], timeout=60)
        if rc == 0 and stdout:
            all_text += stdout
        else:
            raw = _extract_strings_from_binary(file_path, min_len=8)
            all_text += "\n".join(raw)

        if not all_text:
            result.error = "No text available to scan for endpoints"
            return result

        if progress_callback:
            await progress_callback("Extracting URLs and IPs...")

        # --- Extract URLs ---
        urls: set[str] = set()
        for pattern in (_URL_PATTERN, _FTP_URL_PATTERN, _HTTPCLIENT_PATTERN, _RESTSHARP_PATTERN, _OKHTTP_PATTERN, _WCF_PATTERN, _SOAP_PATTERN):
            for m in pattern.finditer(all_text):
                url = m.group(1).rstrip(".,;)'\">")
                urls.add(url)

        # JDBC URLs
        for m in _JDBC_PATTERN.finditer(all_text):
            urls.add(m.group(1).rstrip(".,;)'\">"))

        # --- Extract IPs ---
        ips: set[str] = set()
        for m in _IP_PATTERN.finditer(all_text):
            ip = m.group(1)
            # Validate octets
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                if ip not in ("0.0.0.0", "255.255.255.255"):
                    ips.add(ip)

        # --- Extract ODBC data sources ---
        odbc_hosts: set[str] = set()
        for m in _ODBC_PATTERN.finditer(all_text):
            odbc_hosts.add(m.group(1))

        # --- Categorize and create assets ---
        url_categories: dict[str, list[str]] = {}
        for url in sorted(urls):
            cat = self._categorize_url(url)
            url_categories.setdefault(cat, []).append(url)
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=url,
                    metadata={"category": cat, "source": "thick_client"},
                )
            )

        for ip in sorted(ips):
            is_internal = self._is_internal_ip(ip)
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.IP,
                    value=ip,
                    metadata={"internal": is_internal, "source": "thick_client"},
                )
            )

        for host in sorted(odbc_hosts):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=host,
                    metadata={"category": "database", "type": "odbc", "source": "thick_client"},
                )
            )

        result.raw_output["urls_found"] = len(urls)
        result.raw_output["ips_found"] = len(ips)
        result.raw_output["categories"] = {k: len(v) for k, v in url_categories.items()}

        # --- Findings ---
        internal_ips = [ip for ip in ips if self._is_internal_ip(ip)]
        if internal_ips:
            result.findings.append(
                ModuleFinding(
                    title=f"Internal IP Addresses Exposed ({len(internal_ips)})",
                    description="Internal/private IP addresses found in the binary.",
                    severity=FindingSeverity.LOW,
                    category="code_analysis",
                    evidence="Internal IPs:\n" + "\n".join(f"  {ip}" for ip in sorted(internal_ips)[:20]),
                    impact="Reveals internal network topology to attackers.",
                    remediation="Remove internal IPs from production builds. Use configuration for environment-specific values.",
                    cwe_id="CWE-200",
                    confidence=0.85,
                )
            )

        api_endpoints = url_categories.get("api_endpoint", [])
        if api_endpoints:
            result.findings.append(
                ModuleFinding(
                    title=f"API Endpoints Discovered ({len(api_endpoints)})",
                    description="API endpoint URLs extracted from the binary.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence="API endpoints:\n" + "\n".join(f"  {u}" for u in api_endpoints[:30]),
                    impact="Exposes backend API surface for further testing.",
                    remediation="Ensure all API endpoints enforce proper authentication and authorization.",
                    confidence=0.9,
                )
            )

        auth_endpoints = url_categories.get("authentication", [])
        if auth_endpoints:
            result.findings.append(
                ModuleFinding(
                    title=f"Authentication Endpoints Found ({len(auth_endpoints)})",
                    description="Authentication-related URLs found in the binary.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence="Auth endpoints:\n" + "\n".join(f"  {u}" for u in auth_endpoints[:20]),
                    impact="Authentication endpoints are prime targets for credential attacks.",
                    remediation="Test auth endpoints for brute-force protection, rate limiting, and MFA.",
                    confidence=0.85,
                )
            )

        http_urls = [u for u in urls if u.lower().startswith("http://") and "localhost" not in u.lower() and "127.0.0.1" not in u]
        if http_urls:
            result.findings.append(
                ModuleFinding(
                    title=f"Plaintext HTTP URLs ({len(http_urls)})",
                    description="Non-HTTPS URLs found — traffic can be intercepted.",
                    severity=FindingSeverity.MEDIUM,
                    category="code_analysis",
                    evidence="HTTP URLs:\n" + "\n".join(f"  {u}" for u in http_urls[:20]),
                    impact="Data transmitted over HTTP is visible to network attackers.",
                    remediation="Upgrade all HTTP URLs to HTTPS.",
                    cwe_id="CWE-319",
                    cvss_score=5.3,
                    confidence=0.9,
                )
            )

        update_urls = url_categories.get("update_channel", [])
        if update_urls:
            http_updates = [u for u in update_urls if u.lower().startswith("http://")]
            if http_updates:
                result.findings.append(
                    ModuleFinding(
                        title="Insecure Update Channel (HTTP)",
                        description="Update check URLs use HTTP — supply-chain attack risk.",
                        severity=FindingSeverity.HIGH,
                        category="code_analysis",
                        evidence="HTTP update URLs:\n" + "\n".join(f"  {u}" for u in http_updates[:10]),
                        impact="Attacker on the network can inject malicious updates via MITM.",
                        remediation="Use HTTPS for all update channels. Validate signatures on downloaded updates.",
                        cwe_id="CWE-494",
                        cvss_score=8.1,
                        confidence=0.85,
                    )
                )

        # Summary finding
        result.findings.append(
            ModuleFinding(
                title=f"Endpoint Summary: {len(urls)} URLs, {len(ips)} IPs",
                description=f"Extracted {len(urls)} unique URLs and {len(ips)} IPs from the thick client binary.",
                severity=FindingSeverity.INFO,
                category="code_analysis",
                evidence=f"URLs by category:\n" + "\n".join(
                    f"  {k}: {v}" for k, v in sorted(url_categories.items(), key=lambda x: -len(x[1]))
                ),
                impact="Extracted endpoints define the application's external communication surface.",
                remediation="Review all endpoints for proper security controls.",
                confidence=0.9,
            )
        )

        return result


# ===================================================================
# Module 4: ConfigExtractModule
# ===================================================================

_SENSITIVE_CONFIG_KEYS = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|"
    r"connection[_-]?string|conn[_-]?str|credentials?|auth|client[_-]?secret|"
    r"access[_-]?key|master[_-]?key|encryption[_-]?key|signing[_-]?key|"
    r"database[_-]?url|db[_-]?password|smtp[_-]?password|mail[_-]?password)",
    re.I,
)

_DEBUG_CONFIG_KEYS = re.compile(
    r"(debug|verbose|trace|dev[_-]?mode|staging|test[_-]?mode|"
    r"enable[_-]?debug|log[_-]?level|diagnostics|profiling)",
    re.I,
)


class ConfigExtractModule(BaseModule):
    """Find and parse config files alongside or embedded in thick-client binaries."""

    @property
    def name(self) -> str:
        return "thick_config"

    @property
    def display_name(self) -> str:
        return "Config Extraction"

    @property
    def description(self) -> str:
        return "Extract and analyse configuration files from thick-client binaries and their directories"

    @property
    def target_types(self) -> list[str]:
        return ["thick_client"]

    @property
    def category(self) -> str:
        return "code_analysis"

    @property
    def timeout(self) -> int:
        return 60

    # Config file names to look for
    _CONFIG_FILENAMES = {
        "app.config", "web.config", "appsettings.json", "appsettings.development.json",
        "appsettings.production.json", "application.properties", "application.yml",
        "application.yaml", "config.json", "config.xml", "config.ini", "config.cfg",
        "settings.json", "settings.xml", ".env", "hibernate.cfg.xml",
        "persistence.xml", "log4j.properties", "log4net.config",
        "nlog.config", "packages.config", "nuget.config",
    }

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        file_path = scan_context.get("file_path", target)
        binary_dir = str(Path(file_path).parent)
        base_name = Path(file_path).stem
        decompiled_dir = os.path.join(settings.decompiled_dir, base_name)

        configs_found: list[dict[str, Any]] = []

        # 1. Search alongside the binary
        if progress_callback:
            await progress_callback("Searching for config files alongside binary...")

        for root_dir, _dirs, files in os.walk(binary_dir):
            for fn in files:
                if fn.lower() in self._CONFIG_FILENAMES or fn.lower().endswith(
                    (".config", ".properties", ".yml", ".yaml", ".ini", ".cfg", ".env")
                ):
                    full_path = os.path.join(root_dir, fn)
                    config_data = await self._parse_config_file(full_path, fn)
                    if config_data is not None:
                        configs_found.append({
                            "file": full_path,
                            "name": fn,
                            "source": "filesystem",
                            "data": config_data,
                        })
            # Only scan one level deep alongside binary
            break

        # 2. Search in decompiled output
        if os.path.isdir(decompiled_dir):
            if progress_callback:
                await progress_callback("Searching decompiled output for configs...")
            for root_dir, _dirs, files in os.walk(decompiled_dir):
                for fn in files:
                    if fn.lower() in self._CONFIG_FILENAMES or fn.lower().endswith(
                        (".config", ".properties", ".yml", ".yaml")
                    ):
                        full_path = os.path.join(root_dir, fn)
                        config_data = await self._parse_config_file(full_path, fn)
                        if config_data is not None:
                            configs_found.append({
                                "file": full_path,
                                "name": fn,
                                "source": "decompiled",
                                "data": config_data,
                            })

        # 3. Search inside JAR/ZIP archives
        ext = Path(file_path).suffix.lower()
        if ext in (".jar", ".war", ".ear", ".zip"):
            if progress_callback:
                await progress_callback("Searching inside archive for configs...")
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    for entry in zf.namelist():
                        entry_name = Path(entry).name.lower()
                        if entry_name in self._CONFIG_FILENAMES or entry_name.endswith(
                            (".config", ".properties", ".yml", ".yaml", ".json", ".xml")
                        ):
                            try:
                                raw = zf.read(entry).decode(errors="replace")
                                config_data = self._parse_config_content(entry_name, raw)
                                if config_data is not None:
                                    configs_found.append({
                                        "file": f"{file_path}!{entry}",
                                        "name": entry_name,
                                        "source": "embedded",
                                        "data": config_data,
                                    })
                            except Exception:
                                continue
            except (zipfile.BadZipFile, OSError):
                pass

        result.raw_output["configs_found"] = len(configs_found)

        if not configs_found:
            result.findings.append(
                ModuleFinding(
                    title="No Configuration Files Found",
                    description="No recognisable config files found alongside or inside the binary.",
                    severity=FindingSeverity.INFO,
                    category="code_analysis",
                    evidence="Searched: filesystem, decompiled output, embedded archives",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.8,
                )
            )
            return result

        # Analyse each config
        for cfg in configs_found:
            data = cfg["data"]
            file_label = cfg["file"]
            cfg_name = cfg["name"]

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.FILE,
                    value=file_label,
                    metadata={"type": "config_file", "format": cfg_name, "source": cfg["source"]},
                )
            )

            if not isinstance(data, dict):
                continue

            flat = self._flatten_dict(data)

            # Check for sensitive values
            for key, value in flat.items():
                val_str = str(value).strip()
                if not val_str or val_str.lower() in ("", "null", "none", "false", "true", "0", "1"):
                    continue

                if _SENSITIVE_CONFIG_KEYS.search(key):
                    # Mask the value
                    if len(val_str) > 8:
                        masked = val_str[:4] + "..." + val_str[-3:]
                    else:
                        masked = val_str[:2] + "***"

                    result.findings.append(
                        ModuleFinding(
                            title=f"Sensitive Config Value: {key}",
                            description=f"Config file {cfg_name} contains a sensitive-looking value for '{key}'.",
                            severity=FindingSeverity.HIGH,
                            category="code_analysis",
                            evidence=f"File: {file_label}\nKey: {key}\nValue (masked): {masked}",
                            raw_data={"file": file_label, "key": key, "masked_value": masked},
                            impact="Credentials or secrets in config files can be extracted by anyone with access to the binary.",
                            remediation="Use encrypted config sections, environment variables, or a secrets manager.",
                            cwe_id="CWE-798",
                            cvss_score=7.5,
                            confidence=0.85,
                        )
                    )

                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.SECRET,
                            value=masked,
                            metadata={"key": key, "file": cfg_name, "source": cfg["source"]},
                        )
                    )

                # Check for endpoints in config values
                if re.match(r'https?://', val_str, re.I):
                    result.assets.append(
                        ModuleAsset(
                            asset_type=AssetType.ENDPOINT,
                            value=val_str,
                            metadata={"config_key": key, "file": cfg_name},
                        )
                    )

                # Check for debug/dev mode flags
                if _DEBUG_CONFIG_KEYS.search(key):
                    if val_str.lower() in ("true", "1", "yes", "on", "debug", "verbose", "trace"):
                        result.findings.append(
                            ModuleFinding(
                                title=f"Debug/Dev Mode Enabled: {key}",
                                description=f"Config key '{key}' is set to '{val_str}' in {cfg_name} — debug mode may be active.",
                                severity=FindingSeverity.MEDIUM,
                                category="code_analysis",
                                evidence=f"File: {file_label}\nKey: {key}\nValue: {val_str}",
                                impact="Debug mode may expose verbose errors, stack traces, or internal data.",
                                remediation="Disable debug/dev settings in production builds.",
                                cwe_id="CWE-489",
                                confidence=0.8,
                            )
                        )

        # Summary
        result.findings.append(
            ModuleFinding(
                title=f"Configuration Files Found: {len(configs_found)}",
                description=f"Found {len(configs_found)} configuration file(s) across filesystem, decompiled output, and embedded archives.",
                severity=FindingSeverity.INFO,
                category="code_analysis",
                evidence="Config files:\n" + "\n".join(f"  [{c['source']}] {c['name']}" for c in configs_found),
                impact="Config files may contain secrets, endpoints, and debug settings.",
                remediation="Review all config files and remove sensitive values from distributed binaries.",
                confidence=0.9,
            )
        )

        return result

    async def _parse_config_file(self, file_path: str, filename: str) -> dict[str, Any] | None:
        """Read and parse a config file into a dict."""
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read(500_000)
        except OSError:
            return None
        return self._parse_config_content(filename, content)

    def _parse_config_content(self, filename: str, content: str) -> dict[str, Any] | None:
        """Parse config content by type."""
        lower = filename.lower()

        # JSON
        if lower.endswith(".json"):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return None

        # XML (.config, .xml)
        if lower.endswith((".config", ".xml")):
            return self._parse_xml_config(content)

        # Properties
        if lower.endswith(".properties"):
            return self._parse_properties(content)

        # YAML
        if lower.endswith((".yml", ".yaml")):
            return self._parse_yaml(content)

        # INI / CFG
        if lower.endswith((".ini", ".cfg")):
            return self._parse_ini(content)

        # .env
        if lower == ".env" or lower.endswith(".env"):
            return self._parse_env(content)

        return None

    def _parse_xml_config(self, content: str) -> dict[str, Any] | None:
        """Parse .NET-style XML config."""
        data: dict[str, Any] = {}
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return None

        # appSettings
        for section in root.iter("appSettings"):
            for add in section.findall("add"):
                key = add.get("key", "")
                val = add.get("value", "")
                if key:
                    data[f"appSettings.{key}"] = val

        # connectionStrings
        for section in root.iter("connectionStrings"):
            for add in section.findall("add"):
                name = add.get("name", "")
                cs = add.get("connectionString", "")
                if name:
                    data[f"connectionStrings.{name}"] = cs

        # system.serviceModel endpoints
        for endpoint in root.iter("endpoint"):
            addr = endpoint.get("address", "")
            if addr:
                name = endpoint.get("name", endpoint.get("contract", "endpoint"))
                data[f"endpoint.{name}"] = addr

        # Other key-value add elements
        for add in root.iter("add"):
            key = add.get("key", "")
            val = add.get("value", "")
            full_key = f"xml.{key}" if key else ""
            if full_key and full_key not in data:
                data[full_key] = val

        return data if data else None

    def _parse_properties(self, content: str) -> dict[str, Any] | None:
        """Parse Java .properties files."""
        data: dict[str, Any] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            sep = line.find("=")
            if sep < 0:
                sep = line.find(":")
            if sep > 0:
                key = line[:sep].strip()
                val = line[sep + 1:].strip()
                data[key] = val
        return data if data else None

    def _parse_yaml(self, content: str) -> dict[str, Any] | None:
        """Parse YAML config."""
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
        except ImportError:
            # Fallback: simple key: value parsing
            data = {}
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and val:
                        data[key] = val
            return data if data else None
        except Exception:
            return None
        return None

    def _parse_ini(self, content: str) -> dict[str, Any] | None:
        """Parse INI/CFG files."""
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(content)
        except configparser.Error:
            return None
        data: dict[str, Any] = {}
        for section in parser.sections():
            for key, val in parser.items(section):
                data[f"{section}.{key}"] = val
        return data if data else None

    def _parse_env(self, content: str) -> dict[str, Any] | None:
        """Parse .env files."""
        data: dict[str, Any] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'\"")
                if key:
                    data[key] = val
        return data if data else None

    def _flatten_dict(self, d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
        """Flatten nested dict into dot-separated keys."""
        items: dict[str, Any] = {}
        for k, v in d.items():
            new_key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, new_key))
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.update(self._flatten_dict(item, f"{new_key}[{i}]"))
                    else:
                        items[f"{new_key}[{i}]"] = item
            else:
                items[new_key] = v
        return items
