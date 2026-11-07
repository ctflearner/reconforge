"""Android manifest parsing and analysis modules."""
from __future__ import annotations

import logging
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

from backend.modules.base import (
    AssetType,
    BaseModule,
    FindingSeverity,
    ModuleAsset,
    ModuleFinding,
    ModuleResult,
)

logger = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _ns(attr: str) -> str:
    """Expand android: namespace prefix."""
    return f"{{{ANDROID_NS}}}{attr}"


async def _dump_manifest_xml(mod: BaseModule, apk_path: str) -> str | None:
    """Get decoded AndroidManifest.xml text via aapt2 or aapt."""
    stdout, _, rc = await mod._run_command(
        ["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
        timeout=30,
    )
    if rc == 0 and stdout.strip():
        return stdout

    stdout, _, rc = await mod._run_command(
        ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"],
        timeout=30,
    )
    if rc == 0 and stdout.strip():
        return stdout

    return None


async def _dump_badging(mod: BaseModule, apk_path: str) -> str | None:
    """Get badging output from aapt2/aapt."""
    stdout, _, rc = await mod._run_command(
        ["aapt2", "dump", "badging", apk_path], timeout=30
    )
    if rc == 0 and stdout.strip():
        return stdout
    stdout, _, rc = await mod._run_command(
        ["aapt", "dump", "badging", apk_path], timeout=30
    )
    if rc == 0 and stdout.strip():
        return stdout
    return None


async def _parse_manifest_apktool(mod: BaseModule, apk_path: str) -> ElementTree.Element | None:
    """Try apktool decode to get readable AndroidManifest.xml."""
    with tempfile.TemporaryDirectory() as tmp:
        stdout, stderr, rc = await mod._run_command(
            ["apktool", "d", "-f", "-s", "-o", tmp, apk_path],
            timeout=60,
        )
        manifest_path = Path(tmp) / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ElementTree.parse(str(manifest_path))
                return tree.getroot()
            except Exception:
                pass
    return None


class ManifestModule(BaseModule):
    """Parse AndroidManifest.xml and flag dangerous settings."""

    @property
    def name(self) -> str:
        return "apk_manifest"

    @property
    def display_name(self) -> str:
        return "Manifest Analysis"

    @property
    def description(self) -> str:
        return "Parse AndroidManifest.xml for security-relevant settings"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "manifest_analysis"

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
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Parsing AndroidManifest.xml...")

        badging = await _dump_badging(self, apk_path)
        xml_tree = await _dump_manifest_xml(self, apk_path)

        # Also try apktool for full XML
        root = await _parse_manifest_apktool(self, apk_path)

        manifest: dict[str, Any] = {}

        # --- Extract from badging ---
        if badging:
            pkg_m = re.search(r"package:\s+name='([^']+)'", badging)
            if pkg_m:
                manifest["package"] = pkg_m.group(1)
            ver_m = re.search(r"versionName='([^']+)'", badging)
            if ver_m:
                manifest["version_name"] = ver_m.group(1)
            ver_code_m = re.search(r"versionCode='([^']+)'", badging)
            if ver_code_m:
                manifest["version_code"] = ver_code_m.group(1)
            sdk_min_m = re.search(r"sdkVersion:'(\d+)'", badging)
            if sdk_min_m:
                manifest["min_sdk"] = int(sdk_min_m.group(1))
            sdk_target_m = re.search(r"targetSdkVersion:'(\d+)'", badging)
            if sdk_target_m:
                manifest["target_sdk"] = int(sdk_target_m.group(1))

            permissions = re.findall(r"uses-permission:\s+name='([^']+)'", badging)
            manifest["permissions"] = permissions

        # --- Extract from decoded XML tree ---
        if root is not None:
            if not manifest.get("package"):
                manifest["package"] = root.get("package", "")

            app_elem = root.find("application")
            if app_elem is not None:
                manifest["debuggable"] = app_elem.get(_ns("debuggable"), "false") == "true"
                manifest["allow_backup"] = app_elem.get(_ns("allowBackup"), "true") == "true"
                manifest["uses_cleartext"] = app_elem.get(
                    _ns("usesCleartextTraffic"), "false"
                ) == "true"
                manifest["network_security_config"] = app_elem.get(
                    _ns("networkSecurityConfig"), ""
                )

            # permissions from XML
            if not manifest.get("permissions"):
                perms = []
                for up in root.findall("uses-permission"):
                    pname = up.get(_ns("name"), "")
                    if pname:
                        perms.append(pname)
                manifest["permissions"] = perms

        # --- Fallback: extract flags from xmltree text ---
        if xml_tree and root is None:
            if "android:debuggable" in xml_tree:
                if re.search(r'android:debuggable.*?=.*?0xffffffff', xml_tree):
                    manifest["debuggable"] = True
                elif re.search(r'android:debuggable.*?true', xml_tree, re.I):
                    manifest["debuggable"] = True
            if re.search(r'android:allowBackup.*?0xffffffff', xml_tree):
                manifest["allow_backup"] = True
            elif re.search(r'android:allowBackup.*?true', xml_tree, re.I):
                manifest["allow_backup"] = True
            if re.search(r'android:usesCleartextTraffic.*?(0xffffffff|true)', xml_tree, re.I):
                manifest["uses_cleartext"] = True

        result.raw_output["manifest"] = manifest

        # --- Findings ---
        if manifest.get("debuggable"):
            result.findings.append(
                ModuleFinding(
                    title="Application is Debuggable",
                    description="android:debuggable is set to true. This allows "
                    "attaching a debugger, dumping memory, and bypassing security controls.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence="android:debuggable=true in AndroidManifest.xml",
                    impact="Attacker can attach debugger, inspect memory, bypass cert pinning, "
                    "and extract runtime secrets.",
                    remediation="Set android:debuggable=false for release builds.",
                    cwe_id="CWE-489",
                    cvss_score=7.5,
                    owasp_category="M9: Reverse Engineering",
                    confidence=0.95,
                    validation_hint="Check with: aapt dump badging <apk> | grep debuggable",
                )
            )

        if manifest.get("allow_backup"):
            result.findings.append(
                ModuleFinding(
                    title="Application Allows Backup",
                    description="android:allowBackup is true (default). App data can be "
                    "extracted via adb backup without root.",
                    severity=FindingSeverity.MEDIUM,
                    category="manifest_analysis",
                    evidence="android:allowBackup=true in AndroidManifest.xml",
                    impact="Sensitive data (tokens, credentials, databases) can be extracted "
                    "from a non-rooted device via USB.",
                    remediation="Set android:allowBackup=false or implement BackupAgent with encryption.",
                    cwe_id="CWE-921",
                    cvss_score=5.5,
                    owasp_category="M2: Insecure Data Storage",
                    confidence=0.9,
                )
            )

        if manifest.get("uses_cleartext"):
            result.findings.append(
                ModuleFinding(
                    title="Cleartext Traffic Allowed",
                    description="android:usesCleartextTraffic is true. App permits HTTP connections.",
                    severity=FindingSeverity.MEDIUM,
                    category="manifest_analysis",
                    evidence="android:usesCleartextTraffic=true in AndroidManifest.xml",
                    impact="Traffic can be intercepted via MITM attacks on unencrypted channels.",
                    remediation="Set android:usesCleartextTraffic=false and use networkSecurityConfig.",
                    cwe_id="CWE-319",
                    cvss_score=5.3,
                    owasp_category="M3: Insecure Communication",
                    confidence=0.9,
                )
            )

        if manifest.get("min_sdk") and manifest["min_sdk"] < 24:
            result.findings.append(
                ModuleFinding(
                    title="Low Minimum SDK Version",
                    description=f"minSdkVersion is {manifest['min_sdk']} (< 24 / Android 7). "
                    "Older Android versions lack security features and patches.",
                    severity=FindingSeverity.LOW,
                    category="manifest_analysis",
                    evidence=f"minSdkVersion: {manifest['min_sdk']}",
                    impact="App runs on devices missing modern security mitigations.",
                    remediation="Consider raising minSdkVersion to at least 24 (Android 7.0).",
                    cwe_id="CWE-693",
                    confidence=0.8,
                )
            )

        if manifest.get("target_sdk") and manifest["target_sdk"] < 33:
            result.findings.append(
                ModuleFinding(
                    title="Outdated Target SDK",
                    description=f"targetSdkVersion is {manifest['target_sdk']} (current: 34+). "
                    "Older target SDK bypasses newer permission and security enforcement.",
                    severity=FindingSeverity.LOW,
                    category="manifest_analysis",
                    evidence=f"targetSdkVersion: {manifest['target_sdk']}",
                    impact="App may bypass newer Android security restrictions.",
                    remediation="Update targetSdkVersion to latest stable (34+).",
                    confidence=0.8,
                )
            )

        if not manifest.get("network_security_config"):
            result.findings.append(
                ModuleFinding(
                    title="No Network Security Config",
                    description="No android:networkSecurityConfig defined. App relies on default "
                    "network security which varies by SDK version.",
                    severity=FindingSeverity.LOW,
                    category="manifest_analysis",
                    evidence="networkSecurityConfig attribute absent",
                    impact="Cannot enforce certificate pinning or restrict cleartext traffic per domain.",
                    remediation="Add a network_security_config.xml with certificate pinning.",
                    cwe_id="CWE-295",
                    confidence=0.7,
                )
            )

        # Package asset
        if manifest.get("package"):
            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.COMPONENT,
                    value=manifest["package"],
                    metadata={
                        "version": manifest.get("version_name", ""),
                        "min_sdk": manifest.get("min_sdk"),
                        "target_sdk": manifest.get("target_sdk"),
                    },
                )
            )

        return result


class PermissionAnalysisModule(BaseModule):
    """Analyse requested permissions and calculate risk score."""

    @property
    def name(self) -> str:
        return "apk_permissions"

    @property
    def display_name(self) -> str:
        return "Permission Analysis"

    @property
    def description(self) -> str:
        return "Map APK permissions to risk levels and compute risk score"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "manifest_analysis"

    # Risk map: permission suffix -> (risk_level, description)
    _DANGEROUS_PERMISSIONS: dict[str, tuple[str, str]] = {
        "CAMERA": ("dangerous", "Can access device camera"),
        "RECORD_AUDIO": ("dangerous", "Can record microphone audio"),
        "READ_CONTACTS": ("dangerous", "Can read contacts database"),
        "WRITE_CONTACTS": ("dangerous", "Can modify contacts"),
        "READ_SMS": ("dangerous", "Can read SMS messages"),
        "SEND_SMS": ("dangerous", "Can send SMS (potential premium SMS fraud)"),
        "RECEIVE_SMS": ("dangerous", "Can intercept SMS (OTP theft risk)"),
        "READ_CALL_LOG": ("dangerous", "Can read call history"),
        "READ_PHONE_STATE": ("dangerous", "Can read IMEI/phone identity"),
        "ACCESS_FINE_LOCATION": ("dangerous", "Can track precise GPS location"),
        "ACCESS_COARSE_LOCATION": ("moderate", "Can track approximate location"),
        "READ_EXTERNAL_STORAGE": ("moderate", "Can read files on shared storage"),
        "WRITE_EXTERNAL_STORAGE": ("dangerous", "Can write files to shared storage"),
        "READ_CALENDAR": ("moderate", "Can read calendar events"),
        "WRITE_CALENDAR": ("moderate", "Can modify calendar events"),
        "CALL_PHONE": ("dangerous", "Can initiate phone calls without user interaction"),
        "READ_PHONE_NUMBERS": ("dangerous", "Can read device phone numbers"),
        "BODY_SENSORS": ("dangerous", "Can read health/body sensor data"),
        "ACTIVITY_RECOGNITION": ("moderate", "Can detect physical activity"),
        "ACCESS_BACKGROUND_LOCATION": ("dangerous", "Tracks location in background"),
        "READ_MEDIA_IMAGES": ("moderate", "Can access photos"),
        "READ_MEDIA_VIDEO": ("moderate", "Can access videos"),
        "READ_MEDIA_AUDIO": ("moderate", "Can access audio files"),
        "POST_NOTIFICATIONS": ("low", "Can show notifications"),
        "NEARBY_WIFI_DEVICES": ("moderate", "Can scan nearby WiFi devices"),
        "BLUETOOTH_CONNECT": ("moderate", "Can connect to Bluetooth devices"),
        "SYSTEM_ALERT_WINDOW": ("dangerous", "Can draw overlays (tapjacking risk)"),
        "REQUEST_INSTALL_PACKAGES": ("dangerous", "Can install additional APKs"),
        "MANAGE_EXTERNAL_STORAGE": ("dangerous", "Full external storage access"),
        "BIND_ACCESSIBILITY_SERVICE": ("dangerous", "Accessibility access (keylogging risk)"),
        "BIND_DEVICE_ADMIN": ("dangerous", "Device admin privileges"),
        "BIND_VPN_SERVICE": ("dangerous", "Can create VPN (traffic interception)"),
        "RECEIVE_BOOT_COMPLETED": ("moderate", "Starts on device boot"),
        "FOREGROUND_SERVICE": ("low", "Can run foreground services"),
        "WAKE_LOCK": ("low", "Can prevent device sleep"),
        "INTERNET": ("low", "Can access the internet"),
        "ACCESS_NETWORK_STATE": ("low", "Can check network connectivity"),
        "USE_BIOMETRIC": ("moderate", "Can use biometric authentication"),
        "USE_FINGERPRINT": ("moderate", "Can use fingerprint scanner"),
    }

    _RISK_WEIGHTS = {"dangerous": 3, "moderate": 2, "low": 1}

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Extracting permissions...")

        badging = await _dump_badging(self, apk_path)
        permissions: list[str] = []
        if badging:
            permissions = re.findall(r"uses-permission:\s+name='([^']+)'", badging)

        if not permissions:
            root = await _parse_manifest_apktool(self, apk_path)
            if root is not None:
                for up in root.findall("uses-permission"):
                    pname = up.get(_ns("name"), "")
                    if pname:
                        permissions.append(pname)

        if not permissions:
            result.error = "No permissions found — could not parse manifest"
            return result

        # Classify
        dangerous: list[tuple[str, str, str]] = []
        moderate: list[tuple[str, str, str]] = []
        low_risk: list[tuple[str, str, str]] = []
        unknown: list[str] = []

        total_score = 0

        for perm in permissions:
            suffix = perm.rsplit(".", 1)[-1] if "." in perm else perm
            entry = self._DANGEROUS_PERMISSIONS.get(suffix)

            if entry:
                risk_level, desc = entry
                weight = self._RISK_WEIGHTS.get(risk_level, 1)
                total_score += weight
                item = (perm, risk_level, desc)
                if risk_level == "dangerous":
                    dangerous.append(item)
                elif risk_level == "moderate":
                    moderate.append(item)
                else:
                    low_risk.append(item)
            else:
                unknown.append(perm)
                total_score += 1

            result.assets.append(
                ModuleAsset(
                    asset_type=AssetType.PERMISSION,
                    value=perm,
                    metadata={
                        "risk_level": entry[0] if entry else "unknown",
                        "description": entry[1] if entry else "Custom/unknown permission",
                    },
                )
            )

        # Normalize score to 0-100
        max_possible = len(permissions) * 3
        risk_score = round((total_score / max_possible) * 100) if max_possible else 0

        result.raw_output["permissions"] = {
            "total": len(permissions),
            "dangerous_count": len(dangerous),
            "moderate_count": len(moderate),
            "low_count": len(low_risk),
            "unknown_count": len(unknown),
            "risk_score": risk_score,
        }

        # Findings for dangerous permissions
        if dangerous:
            evidence_lines = [f"  {p}: {d}" for p, _, d in dangerous]
            result.findings.append(
                ModuleFinding(
                    title="Dangerous Permissions Requested",
                    description=f"App requests {len(dangerous)} dangerous permission(s) "
                    "that grant access to sensitive device resources.",
                    severity=FindingSeverity.MEDIUM,
                    category="manifest_analysis",
                    evidence="Dangerous permissions:\n" + "\n".join(evidence_lines),
                    impact="App can access camera, microphone, contacts, SMS, location, "
                    "or other sensitive data.",
                    remediation="Verify each dangerous permission is necessary. Remove unused ones. "
                    "Apply principle of least privilege.",
                    cwe_id="CWE-250",
                    owasp_category="M1: Improper Platform Usage",
                    confidence=0.9,
                )
            )

        # Specific high-risk combos
        perm_suffixes = {p.rsplit(".", 1)[-1] for p in permissions}

        if "SYSTEM_ALERT_WINDOW" in perm_suffixes:
            result.findings.append(
                ModuleFinding(
                    title="Overlay Permission (Tapjacking Risk)",
                    description="App requests SYSTEM_ALERT_WINDOW which allows drawing over other apps.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence="android.permission.SYSTEM_ALERT_WINDOW requested",
                    impact="Enables tapjacking attacks — invisible overlays can capture taps "
                    "meant for other apps.",
                    remediation="Remove overlay permission if not essential. Implement filterTouchesWhenObscured.",
                    cwe_id="CWE-1021",
                    cvss_score=7.1,
                    confidence=0.85,
                )
            )

        if "REQUEST_INSTALL_PACKAGES" in perm_suffixes:
            result.findings.append(
                ModuleFinding(
                    title="APK Install Permission",
                    description="App can install additional APKs — potential for sideloading malware.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence="android.permission.REQUEST_INSTALL_PACKAGES requested",
                    impact="App can silently download and trigger installation of additional malicious APKs.",
                    remediation="Remove unless the app is a legitimate app store or updater.",
                    cwe_id="CWE-829",
                    cvss_score=7.5,
                    confidence=0.85,
                )
            )

        if "RECEIVE_SMS" in perm_suffixes and "INTERNET" in perm_suffixes:
            result.findings.append(
                ModuleFinding(
                    title="SMS Interception + Internet (OTP Theft Risk)",
                    description="App can intercept SMS and has internet access — classic OTP theft vector.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence="RECEIVE_SMS + INTERNET permissions combined",
                    impact="App could intercept 2FA OTP codes and exfiltrate them.",
                    remediation="Verify SMS access is essential. Use SMS Retriever API instead.",
                    cwe_id="CWE-319",
                    cvss_score=7.5,
                    confidence=0.8,
                )
            )

        # Overall risk finding
        sev = FindingSeverity.INFO
        if risk_score >= 70:
            sev = FindingSeverity.HIGH
        elif risk_score >= 45:
            sev = FindingSeverity.MEDIUM
        elif risk_score >= 25:
            sev = FindingSeverity.LOW

        result.findings.append(
            ModuleFinding(
                title=f"Permission Risk Score: {risk_score}/100",
                description=f"Calculated permission risk score based on {len(permissions)} "
                f"permissions ({len(dangerous)} dangerous, {len(moderate)} moderate, "
                f"{len(low_risk)} low, {len(unknown)} unknown).",
                severity=sev,
                category="manifest_analysis",
                evidence=f"Total permissions: {len(permissions)}\n"
                f"Risk score: {risk_score}/100",
                impact="Higher scores indicate more access to sensitive device capabilities.",
                remediation="Review each permission and remove unnecessary ones.",
                confidence=0.85,
            )
        )

        return result


class ComponentMapModule(BaseModule):
    """Map all manifest components and flag exported ones."""

    @property
    def name(self) -> str:
        return "apk_components"

    @property
    def display_name(self) -> str:
        return "Component Map"

    @property
    def description(self) -> str:
        return "Map activities, services, receivers, providers and flag exported components"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "manifest_analysis"

    _SENSITIVE_NAMES = re.compile(
        r"(settings|admin|debug|internal|config|test|dev|secret|hidden|"
        r"backdoor|root|setup|install|migration|diagnostic)",
        re.I,
    )

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Mapping manifest components...")

        root = await _parse_manifest_apktool(self, apk_path)
        if root is None:
            result.error = "Could not decode AndroidManifest.xml"
            return result

        app_elem = root.find("application")
        if app_elem is None:
            result.error = "No <application> element found"
            return result

        component_types = {
            "activity": "Activity",
            "service": "Service",
            "receiver": "Broadcast Receiver",
            "provider": "Content Provider",
        }

        all_components: list[dict[str, Any]] = []
        exported_components: list[dict[str, Any]] = []

        for tag, label in component_types.items():
            for elem in app_elem.findall(tag):
                name = elem.get(_ns("name"), "")
                exported_attr = elem.get(_ns("exported"))
                permission = elem.get(_ns("permission"), "")

                # Exported logic: explicit attribute, or implicit if has intent-filter
                intent_filters: list[dict[str, Any]] = []
                for ifilter in elem.findall("intent-filter"):
                    actions = [a.get(_ns("name"), "") for a in ifilter.findall("action")]
                    categories = [c.get(_ns("name"), "") for c in ifilter.findall("category")]
                    data_elems = []
                    for d in ifilter.findall("data"):
                        data_elems.append({
                            "scheme": d.get(_ns("scheme"), ""),
                            "host": d.get(_ns("host"), ""),
                            "path": d.get(_ns("path"), ""),
                            "pathPrefix": d.get(_ns("pathPrefix"), ""),
                            "pathPattern": d.get(_ns("pathPattern"), ""),
                            "mimeType": d.get(_ns("mimeType"), ""),
                        })
                    intent_filters.append({
                        "actions": actions,
                        "categories": categories,
                        "data": data_elems,
                    })

                is_exported = False
                if exported_attr == "true":
                    is_exported = True
                elif exported_attr is None and intent_filters:
                    is_exported = True  # Implicit export with intent-filter

                comp = {
                    "type": label,
                    "tag": tag,
                    "name": name,
                    "exported": is_exported,
                    "permission": permission,
                    "intent_filters": intent_filters,
                }
                all_components.append(comp)

                result.assets.append(
                    ModuleAsset(
                        asset_type=AssetType.COMPONENT,
                        value=name,
                        metadata={
                            "component_type": label,
                            "exported": is_exported,
                            "permission": permission,
                        },
                    )
                )

                if is_exported:
                    exported_components.append(comp)

        result.raw_output["components"] = {
            "total": len(all_components),
            "exported": len(exported_components),
            "by_type": {
                label: sum(1 for c in all_components if c["type"] == label)
                for label in component_types.values()
            },
        }

        # --- Findings for exported components ---
        unprotected = [c for c in exported_components if not c["permission"]]
        if unprotected:
            evidence_lines = []
            for c in unprotected:
                evidence_lines.append(f"  [{c['type']}] {c['name']} (no permission)")
            result.findings.append(
                ModuleFinding(
                    title=f"{len(unprotected)} Exported Components Without Permission Protection",
                    description="Exported components accessible to any app on the device "
                    "without permission requirements.",
                    severity=FindingSeverity.MEDIUM,
                    category="manifest_analysis",
                    evidence="Unprotected exported components:\n" + "\n".join(evidence_lines),
                    impact="Any malicious app can invoke these components — potential for "
                    "data theft, privilege escalation, or business logic abuse.",
                    remediation="Set android:exported=false where external access is not needed. "
                    "Add android:permission for those that must be exported.",
                    cwe_id="CWE-926",
                    cvss_score=6.5,
                    owasp_category="M1: Improper Platform Usage",
                    confidence=0.85,
                )
            )

        # --- Flag exported with sensitive names ---
        for c in exported_components:
            if self._SENSITIVE_NAMES.search(c["name"]):
                result.findings.append(
                    ModuleFinding(
                        title=f"Sensitive Exported Component: {c['name'].rsplit('.', 1)[-1]}",
                        description=f"Exported {c['type'].lower()} with sensitive-looking name: {c['name']}. "
                        "May expose internal/debug/admin functionality.",
                        severity=FindingSeverity.HIGH,
                        category="manifest_analysis",
                        evidence=f"Component: {c['name']}\nType: {c['type']}\n"
                        f"Exported: true\nPermission: {c['permission'] or 'NONE'}",
                        impact="Internal functionality exposed to any app — potential admin bypass "
                        "or information disclosure.",
                        remediation="Remove export or add strong permission protection.",
                        cwe_id="CWE-749",
                        cvss_score=7.0,
                        confidence=0.7,
                        validation_hint="Invoke with: adb shell am start -n <package>/<component>",
                    )
                )

        # --- Exported providers (content provider leaks) ---
        exported_providers = [c for c in exported_components if c["tag"] == "provider"]
        for p in exported_providers:
            if not p["permission"]:
                result.findings.append(
                    ModuleFinding(
                        title=f"Exported Content Provider: {p['name'].rsplit('.', 1)[-1]}",
                        description=f"Content provider {p['name']} is exported without permission. "
                        "May leak data via content:// URI.",
                        severity=FindingSeverity.HIGH,
                        category="manifest_analysis",
                        evidence=f"Provider: {p['name']}\nExported: true\nPermission: NONE",
                        impact="Any app can query this provider to extract data.",
                        remediation="Set exported=false or add readPermission/writePermission.",
                        cwe_id="CWE-927",
                        cvss_score=7.5,
                        owasp_category="M2: Insecure Data Storage",
                        confidence=0.85,
                        validation_hint="Query with: adb shell content query --uri content://<authority>",
                    )
                )

        return result


class DeeplinkMapModule(BaseModule):
    """Extract and analyse deep link / URI scheme definitions."""

    @property
    def name(self) -> str:
        return "apk_deeplinks"

    @property
    def display_name(self) -> str:
        return "Deep Link Map"

    @property
    def description(self) -> str:
        return "Extract deep links and URI schemes from manifest intent-filters"

    @property
    def target_types(self) -> list[str]:
        return ["apk"]

    @property
    def category(self) -> str:
        return "manifest_analysis"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        result = ModuleResult()
        apk_path = scan_context.get("file_path", target)

        if progress_callback:
            await progress_callback("Extracting deep links from manifest...")

        root = await _parse_manifest_apktool(self, apk_path)
        if root is None:
            result.error = "Could not decode AndroidManifest.xml"
            return result

        app_elem = root.find("application")
        if app_elem is None:
            result.error = "No <application> element"
            return result

        deeplinks: list[dict[str, Any]] = []
        custom_schemes: set[str] = set()

        for tag in ("activity", "activity-alias"):
            for activity in app_elem.findall(tag):
                act_name = activity.get(_ns("name"), "")
                for ifilter in activity.findall("intent-filter"):
                    for data_elem in ifilter.findall("data"):
                        scheme = data_elem.get(_ns("scheme"), "")
                        host = data_elem.get(_ns("host"), "")
                        path = data_elem.get(_ns("path"), "")
                        path_prefix = data_elem.get(_ns("pathPrefix"), "")
                        path_pattern = data_elem.get(_ns("pathPattern"), "")
                        port = data_elem.get(_ns("port"), "")
                        mime = data_elem.get(_ns("mimeType"), "")

                        if not scheme and not host and not mime:
                            continue

                        uri_parts = []
                        if scheme:
                            uri_parts.append(f"{scheme}://")
                        if host:
                            uri_parts.append(host)
                            if port:
                                uri_parts.append(f":{port}")
                        if path:
                            uri_parts.append(path)
                        elif path_prefix:
                            uri_parts.append(f"{path_prefix}*")
                        elif path_pattern:
                            uri_parts.append(path_pattern)

                        uri = "".join(uri_parts) if uri_parts else f"(mimeType={mime})"

                        dl = {
                            "uri": uri,
                            "scheme": scheme,
                            "host": host,
                            "path": path or path_prefix or path_pattern,
                            "activity": act_name,
                            "mime_type": mime,
                        }
                        deeplinks.append(dl)

                        if scheme and scheme not in ("http", "https"):
                            custom_schemes.add(scheme)

                        result.assets.append(
                            ModuleAsset(
                                asset_type=AssetType.ENDPOINT,
                                value=uri,
                                metadata={
                                    "type": "deeplink",
                                    "scheme": scheme,
                                    "host": host,
                                    "activity": act_name,
                                },
                            )
                        )

        result.raw_output["deeplinks"] = deeplinks
        result.raw_output["custom_schemes"] = list(custom_schemes)

        # --- Findings ---
        if not deeplinks:
            result.findings.append(
                ModuleFinding(
                    title="No Deep Links Defined",
                    description="No deep link URI schemes found in the manifest.",
                    severity=FindingSeverity.INFO,
                    category="manifest_analysis",
                    evidence="No <data> elements in intent-filters",
                    impact="N/A",
                    remediation="N/A",
                    confidence=0.9,
                )
            )
            return result

        # JavaScript scheme
        js_links = [d for d in deeplinks if d["scheme"] == "javascript"]
        if js_links:
            result.findings.append(
                ModuleFinding(
                    title="JavaScript URI Scheme Handler",
                    description="App handles javascript: URI scheme — potential XSS via deep link.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence=f"javascript: scheme in activity: {js_links[0]['activity']}",
                    impact="Attacker can execute JavaScript in WebView context via crafted deep link.",
                    remediation="Remove javascript: scheme handler. Validate all deep link URIs.",
                    cwe_id="CWE-79",
                    cvss_score=8.0,
                    confidence=0.8,
                    validation_hint="Test: adb shell am start -d 'javascript:alert(1)' <package>",
                )
            )

        # File scheme
        file_links = [d for d in deeplinks if d["scheme"] == "file"]
        if file_links:
            result.findings.append(
                ModuleFinding(
                    title="File URI Scheme Handler",
                    description="App handles file:// URIs — potential local file read via deep link.",
                    severity=FindingSeverity.HIGH,
                    category="manifest_analysis",
                    evidence=f"file: scheme in activity: {file_links[0]['activity']}",
                    impact="Attacker may read local files through WebView or provider via crafted URI.",
                    remediation="Remove file: scheme handler or add strict path validation.",
                    cwe_id="CWE-22",
                    cvss_score=7.5,
                    confidence=0.75,
                )
            )

        # Wildcard host
        wildcard_links = [d for d in deeplinks if d["host"] == "*" or d["host"] == ""]
        http_wildcards = [
            d for d in wildcard_links if d["scheme"] in ("http", "https")
        ]
        if http_wildcards:
            result.findings.append(
                ModuleFinding(
                    title="Wildcard Host in HTTP Deep Link",
                    description="HTTP/HTTPS deep link with wildcard or empty host — "
                    "app responds to ANY domain.",
                    severity=FindingSeverity.MEDIUM,
                    category="manifest_analysis",
                    evidence=f"Wildcard host in: {http_wildcards[0]['uri']}",
                    impact="Attacker can send phishing links to any domain that open in the app.",
                    remediation="Specify explicit host names for HTTP deep links.",
                    cwe_id="CWE-601",
                    confidence=0.8,
                )
            )

        # Custom schemes summary
        if custom_schemes:
            result.findings.append(
                ModuleFinding(
                    title=f"Custom URI Schemes: {', '.join(sorted(custom_schemes))}",
                    description=f"App registers {len(custom_schemes)} custom URI scheme(s). "
                    "These can be invoked by any app or website.",
                    severity=FindingSeverity.INFO,
                    category="manifest_analysis",
                    evidence="Schemes: " + ", ".join(sorted(custom_schemes)),
                    impact="Custom schemes are not protected — any app can craft intents to them.",
                    remediation="Validate all parameters received via custom scheme handlers.",
                    confidence=0.9,
                )
            )

        return result
