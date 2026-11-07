"""Module registry — auto-discovers all OSINT/analysis modules."""
from __future__ import annotations

from backend.modules.base import BaseModule

# --- Web modules ---
from backend.modules.web.dns_intel import DnsRecordsModule, DnsHistoryModule, ZoneTransferModule
from backend.modules.web.domain_intel import WhoisModule, SubdomainEnumModule, LiveHostModule
from backend.modules.web.ssl_web import SslAnalysisModule, SecurityHeadersModule, CorsAnalysisModule
from backend.modules.web.content_discovery import (
    RobotsSitemapModule, WaybackModule, JsAnalysisModule, GoogleDorkModule,
    TechFingerprintModule, WafDetectionModule, FaviconHashModule,
)
from backend.modules.web.email_social import (
    EmailHarvestModule, SpfDmarcModule, SocialLinksModule, BreachSearchModule,
)
from backend.modules.web.cloud_code import CloudStorageModule, GithubDorkModule, MetadataExtractModule

# --- IP modules ---
from backend.modules.ip.network_intel import (
    IpWhoisModule, GeoLocationModule, AsnInfoModule,
    ShodanLookupModule, ReverseDnsModule, ThreatIntelModule,
)
from backend.modules.ip.port_service import (
    PortScanModule, BannerGrabModule, ServiceEnumModule, SslCertScanModule,
)
from backend.modules.ip.protocol_enum import (
    SmbEnumModule, SnmpEnumModule, SmtpEnumModule, RpcEnumModule,
)

# --- AD modules ---
from backend.modules.ad.domain_recon import (
    AdDnsModule, LdapEnumModule, NullSessionModule, DomainTrustModule,
)
from backend.modules.ad.auth_recon import (
    KerberosEnumModule, AsrepRoastModule, PasswordPolicyModule, AdcsCheckModule,
)

# --- APK modules ---
from backend.modules.apk.store_intel import PlayStoreModule, DeveloperOsintModule
from backend.modules.apk.manifest_analysis import (
    ManifestModule, PermissionAnalysisModule, ComponentMapModule, DeeplinkMapModule,
)
from backend.modules.apk.code_analysis import (
    ApkSecretScanModule, EndpointExtractModule, CryptoAuditModule,
    StoragePatternsModule, WebviewAuditModule,
)
from backend.modules.apk.sdk_framework import (
    FrameworkDetectModule, SdkMapModule, TrackerDetectModule, NativeLibModule,
)

# --- Thick client modules ---
from backend.modules.thick.binary_analysis import (
    BinaryMetadataModule, StringsExtractModule, CodeSigningModule, PackingDetectModule,
)
from backend.modules.thick.code_analysis import (
    ThickDecompileModule, ThickSecretScanModule, ThickEndpointModule, ConfigExtractModule,
)
from backend.modules.thick.security_analysis import (
    DependencyCveModule, UnsafeApiModule, ThickCryptoModule, PrivilegeAnalysisModule,
    UpdateMechanismModule,
)

ALL_MODULES: dict[str, type[BaseModule]] = {}

def _register(cls: type[BaseModule]) -> None:
    inst = cls()
    ALL_MODULES[inst.name] = cls

# Web
for _m in (
    DnsRecordsModule, DnsHistoryModule, ZoneTransferModule,
    WhoisModule, SubdomainEnumModule, LiveHostModule,
    SslAnalysisModule, SecurityHeadersModule, CorsAnalysisModule,
    RobotsSitemapModule, WaybackModule, JsAnalysisModule, GoogleDorkModule,
    TechFingerprintModule, WafDetectionModule, FaviconHashModule,
    EmailHarvestModule, SpfDmarcModule, SocialLinksModule, BreachSearchModule,
    CloudStorageModule, GithubDorkModule, MetadataExtractModule,
):
    _register(_m)

# IP
for _m in (
    IpWhoisModule, GeoLocationModule, AsnInfoModule, ShodanLookupModule,
    ReverseDnsModule, ThreatIntelModule,
    PortScanModule, BannerGrabModule, ServiceEnumModule, SslCertScanModule,
    SmbEnumModule, SnmpEnumModule, SmtpEnumModule, RpcEnumModule,
):
    _register(_m)

# AD
for _m in (
    AdDnsModule, LdapEnumModule, NullSessionModule, DomainTrustModule,
    KerberosEnumModule, AsrepRoastModule, PasswordPolicyModule, AdcsCheckModule,
):
    _register(_m)

# APK
for _m in (
    PlayStoreModule, DeveloperOsintModule,
    ManifestModule, PermissionAnalysisModule, ComponentMapModule, DeeplinkMapModule,
    ApkSecretScanModule, EndpointExtractModule, CryptoAuditModule,
    StoragePatternsModule, WebviewAuditModule,
    FrameworkDetectModule, SdkMapModule, TrackerDetectModule, NativeLibModule,
):
    _register(_m)

# Thick client
for _m in (
    BinaryMetadataModule, StringsExtractModule, CodeSigningModule, PackingDetectModule,
    ThickDecompileModule, ThickSecretScanModule, ThickEndpointModule, ConfigExtractModule,
    DependencyCveModule, UnsafeApiModule, ThickCryptoModule, PrivilegeAnalysisModule,
    UpdateMechanismModule,
):
    _register(_m)


def get_modules_for_target(target_type: str) -> dict[str, type[BaseModule]]:
    return {
        name: cls for name, cls in ALL_MODULES.items()
        if target_type in cls().target_types
    }


__all__ = ["ALL_MODULES", "get_modules_for_target", "BaseModule"]
