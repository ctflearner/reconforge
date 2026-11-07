"""Network intelligence modules for IP targets — WHOIS, geolocation, ASN, Shodan, reverse DNS, threat intel."""
from __future__ import annotations

import ipaddress
import json
import logging
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


# ---------------------------------------------------------------------------
# 1. IP WHOIS Lookup
# ---------------------------------------------------------------------------
class IpWhoisModule(BaseModule):
    @property
    def name(self) -> str:
        return "ip_whois"

    @property
    def display_name(self) -> str:
        return "IP WHOIS Lookup"

    @property
    def description(self) -> str:
        return "RDAP/WHOIS lookup for IP ownership, ASN, CIDR, abuse contact and registration data."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        whois_data: dict[str, Any] = {}

        # --- Try ipwhois library first ---
        try:
            from ipwhois import IPWhois  # type: ignore[import-untyped]

            if progress_callback:
                await progress_callback("Running RDAP lookup via ipwhois library")

            obj = IPWhois(target)
            result = obj.lookup_rdap()
            raw["ipwhois_rdap"] = result

            whois_data = {
                "asn": result.get("asn"),
                "asn_description": result.get("asn_description"),
                "asn_cidr": result.get("asn_cidr"),
                "asn_country_code": result.get("asn_country_code"),
                "network_name": result.get("network", {}).get("name"),
                "network_cidr": result.get("asn_cidr"),
                "network_start": result.get("network", {}).get("start_address"),
                "network_end": result.get("network", {}).get("end_address"),
            }

            # Extract abuse contact from entities
            for entity_key, entity_val in (result.get("objects") or {}).items():
                contact = entity_val.get("contact") or {}
                for role in (entity_val.get("roles") or []):
                    if role == "abuse":
                        for email_entry in contact.get("email") or []:
                            whois_data["abuse_contact"] = email_entry.get("value", "")
                            break

        except ImportError:
            logger.info("ipwhois not installed — falling back to RDAP REST APIs")
            whois_data = await self._fallback_rdap(target, progress_callback)
            raw["rdap_rest"] = whois_data
        except Exception as exc:
            logger.warning("ipwhois RDAP failed (%s) — trying REST fallback", exc)
            whois_data = await self._fallback_rdap(target, progress_callback)
            raw["rdap_rest"] = whois_data

        # --- Build assets and findings ---
        assets.append(
            ModuleAsset(
                asset_type=AssetType.IP,
                value=target,
                metadata={k: v for k, v in whois_data.items() if v},
            )
        )

        summary_lines = [f"**{k.replace('_', ' ').title()}:** {v}" for k, v in whois_data.items() if v]
        findings.append(
            ModuleFinding(
                title=f"WHOIS data for {target}",
                description="IP registration and network ownership information.",
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence="\n".join(summary_lines) if summary_lines else "No WHOIS data retrieved.",
                raw_data=whois_data,
                confidence=0.95,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    # -- REST fallback --
    async def _fallback_rdap(
        self, ip: str, progress_callback: Callable | None = None
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}

        if progress_callback:
            await progress_callback("Querying ARIN RDAP REST API")

        resp = await self._http_get(f"https://rdap.arin.net/registry/ip/{ip}")
        if resp.get("status") == 200:
            try:
                body = json.loads(resp["body"])
                data["network_name"] = body.get("name", "")
                data["network_handle"] = body.get("handle", "")
                # CIDR from cidr0_cidrs
                cidrs = body.get("cidr0_cidrs") or []
                if cidrs:
                    data["network_cidr"] = f"{cidrs[0].get('v4prefix', '')}/{cidrs[0].get('length', '')}"
                for entity in body.get("entities") or []:
                    vcard = (entity.get("vcardArray") or [None, []])[1]
                    for vc_field in vcard:
                        if vc_field[0] == "org":
                            data["org"] = vc_field[3]
                        if vc_field[0] == "email":
                            data.setdefault("abuse_contact", vc_field[3])
            except (json.JSONDecodeError, IndexError, KeyError):
                pass

        # RIPE fallback for non-ARIN ranges
        if not data.get("network_name"):
            if progress_callback:
                await progress_callback("Querying RIPE Stat API")
            resp2 = await self._http_get(
                f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
            )
            if resp2.get("status") == 200:
                try:
                    body2 = json.loads(resp2["body"])
                    for record in body2.get("data", {}).get("records") or []:
                        for field_entry in record:
                            key = field_entry.get("key", "").lower()
                            val = field_entry.get("value", "")
                            if key == "netname":
                                data["network_name"] = val
                            elif key == "origin":
                                data["asn"] = val
                            elif key == "descr" and "org" not in data:
                                data["org"] = val
                            elif key == "country":
                                data["asn_country_code"] = val
                except (json.JSONDecodeError, KeyError):
                    pass

        return data


# ---------------------------------------------------------------------------
# 2. IP Geolocation
# ---------------------------------------------------------------------------
class GeoLocationModule(BaseModule):
    @property
    def name(self) -> str:
        return "geo_location"

    @property
    def display_name(self) -> str:
        return "IP Geolocation"

    @property
    def description(self) -> str:
        return "Geolocate an IP address — city, region, country, coordinates, ISP/org."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        if progress_callback:
            await progress_callback("Querying ip-api.com for geolocation")

        fields = (
            "status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,query"
        )
        resp = await self._http_get(f"http://ip-api.com/json/{target}?fields={fields}")
        raw["ip_api_response"] = resp

        if resp.get("status") != 200:
            return ModuleResult(
                findings=[],
                assets=[],
                raw_output=raw,
                error=f"ip-api.com returned HTTP {resp.get('status')}: {resp.get('error', '')}",
            )

        try:
            data = json.loads(resp["body"])
        except json.JSONDecodeError:
            return ModuleResult(raw_output=raw, error="Failed to parse ip-api.com response")

        if data.get("status") == "fail":
            return ModuleResult(raw_output=raw, error=f"ip-api.com error: {data.get('message', 'unknown')}")

        geo_meta = {
            "city": data.get("city", ""),
            "region": data.get("regionName", ""),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "zip": data.get("zip", ""),
        }

        assets.append(
            ModuleAsset(asset_type=AssetType.IP, value=target, metadata=geo_meta)
        )

        location_parts = [p for p in [geo_meta["city"], geo_meta["region"], geo_meta["country"]] if p]
        coords = ""
        if geo_meta["latitude"] and geo_meta["longitude"]:
            coords = f" ({geo_meta['latitude']}, {geo_meta['longitude']})"

        findings.append(
            ModuleFinding(
                title=f"Geolocation for {target}",
                description=f"IP geolocated to {', '.join(location_parts) or 'unknown'}{coords}.",
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence=(
                    f"Location: {', '.join(location_parts)}{coords}\n"
                    f"ISP: {geo_meta['isp']}\n"
                    f"Org: {geo_meta['org']}\n"
                    f"ASN: {geo_meta['asn']}\n"
                    f"Timezone: {geo_meta['timezone']}"
                ),
                raw_data=geo_meta,
                confidence=0.7,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# 3. ASN Information
# ---------------------------------------------------------------------------
class AsnInfoModule(BaseModule):
    @property
    def name(self) -> str:
        return "asn_info"

    @property
    def display_name(self) -> str:
        return "ASN Information"

    @property
    def description(self) -> str:
        return "Discover ASN, announced prefixes, and peer relationships for an IP address."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        # Step 1: Get ASN for IP
        if progress_callback:
            await progress_callback("Resolving ASN from RIPE Stat")

        net_resp = await self._http_get(
            f"https://stat.ripe.net/data/network-info/data.json?resource={target}"
        )
        raw["network_info"] = net_resp

        asn: str | None = None
        prefix: str | None = None
        try:
            net_data = json.loads(net_resp["body"]).get("data", {})
            asns = net_data.get("asns") or []
            if asns:
                asn = str(asns[0])
            prefix = net_data.get("prefix")
        except (json.JSONDecodeError, KeyError):
            pass

        if not asn:
            return ModuleResult(
                findings=[
                    ModuleFinding(
                        title=f"No ASN found for {target}",
                        description="Could not resolve an ASN for this IP address.",
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        confidence=0.6,
                    )
                ],
                raw_output=raw,
            )

        asn_number = asn.lstrip("AS").lstrip("as")

        # Step 2: ASN overview
        if progress_callback:
            await progress_callback(f"Fetching ASN overview for AS{asn_number}")

        overview_resp = await self._http_get(
            f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_number}"
        )
        raw["as_overview"] = overview_resp

        asn_holder = ""
        try:
            ov_data = json.loads(overview_resp["body"]).get("data", {})
            asn_holder = ov_data.get("holder", "")
        except (json.JSONDecodeError, KeyError):
            pass

        # Step 3: Announced prefixes
        if progress_callback:
            await progress_callback(f"Fetching announced prefixes for AS{asn_number}")

        prefix_resp = await self._http_get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
        )
        raw["announced_prefixes"] = prefix_resp

        prefixes: list[str] = []
        try:
            pf_data = json.loads(prefix_resp["body"]).get("data", {})
            for pf_entry in pf_data.get("prefixes") or []:
                pfx = pf_entry.get("prefix", "")
                if pfx:
                    prefixes.append(pfx)
        except (json.JSONDecodeError, KeyError):
            pass

        # Step 4: Peers
        if progress_callback:
            await progress_callback(f"Fetching peer info for AS{asn_number}")

        peer_resp = await self._http_get(
            f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn_number}"
        )
        raw["asn_neighbours"] = peer_resp

        peers: list[dict[str, Any]] = []
        try:
            pe_data = json.loads(peer_resp["body"]).get("data", {})
            for nb in pe_data.get("neighbours") or []:
                peers.append({"asn": nb.get("asn"), "type": nb.get("type", "")})
        except (json.JSONDecodeError, KeyError):
            pass

        # Assets — each prefix becomes an IP asset
        for pfx in prefixes:
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.IP,
                    value=pfx,
                    metadata={"asn": f"AS{asn_number}", "holder": asn_holder, "type": "announced_prefix"},
                )
            )

        evidence_lines = [
            f"ASN: AS{asn_number}",
            f"Holder: {asn_holder}",
            f"IP prefix: {prefix or 'N/A'}",
            f"Total announced prefixes: {len(prefixes)}",
            f"Peer count: {len(peers)}",
        ]
        if prefixes:
            evidence_lines.append(f"Sample prefixes: {', '.join(prefixes[:20])}")

        findings.append(
            ModuleFinding(
                title=f"ASN information for {target} (AS{asn_number})",
                description=f"IP belongs to AS{asn_number} ({asn_holder}), announcing {len(prefixes)} prefixes with {len(peers)} peers.",
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence="\n".join(evidence_lines),
                raw_data={"asn": f"AS{asn_number}", "holder": asn_holder, "prefixes": prefixes[:50], "peer_count": len(peers)},
                confidence=0.9,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# 4. Shodan Host Lookup
# ---------------------------------------------------------------------------
class ShodanLookupModule(BaseModule):
    @property
    def name(self) -> str:
        return "shodan_lookup"

    @property
    def display_name(self) -> str:
        return "Shodan Host Lookup"

    @property
    def description(self) -> str:
        return "Query Shodan for open ports, banners, CVEs, and host metadata."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    @property
    def requires_api_key(self) -> str | None:
        return "shodan_api_key"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        api_key = getattr(settings, "shodan_api_key", "")
        if not api_key:
            findings.append(
                ModuleFinding(
                    title=f"Shodan lookup skipped for {target}",
                    description="No Shodan API key configured. Set RF_SHODAN_API_KEY to enable.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    remediation="Configure shodan_api_key in settings or RF_SHODAN_API_KEY env var.",
                    confidence=1.0,
                )
            )
            return ModuleResult(findings=findings, raw_output=raw)

        if progress_callback:
            await progress_callback("Querying Shodan host API")

        resp = await self._http_get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
        raw["shodan_response"] = {k: v for k, v in resp.items() if k != "body"}

        if resp.get("status") != 200:
            error_msg = ""
            try:
                error_msg = json.loads(resp["body"]).get("error", "")
            except (json.JSONDecodeError, KeyError):
                error_msg = resp.get("error", f"HTTP {resp.get('status')}")
            return ModuleResult(raw_output=raw, error=f"Shodan API error: {error_msg}")

        try:
            data = json.loads(resp["body"])
        except json.JSONDecodeError:
            return ModuleResult(raw_output=raw, error="Failed to parse Shodan response")

        raw["shodan_data"] = data

        # --- Hostnames ---
        for hostname in data.get("hostnames") or []:
            assets.append(
                ModuleAsset(asset_type=AssetType.DOMAIN, value=hostname, metadata={"source": "shodan"})
            )

        # --- Ports & services ---
        open_ports: list[int] = data.get("ports") or []
        for service_entry in data.get("data") or []:
            port = service_entry.get("port")
            transport = service_entry.get("transport", "tcp")
            product = service_entry.get("product", "")
            version = service_entry.get("version", "")
            banner = service_entry.get("data", "")[:2000]

            assets.append(
                ModuleAsset(
                    asset_type=AssetType.PORT,
                    value=str(port),
                    metadata={
                        "port": port,
                        "protocol": transport,
                        "service": product,
                        "version": version,
                        "state": "open",
                    },
                )
            )

            if banner:
                assets.append(
                    ModuleAsset(
                        asset_type=AssetType.SERVICE,
                        value=f"{product or 'unknown'}:{port}",
                        metadata={
                            "port": port,
                            "product": product,
                            "version": version,
                            "banner": banner[:500],
                        },
                    )
                )

        # --- Vulnerabilities ---
        vulns: list[str] = data.get("vulns") or []
        for cve_id in vulns:
            # Attempt to extract CVSS from Shodan data (stored per-service)
            cvss_score = self._extract_cvss(data, cve_id)
            severity = self._cvss_to_severity(cvss_score)

            findings.append(
                ModuleFinding(
                    title=f"Shodan: {cve_id} detected on {target}",
                    description=f"Shodan reports vulnerability {cve_id} on this host.",
                    severity=severity,
                    category=self.category,
                    evidence=f"CVE: {cve_id}\nCVSS: {cvss_score if cvss_score else 'N/A'}\nSource: Shodan",
                    cwe_id="",
                    cvss_score=cvss_score,
                    impact=f"Host may be vulnerable to {cve_id}. Verify with targeted scanning.",
                    remediation=f"Investigate {cve_id} and apply vendor patches.",
                    confidence=0.6,
                    validation_hint=f"Run: nmap --script vuln -p {','.join(str(p) for p in open_ports[:20])} {target}",
                )
            )

        # --- Summary finding ---
        os_info = data.get("os", "")
        tags = data.get("tags") or []
        last_update = data.get("last_update", "")

        summary_evidence = (
            f"IP: {target}\n"
            f"Open ports: {', '.join(str(p) for p in open_ports)}\n"
            f"OS: {os_info or 'unknown'}\n"
            f"Hostnames: {', '.join(data.get('hostnames') or ['none'])}\n"
            f"Vulns: {len(vulns)} CVEs\n"
            f"Tags: {', '.join(tags) if tags else 'none'}\n"
            f"Last update: {last_update}"
        )

        findings.append(
            ModuleFinding(
                title=f"Shodan host summary for {target}",
                description=f"{len(open_ports)} open ports, {len(vulns)} CVEs reported by Shodan.",
                severity=FindingSeverity.INFO,
                category=self.category,
                evidence=summary_evidence,
                raw_data={"ports": open_ports, "vulns": vulns, "os": os_info, "tags": tags},
                confidence=0.85,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    @staticmethod
    def _extract_cvss(shodan_data: dict[str, Any], cve_id: str) -> float | None:
        """Try to pull CVSS from Shodan service data."""
        for svc in shodan_data.get("data") or []:
            svc_vulns = svc.get("vulns") or {}
            if cve_id in svc_vulns:
                vuln_info = svc_vulns[cve_id]
                if isinstance(vuln_info, dict):
                    return vuln_info.get("cvss")
        return None

    @staticmethod
    def _cvss_to_severity(score: float | None) -> FindingSeverity:
        if score is None:
            return FindingSeverity.MEDIUM
        if score >= 9.0:
            return FindingSeverity.CRITICAL
        if score >= 7.0:
            return FindingSeverity.HIGH
        if score >= 4.0:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW


# ---------------------------------------------------------------------------
# 5. Reverse DNS
# ---------------------------------------------------------------------------
class ReverseDnsModule(BaseModule):
    @property
    def name(self) -> str:
        return "reverse_dns"

    @property
    def display_name(self) -> str:
        return "Reverse DNS"

    @property
    def description(self) -> str:
        return "PTR record lookup and SecurityTrails reverse DNS for hostnames pointing to an IP."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}
        hostnames: list[str] = []

        # --- PTR lookup ---
        if progress_callback:
            await progress_callback("Performing PTR record lookup")

        try:
            addr = ipaddress.ip_address(target)
            if isinstance(addr, ipaddress.IPv4Address):
                reversed_ip = ".".join(reversed(target.split(".")))
                ptr_name = f"{reversed_ip}.in-addr.arpa"
            else:
                # IPv6: expand and reverse nibbles
                expanded = addr.exploded.replace(":", "")
                reversed_ip = ".".join(reversed(expanded))
                ptr_name = f"{reversed_ip}.ip6.arpa"

            ptr_records = await self._resolve_dns(ptr_name, "PTR")
            raw["ptr_records"] = ptr_records

            for ptr in ptr_records:
                hostname = ptr.rstrip(".")
                if hostname and hostname not in hostnames:
                    hostnames.append(hostname)
        except (ValueError, Exception) as exc:
            raw["ptr_error"] = str(exc)

        # --- SecurityTrails enrichment ---
        st_key = getattr(settings, "securitytrails_api_key", "")
        if st_key:
            if progress_callback:
                await progress_callback("Querying SecurityTrails reverse DNS")

            st_headers = {"APIKEY": st_key, "Accept": "application/json"}

            # Nearby IPs
            nearby_resp = await self._http_get(
                f"https://api.securitytrails.com/v1/ips/nearby/{target}",
                headers=st_headers,
            )
            raw["securitytrails_nearby"] = nearby_resp
            if nearby_resp.get("status") == 200:
                try:
                    nb_data = json.loads(nearby_resp["body"])
                    for block in nb_data.get("blocks") or []:
                        for site in block.get("sites") or []:
                            hostname_val = site if isinstance(site, str) else site.get("hostname", "")
                            if hostname_val and hostname_val not in hostnames:
                                hostnames.append(hostname_val)
                except (json.JSONDecodeError, KeyError):
                    pass

            # Search/list for reverse DNS
            search_resp = await self._http_post(
                "https://api.securitytrails.com/v1/search/list",
                json_data={"filter": {"ipv4": target}},
                headers=st_headers,
            )
            raw["securitytrails_search"] = search_resp
            if search_resp.get("status") == 200:
                try:
                    sr_data = json.loads(search_resp["body"])
                    for record in sr_data.get("records") or []:
                        hostname_val = record.get("hostname", "")
                        if hostname_val and hostname_val not in hostnames:
                            hostnames.append(hostname_val)
                except (json.JSONDecodeError, KeyError):
                    pass

        # --- Build results ---
        for hostname in hostnames:
            assets.append(
                ModuleAsset(
                    asset_type=AssetType.DOMAIN,
                    value=hostname,
                    metadata={"source": "reverse_dns", "ip": target},
                )
            )

        if hostnames:
            findings.append(
                ModuleFinding(
                    title=f"Reverse DNS entries for {target}",
                    description=f"Found {len(hostnames)} hostname(s) resolving to this IP.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    evidence="Hostnames:\n" + "\n".join(f"  - {h}" for h in hostnames),
                    raw_data={"hostnames": hostnames},
                    confidence=0.9,
                )
            )
        else:
            findings.append(
                ModuleFinding(
                    title=f"No reverse DNS entries for {target}",
                    description="No PTR records or reverse DNS hostnames found for this IP.",
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    confidence=0.8,
                )
            )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# 6. Threat Intelligence
# ---------------------------------------------------------------------------
class ThreatIntelModule(BaseModule):
    @property
    def name(self) -> str:
        return "threat_intel"

    @property
    def display_name(self) -> str:
        return "Threat Intelligence"

    @property
    def description(self) -> str:
        return "Aggregate threat reputation from AbuseIPDB, VirusTotal, and AlienVault OTX."

    @property
    def target_types(self) -> list[str]:
        return ["ip"]

    @property
    def category(self) -> str:
        return "Network Intelligence"

    async def run(
        self,
        target: str,
        scan_context: dict[str, Any],
        progress_callback: Callable | None = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        abuse_score: int | None = None
        abuse_reports: int = 0
        vt_malicious: int = 0
        vt_reputation: int = 0
        otx_pulse_count: int = 0
        sources_checked: list[str] = []
        evidence_parts: list[str] = []

        # ---- AbuseIPDB ----
        abuseipdb_key = getattr(settings, "abuseipdb_api_key", "")
        if abuseipdb_key:
            if progress_callback:
                await progress_callback("Checking AbuseIPDB")

            sources_checked.append("AbuseIPDB")
            resp = await self._http_get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90&verbose",
                headers={"Key": abuseipdb_key, "Accept": "application/json"},
            )
            raw["abuseipdb"] = {k: v for k, v in resp.items() if k != "body"}

            if resp.get("status") == 200:
                try:
                    ab_data = json.loads(resp["body"]).get("data", {})
                    abuse_score = ab_data.get("abuseConfidenceScore", 0)
                    abuse_reports = ab_data.get("totalReports", 0)
                    abuse_country = ab_data.get("countryCode", "")
                    abuse_isp = ab_data.get("isp", "")
                    is_tor = ab_data.get("isTor", False)
                    usage_type = ab_data.get("usageType", "")
                    categories = ab_data.get("reports", [])
                    raw["abuseipdb_data"] = ab_data

                    evidence_parts.append(
                        f"**AbuseIPDB:**\n"
                        f"  Confidence score: {abuse_score}%\n"
                        f"  Total reports: {abuse_reports}\n"
                        f"  Country: {abuse_country}\n"
                        f"  ISP: {abuse_isp}\n"
                        f"  Tor exit node: {is_tor}\n"
                        f"  Usage type: {usage_type}"
                    )

                    if abuse_score and abuse_score > 0:
                        # Collect unique abuse categories
                        cat_set: set[int] = set()
                        for report in categories[:50]:
                            for cat in report.get("categories") or []:
                                cat_set.add(cat)
                        if cat_set:
                            evidence_parts.append(f"  Abuse categories: {sorted(cat_set)}")

                except (json.JSONDecodeError, KeyError):
                    pass

        # ---- VirusTotal ----
        vt_key = getattr(settings, "virustotal_api_key", "")
        if vt_key:
            if progress_callback:
                await progress_callback("Checking VirusTotal")

            sources_checked.append("VirusTotal")
            resp = await self._http_get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
                headers={"x-apikey": vt_key},
            )
            raw["virustotal"] = {k: v for k, v in resp.items() if k != "body"}

            if resp.get("status") == 200:
                try:
                    vt_data = json.loads(resp["body"]).get("data", {}).get("attributes", {})
                    raw["virustotal_data"] = vt_data

                    analysis = vt_data.get("last_analysis_stats") or {}
                    vt_malicious = analysis.get("malicious", 0)
                    vt_suspicious = analysis.get("suspicious", 0)
                    vt_harmless = analysis.get("harmless", 0)
                    vt_undetected = analysis.get("undetected", 0)
                    vt_reputation = vt_data.get("reputation", 0)

                    evidence_parts.append(
                        f"**VirusTotal:**\n"
                        f"  Malicious: {vt_malicious}\n"
                        f"  Suspicious: {vt_suspicious}\n"
                        f"  Harmless: {vt_harmless}\n"
                        f"  Undetected: {vt_undetected}\n"
                        f"  Reputation score: {vt_reputation}"
                    )
                except (json.JSONDecodeError, KeyError):
                    pass

        # ---- AlienVault OTX (free, no key needed) ----
        if progress_callback:
            await progress_callback("Checking AlienVault OTX")

        sources_checked.append("AlienVault OTX")
        otx_resp = await self._http_get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
        )
        raw["otx"] = {k: v for k, v in otx_resp.items() if k != "body"}

        if otx_resp.get("status") == 200:
            try:
                otx_data = json.loads(otx_resp["body"])
                raw["otx_data"] = otx_data

                otx_pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                otx_reputation_val = otx_data.get("reputation", 0)
                otx_validation = otx_data.get("validation") or []

                evidence_parts.append(
                    f"**AlienVault OTX:**\n"
                    f"  Pulse count: {otx_pulse_count}\n"
                    f"  Reputation: {otx_reputation_val}\n"
                    f"  Validation: {otx_validation if otx_validation else 'none'}"
                )

                # Extract pulse names for context
                pulses = otx_data.get("pulse_info", {}).get("pulses") or []
                if pulses:
                    pulse_names = [p.get("name", "") for p in pulses[:10] if p.get("name")]
                    if pulse_names:
                        evidence_parts.append(
                            "  Recent pulses:\n" + "\n".join(f"    - {n}" for n in pulse_names)
                        )
            except (json.JSONDecodeError, KeyError):
                pass

        # ---- Aggregate severity decision ----
        is_high_threat = (
            (abuse_score is not None and abuse_score > 50)
            or vt_malicious > 5
        )
        is_moderate_threat = (
            (abuse_score is not None and 20 < abuse_score <= 50)
            or (1 <= vt_malicious <= 5)
            or otx_pulse_count > 10
        )

        if is_high_threat:
            severity = FindingSeverity.HIGH
            summary = f"HIGH threat — AbuseIPDB score {abuse_score}%, VT malicious {vt_malicious}, OTX pulses {otx_pulse_count}."
        elif is_moderate_threat:
            severity = FindingSeverity.MEDIUM
            summary = f"Moderate threat signals — AbuseIPDB score {abuse_score}%, VT malicious {vt_malicious}, OTX pulses {otx_pulse_count}."
        else:
            severity = FindingSeverity.INFO
            summary = f"No significant threat indicators — AbuseIPDB score {abuse_score or 0}%, VT malicious {vt_malicious}, OTX pulses {otx_pulse_count}."

        full_evidence = f"Sources checked: {', '.join(sources_checked)}\n\n" + "\n\n".join(evidence_parts)

        findings.append(
            ModuleFinding(
                title=f"Threat intelligence for {target}",
                description=summary,
                severity=severity,
                category=self.category,
                evidence=full_evidence,
                raw_data={
                    "abuseipdb_score": abuse_score,
                    "abuseipdb_reports": abuse_reports,
                    "vt_malicious": vt_malicious,
                    "vt_reputation": vt_reputation,
                    "otx_pulse_count": otx_pulse_count,
                    "sources_checked": sources_checked,
                },
                impact="High threat score indicates the IP is associated with malicious activity (scanning, spam, botnets, or malware distribution)."
                if is_high_threat
                else "Moderate threat signals suggest further investigation is warranted."
                if is_moderate_threat
                else "IP appears clean across checked threat intelligence sources.",
                remediation="Block or restrict traffic from this IP if it is not an expected source. Investigate associated activity."
                if is_high_threat or is_moderate_threat
                else "",
                confidence=0.75 if is_high_threat else 0.6,
            )
        )

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)
