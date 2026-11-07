"""DNS intelligence modules — record enumeration, history, and zone transfer."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable
from urllib.parse import urlparse

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

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


def _extract_domain(target: str) -> str:
    """Normalise a target URL/domain down to a bare domain name."""
    t = target.strip()
    if "://" not in t:
        t = f"https://{t}"
    parsed = urlparse(t)
    host = parsed.hostname or parsed.path.split("/")[0]
    return host.lower().rstrip(".").split(":")[0]


# ---------------------------------------------------------------------------
# DnsRecordsModule
# ---------------------------------------------------------------------------

class DnsRecordsModule(BaseModule):
    @property
    def name(self) -> str:
        return "dns_records"

    @property
    def display_name(self) -> str:
        return "DNS Records"

    @property
    def description(self) -> str:
        return "Query A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA records and flag misconfigurations"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "DNS Intelligence"

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {}

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA"]
        all_records: dict[str, list[str]] = {}

        for rtype in record_types:
            if progress_callback:
                await progress_callback(f"Querying {rtype} records for {domain}")
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                all_records[rtype] = records
                for rec in records:
                    assets.append(ModuleAsset(
                        asset_type=AssetType.DNS_RECORD,
                        value=rec,
                        metadata={"type": rtype, "domain": domain},
                    ))
            except dns.resolver.NoAnswer:
                all_records[rtype] = []
            except dns.resolver.NXDOMAIN:
                return ModuleResult(
                    findings=[ModuleFinding(
                        title="Domain does not exist",
                        description=f"NXDOMAIN for {domain}",
                        severity=FindingSeverity.INFO,
                        category="DNS Intelligence",
                        evidence=f"DNS query for {domain} returned NXDOMAIN",
                        confidence=1.0,
                    )],
                    raw_output={"domain": domain, "error": "NXDOMAIN"},
                )
            except Exception as exc:
                all_records[rtype] = []
                logger.debug("DNS %s query for %s failed: %s", rtype, domain, exc)

        raw["records"] = all_records

        # --- Misconfiguration checks ---

        # Missing CAA
        if not all_records.get("CAA"):
            findings.append(ModuleFinding(
                title="Missing CAA Records",
                description=f"No CAA records found for {domain}. Any Certificate Authority can issue certificates.",
                severity=FindingSeverity.MEDIUM,
                category="DNS Intelligence",
                evidence="CAA query returned no records",
                impact="Any CA can issue TLS certificates for this domain, increasing risk of unauthorized cert issuance.",
                remediation="Add CAA DNS records to restrict certificate issuance to authorized CAs.",
                cwe_id="CWE-295",
                confidence=0.95,
            ))

        # Wildcard DNS
        try:
            wildcard = dns.resolver.resolve(f"nonexistent-xyzzy-42.{domain}", "A")
            if wildcard:
                findings.append(ModuleFinding(
                    title="Wildcard DNS Detected",
                    description=f"Wildcard DNS is configured for {domain} — any subdomain resolves.",
                    severity=FindingSeverity.INFO,
                    category="DNS Intelligence",
                    evidence=f"nonexistent-xyzzy-42.{domain} resolved to {[str(r) for r in wildcard]}",
                    impact="Wildcard DNS can mask subdomain takeover and complicate enumeration.",
                    remediation="Review if wildcard DNS is intentional; remove if not needed.",
                    confidence=0.9,
                ))
        except Exception:
            pass

        # SPF +all
        for txt in all_records.get("TXT", []):
            if "v=spf1" in txt and "+all" in txt:
                findings.append(ModuleFinding(
                    title="SPF Record with +all",
                    description=f"SPF record for {domain} uses +all, allowing any server to send mail.",
                    severity=FindingSeverity.HIGH,
                    category="DNS Intelligence",
                    evidence=txt,
                    impact="Email spoofing: any server can send email pretending to be this domain.",
                    remediation="Change SPF record to use -all or ~all.",
                    cwe_id="CWE-290",
                    cvss_score=7.4,
                    confidence=0.95,
                ))

        # Multiple A records
        a_records = all_records.get("A", [])
        if len(a_records) > 1:
            findings.append(ModuleFinding(
                title="Multiple A Records — Possible Load Balancing",
                description=f"{domain} has {len(a_records)} A records, suggesting load balancing or CDN.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence=", ".join(a_records),
                confidence=0.8,
            ))

        # Dangling CNAME
        for cname in all_records.get("CNAME", []):
            cname_target = cname.rstrip(".")
            try:
                dns.resolver.resolve(cname_target, "A")
            except Exception:
                findings.append(ModuleFinding(
                    title="Dangling CNAME Record",
                    description=f"CNAME {domain} -> {cname_target} does not resolve. Possible subdomain takeover.",
                    severity=FindingSeverity.MEDIUM,
                    category="DNS Intelligence",
                    evidence=f"CNAME target {cname_target} returned no A record",
                    impact="Dangling CNAME may allow subdomain takeover if the target can be claimed.",
                    remediation="Remove the CNAME record or point it to a valid host.",
                    cwe_id="CWE-284",
                    cvss_score=5.3,
                    confidence=0.7,
                ))

        # Summary finding
        total = sum(len(v) for v in all_records.values())
        findings.append(ModuleFinding(
            title="DNS Records Summary",
            description=f"Found {total} DNS records across {len([k for k, v in all_records.items() if v])} record types for {domain}.",
            severity=FindingSeverity.INFO,
            category="DNS Intelligence",
            evidence="\n".join(f"{k}: {', '.join(v)}" for k, v in all_records.items() if v),
            confidence=1.0,
        ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# DnsHistoryModule
# ---------------------------------------------------------------------------

class DnsHistoryModule(BaseModule):
    @property
    def name(self) -> str:
        return "dns_history"

    @property
    def display_name(self) -> str:
        return "DNS History"

    @property
    def description(self) -> str:
        return "Track DNS record changes over time via SecurityTrails or ViewDNS.info"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "DNS Intelligence"

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain}

        if settings.securitytrails_api_key:
            result = await self._query_securitytrails(domain, findings, assets, raw)
        else:
            result = await self._query_viewdns(domain, findings, assets, raw)

        return result

    async def _query_securitytrails(self, domain: str, findings: list, assets: list,
                                     raw: dict) -> ModuleResult:
        key = settings.securitytrails_api_key
        headers = {"APIKEY": key, "Accept": "application/json"}

        for rtype in ("a", "aaaa", "mx", "ns"):
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{rtype}"
            resp = await self._http_get(url, headers=headers)
            if resp.get("status") != 200:
                continue

            try:
                data = json.loads(resp["body"])
                records = data.get("records", [])
                raw[f"history_{rtype}"] = records

                ips_seen: set[str] = set()
                for record in records:
                    for val in record.get("values", []):
                        ip = val.get("ip", "") or val.get("ip_count", "") or val.get("host", "")
                        if ip and ip not in ips_seen:
                            ips_seen.add(ip)
                            assets.append(ModuleAsset(
                                asset_type=AssetType.IP,
                                value=ip,
                                metadata={
                                    "source": "securitytrails_history",
                                    "record_type": rtype,
                                    "first_seen": record.get("first_seen", ""),
                                    "last_seen": record.get("last_seen", ""),
                                },
                            ))

                if len(ips_seen) > 1:
                    findings.append(ModuleFinding(
                        title=f"DNS {rtype.upper()} History — {len(ips_seen)} Unique Values",
                        description=f"Domain {domain} has pointed to {len(ips_seen)} different {rtype.upper()} values over time.",
                        severity=FindingSeverity.INFO,
                        category="DNS Intelligence",
                        evidence=", ".join(sorted(ips_seen)),
                        impact="Previous hosting providers may still have residual data or configurations.",
                        confidence=0.9,
                    ))
            except Exception as exc:
                logger.debug("SecurityTrails parse error for %s %s: %s", domain, rtype, exc)

        if not findings:
            findings.append(ModuleFinding(
                title="DNS History Retrieved",
                description=f"DNS history queried for {domain} via SecurityTrails.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence="SecurityTrails API queried successfully",
                confidence=0.9,
            ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _query_viewdns(self, domain: str, findings: list, assets: list,
                              raw: dict) -> ModuleResult:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        resp = await self._http_get(url, headers={"User-Agent": "Mozilla/5.0"})

        if resp.get("status") != 200:
            findings.append(ModuleFinding(
                title="DNS History Unavailable",
                description="Could not retrieve DNS history — no SecurityTrails key and ViewDNS.info request failed.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence=f"ViewDNS.info returned status {resp.get('status')}",
                remediation="Configure securitytrails_api_key for reliable DNS history.",
                confidence=0.5,
            ))
            return ModuleResult(findings=findings, assets=assets, raw_output=raw)

        body = resp["body"]
        # Parse HTML table rows: <tr><td>IP</td><td>Location</td><td>Owner</td><td>Date</td></tr>
        rows = re.findall(
            r"<tr>\s*<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>",
            body,
        )
        ips_seen: set[str] = set()
        history_entries: list[dict] = []
        for ip, location, owner, date in rows:
            history_entries.append({"ip": ip, "location": location, "owner": owner, "date": date})
            if ip not in ips_seen:
                ips_seen.add(ip)
                assets.append(ModuleAsset(
                    asset_type=AssetType.IP,
                    value=ip,
                    metadata={"source": "viewdns_history", "owner": owner, "date": date},
                ))

        raw["viewdns_history"] = history_entries

        if history_entries:
            evidence_lines = [f"{e['ip']} ({e['owner']}, {e['date']})" for e in history_entries[:20]]
            findings.append(ModuleFinding(
                title=f"DNS History — {len(ips_seen)} Historical IPs",
                description=f"Found {len(history_entries)} DNS history entries for {domain} with {len(ips_seen)} unique IPs.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence="\n".join(evidence_lines),
                impact="Historical IPs may reveal previous hosting, migrations, or origin servers behind CDNs.",
                confidence=0.75,
            ))
        else:
            findings.append(ModuleFinding(
                title="No DNS History Found",
                description=f"No IP history entries found for {domain}.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence="ViewDNS.info returned no history rows",
                confidence=0.6,
            ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)


# ---------------------------------------------------------------------------
# ZoneTransferModule
# ---------------------------------------------------------------------------

class ZoneTransferModule(BaseModule):
    @property
    def name(self) -> str:
        return "zone_transfer"

    @property
    def display_name(self) -> str:
        return "Zone Transfer (AXFR)"

    @property
    def description(self) -> str:
        return "Attempt AXFR zone transfer on all NS servers — CRITICAL if successful"

    @property
    def target_types(self) -> list[str]:
        return ["url"]

    @property
    def category(self) -> str:
        return "DNS Intelligence"

    @property
    def timeout(self) -> int:
        return 180

    async def run(self, target: str, scan_context: dict[str, Any],
                  progress_callback: Callable | None = None) -> ModuleResult:
        domain = _extract_domain(target)
        findings: list[ModuleFinding] = []
        assets: list[ModuleAsset] = []
        raw: dict[str, Any] = {"domain": domain, "nameservers_tested": [], "vulnerable": []}

        # Resolve NS records
        if progress_callback:
            await progress_callback(f"Resolving NS records for {domain}")

        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(ns).rstrip(".") for ns in ns_answers]
        except dns.resolver.NXDOMAIN:
            return ModuleResult(error=f"Domain {domain} does not exist (NXDOMAIN)")
        except Exception as exc:
            return ModuleResult(
                findings=[ModuleFinding(
                    title="Cannot Resolve Nameservers",
                    description=f"Failed to resolve NS records for {domain}: {exc}",
                    severity=FindingSeverity.INFO,
                    category="DNS Intelligence",
                    evidence=str(exc),
                    confidence=0.9,
                )],
                raw_output={"error": str(exc)},
            )

        if not nameservers:
            return ModuleResult(
                raw_output=raw,
                error=f"No NS records found for {domain}",
            )

        for ns in nameservers:
            raw["nameservers_tested"].append(ns)
            if progress_callback:
                await progress_callback(f"Attempting AXFR on {ns} for {domain}")

            transfer_result = await self._try_axfr(domain, ns)
            raw.setdefault("transfer_details", {})[ns] = {
                "success": transfer_result["success"],
                "record_count": len(transfer_result.get("records", [])),
                "error": transfer_result.get("error"),
            }

            if not transfer_result["success"]:
                logger.debug(
                    "AXFR refused/failed on %s for %s: %s",
                    ns, domain, transfer_result.get("error", "unknown"),
                )
                continue

            records = transfer_result["records"]
            zone_lines: list[str] = []

            for rec in records:
                rec_name = rec.get("name", "")
                rec_type = rec.get("type", "")
                rec_value = rec.get("value", "")
                zone_lines.append(f"{rec_name}\t{rec_type}\t{rec_value}")
                self._record_to_asset(rec, domain, assets)

            raw["vulnerable"].append(ns)

            # Truncate evidence for very large zones
            if len(zone_lines) > 200:
                shown = zone_lines[:180] + [
                    f"\n... ({len(zone_lines) - 190} records omitted) ...\n"
                ] + zone_lines[-10:]
                evidence_text = "\n".join(shown)
            else:
                evidence_text = "\n".join(zone_lines)

            findings.append(ModuleFinding(
                title=f"Zone Transfer Successful on {ns}",
                description=(
                    f"AXFR zone transfer succeeded on nameserver {ns} for domain {domain}. "
                    f"Full DNS zone with {len(records)} records was disclosed. This exposes "
                    "all subdomains, mail servers, and internal hostnames."
                ),
                severity=FindingSeverity.CRITICAL,
                category="DNS Intelligence",
                evidence=f"AXFR against {ns} for {domain} returned {len(records)} records:\n\n{evidence_text}",
                raw_data={"nameserver": ns, "record_count": len(records)},
                impact=(
                    "Complete DNS zone disclosure exposes all subdomains, internal hostnames, "
                    "mail servers, and network architecture. Attackers gain a full map of the "
                    "attack surface. TXT records may also contain secrets or verification tokens."
                ),
                remediation=(
                    "Restrict zone transfers to authorized secondary nameservers only. "
                    "Configure allow-transfer ACLs in BIND or equivalent in your DNS software."
                ),
                cwe_id="CWE-200",
                cvss_score=7.5,
                owasp_category="A01:2021-Broken Access Control",
                confidence=1.0,
                validation_hint=f"Reproduce with: dig axfr {domain} @{ns}",
            ))

        if not raw["vulnerable"]:
            findings.append(ModuleFinding(
                title="Zone Transfer Not Possible",
                description=f"AXFR zone transfer was refused or failed on all {len(nameservers)} nameservers for {domain}.",
                severity=FindingSeverity.INFO,
                category="DNS Intelligence",
                evidence=f"Tested nameservers: {', '.join(nameservers)}",
                confidence=1.0,
            ))

        return ModuleResult(findings=findings, assets=assets, raw_output=raw)

    async def _try_axfr(self, domain: str, nameserver: str) -> dict[str, Any]:
        """Attempt a single AXFR zone transfer and return parsed records."""
        try:
            # Resolve the nameserver hostname to an IP for the transfer
            try:
                ns_answers = dns.resolver.resolve(nameserver, "A")
                ns_ip = str(list(ns_answers)[0])
            except Exception:
                ns_ip = nameserver

            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=15, lifetime=30)
            )

            records: list[dict[str, str]] = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    rtype = dns.rdatatype.to_text(rdataset.rdtype)
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": rtype,
                            "value": str(rdata),
                            "ttl": str(rdataset.ttl),
                        })

            return {"success": True, "records": records}

        except dns.query.TransferError as exc:
            return {"success": False, "error": f"Transfer refused: {exc}", "records": []}
        except dns.exception.FormError as exc:
            return {"success": False, "error": f"Form error: {exc}", "records": []}
        except ConnectionRefusedError:
            return {"success": False, "error": "Connection refused", "records": []}
        except TimeoutError:
            return {"success": False, "error": "Connection timed out", "records": []}
        except OSError as exc:
            return {"success": False, "error": f"Network error: {exc}", "records": []}
        except Exception as exc:
            return {"success": False, "error": str(exc), "records": []}

    @staticmethod
    def _record_to_asset(
        record: dict[str, str], domain: str, assets: list[ModuleAsset],
    ) -> None:
        """Convert a DNS zone record into appropriate ModuleAsset(s)."""
        rec_name = record.get("name", "")
        rec_type = record.get("type", "")
        rec_value = record.get("value", "")

        # Build FQDN from record name
        if rec_name == "@" or not rec_name:
            fqdn = domain
        elif rec_name.endswith("."):
            fqdn = rec_name.rstrip(".")
        else:
            fqdn = f"{rec_name}.{domain}"

        if rec_type == "A":
            assets.append(ModuleAsset(
                asset_type=AssetType.IP,
                value=rec_value,
                metadata={"source": "zone_transfer", "hostname": fqdn},
            ))
            if rec_name and rec_name != "@":
                assets.append(ModuleAsset(
                    asset_type=AssetType.SUBDOMAIN,
                    value=fqdn,
                    metadata={"source": "zone_transfer", "ip": rec_value},
                ))
        elif rec_type == "AAAA":
            assets.append(ModuleAsset(
                asset_type=AssetType.IP,
                value=rec_value,
                metadata={"source": "zone_transfer", "hostname": fqdn, "version": "ipv6"},
            ))
            if rec_name and rec_name != "@":
                assets.append(ModuleAsset(
                    asset_type=AssetType.SUBDOMAIN,
                    value=fqdn,
                    metadata={"source": "zone_transfer", "ip": rec_value},
                ))
        elif rec_type == "CNAME":
            assets.append(ModuleAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=fqdn,
                metadata={"source": "zone_transfer", "cname_target": rec_value},
            ))
        elif rec_type == "MX":
            parts = rec_value.split()
            mail_host = parts[-1].rstrip(".") if parts else rec_value.rstrip(".")
            assets.append(ModuleAsset(
                asset_type=AssetType.DOMAIN,
                value=mail_host,
                metadata={"source": "zone_transfer", "role": "mail_server"},
            ))
        elif rec_type == "NS":
            ns_host = rec_value.rstrip(".")
            assets.append(ModuleAsset(
                asset_type=AssetType.DOMAIN,
                value=ns_host,
                metadata={"source": "zone_transfer", "role": "nameserver"},
            ))
        elif rec_type == "SRV":
            parts = rec_value.split()
            if len(parts) >= 4:
                srv_target = parts[3].rstrip(".")
                srv_port = parts[2]
                assets.append(ModuleAsset(
                    asset_type=AssetType.SERVICE,
                    value=f"{srv_target}:{srv_port}",
                    metadata={
                        "source": "zone_transfer",
                        "srv_name": fqdn,
                        "priority": parts[0],
                        "weight": parts[1],
                    },
                ))
        elif rec_type == "TXT":
            assets.append(ModuleAsset(
                asset_type=AssetType.DNS_RECORD,
                value=rec_value,
                metadata={"source": "zone_transfer", "record_type": "TXT", "hostname": fqdn},
            ))
        else:
            assets.append(ModuleAsset(
                asset_type=AssetType.DNS_RECORD,
                value=rec_value,
                metadata={"source": "zone_transfer", "record_type": rec_type, "hostname": fqdn},
            ))
