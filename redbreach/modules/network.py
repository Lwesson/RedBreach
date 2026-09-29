"""Network attack surface module, nmap, masscan, infrastructure scanning."""

import json
import logging
import xml.etree.ElementTree as ET

from redbreach.modules.base import ModuleBase

logger = logging.getLogger("redbreach.modules.network")

# Masscan rate + port set by engagement speed. NOTE: masscan has NO --top-ports
# (that is an nmap flag); ports must be given with -p. The stealth set is the
# most-scanned services; normal is the well-known range; aggressive is all ports.
_MASSCAN_RATES = {
    "stealth": ("100", "-p21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017"),
    "normal": ("1000", "-p1-1000"),
    "aggressive": ("10000", "-p0-65535"),
}

# NSE scripts by service name
_NSE_SCRIPTS = {
    "ssh": "ssh-auth-methods",
    "http": "http-title,http-headers,http-methods",
    "https": "http-title,http-headers,http-methods,ssl-enum-ciphers,ssl-cert",
    "ssl": "ssl-enum-ciphers,ssl-cert",
    "ftp": "ftp-anon,ftp-bounce",
    "smb": "smb-vuln-ms17-010,smb-enum-shares,smb-os-discovery",
    "mysql": "mysql-empty-password,mysql-info",
    "mssql": "ms-sql-info,ms-sql-empty-password",
    "postgresql": "pgsql-brute",
    "modbus": "modbus-discover",
    "enip": "enip-info",
    "s7comm": "s7-info",
    "bacnet": "bacnet-info",
    "dnp3": "dnp3-info",
}

# ICS/SCADA well-known ports and their protocols
_ICS_PORTS = {
    102: ("S7comm", "Siemens S7 PLC communication"),
    502: ("Modbus", "Modbus TCP, PLC/RTU control protocol"),
    2222: ("EtherNet/IP", "EtherNet/IP explicit messaging"),
    4840: ("OPC-UA", "OPC Unified Architecture"),
    4843: ("OPC-UA-TLS", "OPC-UA over TLS"),
    18245: ("GE-SRTP", "GE SRTP, GE PLC service request"),
    20000: ("DNP3", "Distributed Network Protocol 3, SCADA"),
    34962: ("PROFINET", "PROFINET RT, Siemens industrial"),
    34963: ("PROFINET", "PROFINET RT, Siemens industrial"),
    34964: ("PROFINET", "PROFINET RT, Siemens industrial"),
    44818: ("EtherNet/IP-CIP", "EtherNet/IP CIP, Allen-Bradley/Rockwell PLCs"),
    47808: ("BACnet", "Building Automation and Control network"),
}

_NETWORK_TESTS = {
    "ftp": [
        "Enumerate FTP directory contents for sensitive files",
        "Test for FTP upload permissions",
        "Check for FTP bounce attacks to scan internal network",
    ],
    "ssh": [
        "Test for weak SSH credentials (common username/password pairs)",
        "Check for known CVEs on the detected SSH version",
        "Verify SSH key authentication enforcement",
    ],
    "http": [
        "Run web application scanner on HTTP service",
        "Check for directory listing enabled",
        "Test for HTTP method tampering (PUT, DELETE, TRACE)",
    ],
    "smb": [
        "Enumerate SMB shares for sensitive data",
        "Test for null session authentication",
        "Check for EternalBlue and related SMB vulnerabilities",
    ],
    "mysql": [
        "Test for empty/default MySQL credentials",
        "Attempt to enumerate databases and tables",
        "Check for remote code execution via UDF",
    ],
    "ics": [
        "Enumerate PLC/HMI device info and firmware version",
        "Test for unauthenticated read/write access to registers or coils",
        "Check for default credentials on embedded web interfaces",
        "Verify network segmentation between IT and OT zones",
        "Test for ARP spoofing susceptibility on the ICS network",
        "Check for unencrypted industrial protocols (Modbus, EtherNet/IP, S7comm)",
    ],
    "default": [
        "Check for default credentials on discovered service",
        "Test for unencrypted protocol alternatives",
        "Verify network segmentation between zones",
    ],
}


class NetworkModule(ModuleBase):
    name = "network"
    tools_required = ["nmap", "masscan"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        target = engagement.get("target", "")
        logger.info("Network recon for %s", target)
        result = await self.run_tool(["nmap", "-sn", "-oG", "-", target], timeout=300)
        return self._parse_nmap_hosts(result.stdout)

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 3: Fast port discovery with masscan."""
        targets = [a["value"] for a in assets if a.get("type") == "host"]
        if not targets:
            return assets

        speed = engagement.get("speed", "normal")
        rate, port_arg = _MASSCAN_RATES.get(speed, _MASSCAN_RATES["normal"])

        result = await self.run_tool(
            ["masscan"] + targets + port_arg.split() + ["--rate", rate, "-oJ", "-"],
            timeout=600,
        )

        if result.returncode == 127:
            logger.debug("masscan not installed, skipping port discovery")
            return assets

        parsed = self._parse_masscan(result.stdout)
        return parsed if parsed else assets

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 4: Targeted nmap service scan + NSE scripts on masscan-discovered ports."""
        if not assets:
            return []

        host_ports = {}
        plain_hosts = []
        for a in assets:
            if a.get("type") != "host":
                continue
            ports = a.get("ports")
            if ports:
                host_ports[a["value"]] = ports
            else:
                plain_hosts.append(a["value"])

        if not host_ports and not plain_hosts:
            return []

        all_findings = []

        # Scan hosts with known ports (from masscan)
        for host, ports in host_ports.items():
            port_str = ",".join(str(p) for p in ports)
            result = await self.run_tool(
                ["nmap", "-sV", "-p", port_str, "--script", "default,vuln", "-oX", "-", host],
                timeout=600,
            )
            all_findings.extend(self._parse_nmap_xml(result.stdout))

        # Fallback for hosts without port info
        if plain_hosts:
            targets = " ".join(plain_hosts)
            result = await self.run_tool(
                ["nmap", "-sV", "-oX", "-", targets], timeout=600,
            )
            all_findings.extend(self._parse_nmap_xml(result.stdout))

        return all_findings

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        """Generate context-aware manual test suggestions based on actual findings."""
        suggestions = []
        seen_services = set()

        for f in findings:
            service = f.get("service", "")
            nse = f.get("nse_scripts", {})

            if service and service not in seen_services:
                seen_services.add(service)
                # Map ICS findings to ICS test suggestions
                test_key = service
                if f.get("category") == "ics_service":
                    test_key = "ics"
                tests = _NETWORK_TESTS.get(test_key, _NETWORK_TESTS["default"])
                for desc in tests:
                    suggestions.append({
                        "type": "suggested_test", "category": service,
                        "description": desc,
                        "context": f"{f.get('host', '')}:{f.get('port', '')}",
                    })

            if nse:
                script_output = " ".join(nse.values()).lower()
                if "anonymous" in script_output:
                    suggestions.append({
                        "type": "suggested_test", "category": "ftp",
                        "description": "Anonymous access confirmed, enumerate all accessible files and check for write permissions",
                        "context": f"{f.get('host', '')}:{f.get('port', '')}",
                    })
                if "vulnerable" in script_output:
                    suggestions.append({
                        "type": "suggested_test", "category": "network_vuln",
                        "description": "NSE detected vulnerability, verify exploitability and assess business impact",
                        "context": f"{f.get('host', '')}:{f.get('port', '')}",
                    })

        return suggestions

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        if tool == "nmap_hosts":
            return self._parse_nmap_hosts(raw_output)
        elif tool == "nmap_xml":
            return self._parse_nmap_xml(raw_output)
        elif tool == "masscan":
            return self._parse_masscan(raw_output)
        return super().parse_output(tool, raw_output)

    def _parse_nmap_hosts(self, output: str) -> list[dict]:
        return [{"type": "host", "value": l.strip()} for l in output.strip().splitlines() if l.strip()]

    def _parse_nmap_xml(self, output: str) -> list[dict]:
        findings = []
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            logger.warning("Failed to parse nmap XML")
            return []
        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"
            for port in host.findall(".//port"):
                state_el = port.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    service_el = port.find("service")
                    service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                    product = service_el.get("product", "") if service_el is not None else ""
                    version = service_el.get("version", "") if service_el is not None else ""

                    scripts = {}
                    for script_el in port.findall("script"):
                        scripts[script_el.get("id", "")] = script_el.get("output", "")

                    port_num = int(port.get("portid", 0))
                    ics_info = _ICS_PORTS.get(port_num)
                    severity = "info"
                    category = "network_service"
                    title = f"Open port {port.get('portid')}/{port.get('protocol')} ({service})"

                    if ics_info:
                        proto_name, proto_desc = ics_info
                        severity = "high"
                        category = "ics_service"
                        title = f"ICS/SCADA: {proto_name} on {addr}:{port_num}, {proto_desc}"

                    finding = {
                        "type": "finding",
                        "title": title,
                        "severity": severity, "category": category,
                        "host": addr, "port": port.get("portid"),
                        "protocol": port.get("protocol"), "service": service,
                        "product": product, "version": version,
                    }
                    if scripts:
                        finding["nse_scripts"] = scripts
                        script_output = " ".join(scripts.values()).lower()
                        if "anonymous" in script_output or "allowed" in script_output:
                            finding["severity"] = "medium"
                        if "vulnerable" in script_output or "vuln" in script_output:
                            finding["severity"] = "high"

                    findings.append(finding)
        return findings

    def _parse_masscan(self, raw: str) -> list[dict]:
        """Parse masscan JSON output, aggregating ports per host."""
        cleaned = raw.strip().rstrip(",")
        if not cleaned.startswith("["):
            cleaned = f"[{cleaned}]"
        if cleaned.endswith(",]"):
            cleaned = cleaned[:-2] + "]"

        try:
            entries = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Failed to parse masscan output")
            return []

        hosts: dict[str, set[int]] = {}
        for entry in entries:
            ip = entry.get("ip", "")
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = set()
            for port_info in entry.get("ports", []):
                hosts[ip].add(port_info.get("port", 0))

        return [
            {"type": "host", "value": ip, "ports": sorted(ports)}
            for ip, ports in hosts.items()
        ]
