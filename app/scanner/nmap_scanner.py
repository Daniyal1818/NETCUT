"""
NetCut - Nmap Execution and XML Output Parser
Safely runs Nmap via structured subprocess (never shell=True) and extracts
hosts, open ports, detected services, and software versions from XML output.
"""

import os
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .detector import find_nmap_binary, get_nmap_info
from .validator import validate_scan_target, ScanTargetError


class ScanResult:
    """Represents the results of a network scan."""

    def __init__(
        self,
        target: str,
        engine: str,
        hosts: List[Dict[str, Any]],
        duration_s: float,
        success: bool = True,
        error_message: Optional[str] = None,
        raw_output: Optional[str] = None,
    ):
        self.target = target
        self.engine = engine
        self.hosts = hosts
        self.duration_s = duration_s
        self.success = success
        self.error_message = error_message
        self.raw_output = raw_output
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    def to_dict(self) -> Dict[str, Any]:
        open_ports_count = sum(len(h.get("ports", [])) for h in self.hosts)
        return {
            "target": self.target,
            "engine": self.engine,
            "success": self.success,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
            "duration_s": round(self.duration_s, 2),
            "hosts_count": len(self.hosts),
            "open_ports_count": open_ports_count,
            "hosts": self.hosts,
        }


class NmapScanner:
    """
    Safe Nmap wrapper for network discovery and service identification.
    """

    def __init__(self, nmap_path: Optional[str] = None):
        self.nmap_path = nmap_path or find_nmap_binary()

    def is_available(self) -> bool:
        if not self.nmap_path:
            return False
        import shutil
        return os.path.isfile(self.nmap_path) or (shutil.which(self.nmap_path) is not None)

    def scan(
        self,
        target: str,
        profile: str = "fast",  # 'fast', 'services', 'ping_only'
        timeout_seconds: int = 60,
    ) -> ScanResult:
        """
        Executes a safe Nmap scan against a validated target.
        """
        t0 = time.perf_counter()

        # 1. Verify Nmap presence
        if not self.is_available():
            info = get_nmap_info()
            return ScanResult(
                target=target,
                engine="nmap",
                hosts=[],
                duration_s=0.0,
                success=False,
                error_message="Nmap binary not installed or not in PATH. Please install Nmap or use socket scanner.",
            )

        # 2. Validate target
        try:
            target_meta = validate_scan_target(target)
            target_str = target_meta["target"]
        except ScanTargetError as ex:
            return ScanResult(
                target=target,
                engine="nmap",
                hosts=[],
                duration_s=0.0,
                success=False,
                error_message=str(ex),
            )

        # 3. Construct strictly structured argument array (NO shell=True)
        # Safe options:
        # -sT: unprivileged TCP connect (avoids raw socket permission crashes on Windows/Linux)
        # -T3: polite normal timing (avoids DoS or flooding)
        # -oX -: Output XML directly to stdout
        cmd = [self.nmap_path, "-oX", "-", "-T3"]

        if profile == "ping_only":
            # Host discovery only (ping sweep)
            cmd.extend(["-sn"])
        elif profile == "services":
            # Safe service version probe
            cmd.extend(["-sT", "-sV", "--version-light", "--top-ports", "100", "--host-timeout", "30s"])
        else:  # default 'fast'
            # Fast scan of top 100 ports with version probe
            cmd.extend(["-sT", "-sV", "--version-light", "-F", "--host-timeout", "20s"])

        cmd.append(target_str)

        # 4. Safe execution with timeout
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            duration = time.perf_counter() - t0
            return ScanResult(
                target=target_str,
                engine="nmap",
                hosts=[],
                duration_s=duration,
                success=False,
                error_message=f"Scan timed out after {timeout_seconds} seconds. Try scanning a smaller subnet or single IP.",
            )
        except Exception as ex:
            duration = time.perf_counter() - t0
            return ScanResult(
                target=target_str,
                engine="nmap",
                hosts=[],
                duration_s=duration,
                success=False,
                error_message=f"Subprocess execution error: {ex}",
            )

        duration = time.perf_counter() - t0

        if proc.returncode != 0 and not proc.stdout:
            err_msg = proc.stderr.strip() or f"Nmap exited with code {proc.returncode}"
            return ScanResult(
                target=target_str,
                engine="nmap",
                hosts=[],
                duration_s=duration,
                success=False,
                error_message=err_msg,
            )

        # 5. Parse XML output safely
        try:
            hosts = self._parse_nmap_xml(proc.stdout)
            return ScanResult(
                target=target_str,
                engine="nmap",
                hosts=hosts,
                duration_s=duration,
                success=True,
                raw_output=proc.stdout[:2000],  # preview
            )
        except Exception as parse_ex:
            return ScanResult(
                target=target_str,
                engine="nmap",
                hosts=[],
                duration_s=duration,
                success=False,
                error_message=f"Failed to parse Nmap output: {parse_ex}",
                raw_output=proc.stdout[:500] if proc.stdout else proc.stderr[:500],
            )

    def _parse_nmap_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parses Nmap XML output into clean host & service dictionaries."""
        if not xml_content or not xml_content.strip():
            return []

        root = ET.fromstring(xml_content)
        hosts = []

        for host_elem in root.findall("host"):
            # Check host status (up/down)
            status_elem = host_elem.find("status")
            status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
            if status != "up":
                continue

            # Extract IP address
            ip = None
            for addr_elem in host_elem.findall("address"):
                if addr_elem.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr_elem.get("addr")
                    break

            if not ip:
                continue

            # Extract hostnames
            hostname = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostname = name
                        break

            # Extract ports & services
            ports_list = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "closed") if state_elem is not None else "closed"

                    # Only retain open or open|filtered ports
                    if "open" not in state:
                        continue

                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

                    cpe_list = []
                    if service_elem is not None:
                        for cpe_elem in service_elem.findall("cpe"):
                            if cpe_elem.text:
                                cpe_list.append(cpe_elem.text)

                    # Build unified version string
                    full_version_parts = [p for p in (product, version, extrainfo) if p]
                    full_version = " ".join(full_version_parts) if full_version_parts else version

                    ports_list.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "full_version": full_version,
                        "cpe": cpe_list,
                    })

            hosts.append({
                "ip": ip,
                "hostname": hostname or ip,
                "status": status,
                "ports": ports_list,
                "open_ports_count": len(ports_list),
            })

        return hosts
