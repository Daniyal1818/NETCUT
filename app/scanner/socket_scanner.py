"""
NetCut - Python Socket Fallback Scanner
Provides fast, zero-dependency network host & port discovery when Nmap is not installed.
Uses concurrent thread pool and basic banner grabbing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from typing import Any, Dict, List, Optional

from .validator import validate_scan_target, ScanTargetError
from .nmap_scanner import ScanResult

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    443: "https",
    445: "microsoft-ds",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


class SocketScanner:
    """
    Standard library TCP connect & banner grabbing scanner.
    """

    def __init__(self, socket_timeout: float = 0.6, max_workers: int = 30):
        self.socket_timeout = socket_timeout
        self.max_workers = max_workers

    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout_seconds: int = 40,
    ) -> ScanResult:
        t0 = time.perf_counter()

        try:
            target_meta = validate_scan_target(target)
            hosts_to_scan = target_meta["hosts_preview"]
        except ScanTargetError as ex:
            return ScanResult(
                target=target,
                engine="socket",
                hosts=[],
                duration_s=0.0,
                success=False,
                error_message=str(ex),
            )

        ports_to_scan = ports or sorted(list(COMMON_PORTS.keys()))
        discovered_hosts = []

        # Scan each host
        for host_ip in hosts_to_scan:
            # Check elapsed overall time
            if time.perf_counter() - t0 > timeout_seconds:
                break

            open_ports = self._scan_host_ports(host_ip, ports_to_scan)
            if open_ports:
                # Resolve hostname
                hostname = host_ip
                try:
                    hostname = socket.gethostbyaddr(host_ip)[0]
                except Exception:
                    pass

                discovered_hosts.append({
                    "ip": host_ip,
                    "hostname": hostname,
                    "status": "up",
                    "ports": open_ports,
                    "open_ports_count": len(open_ports),
                })

        duration = time.perf_counter() - t0
        return ScanResult(
            target=target,
            engine="socket_fallback",
            hosts=discovered_hosts,
            duration_s=duration,
            success=True,
            error_message=None if discovered_hosts else "Scan completed. No responsive hosts with open ports found.",
        )

    def _scan_host_ports(self, host_ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(len(ports), self.max_workers)) as executor:
            futures = {executor.submit(self._probe_port, host_ip, p): p for p in ports}
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    open_ports.append(res)
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _probe_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.socket_timeout)
                result = s.connect_ex((host, port))
                if result == 0:
                    service_name = COMMON_PORTS.get(port, "unknown")
                    banner = ""
                    # Quick banner probe for SSH, FTP, SMTP
                    if port in (21, 22, 25):
                        try:
                            s.settimeout(0.4)
                            raw = s.recv(256).decode("utf-8", errors="ignore").strip()
                            banner = raw.splitlines()[0] if raw else ""
                        except Exception:
                            pass
                    elif port in (80, 8080):
                        try:
                            s.settimeout(0.4)
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            resp = s.recv(512).decode("utf-8", errors="ignore")
                            for line in resp.splitlines():
                                if line.lower().startswith("server:"):
                                    banner = line.split(":", 1)[1].strip()
                                    break
                        except Exception:
                            pass

                    version_guess = banner
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_name,
                        "product": "",
                        "version": version_guess,
                        "extrainfo": banner,
                        "full_version": banner or f"{service_name} on port {port}",
                        "cpe": [],
                    }
        except Exception:
            return None
        return None
