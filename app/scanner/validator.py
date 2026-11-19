"""
NetCut - Scan Target Validator & Security Gate
Validates IP addresses and CIDR subnets to prevent command injection,
uncontrolled broad sweeps, or scanning unauthorized public networks.
"""

import ipaddress
import re
from typing import Any, Dict, List, Union

FORBIDDEN_CHARS_PATTERN = re.compile(r"[;&|`$><!\"'\\\s]")
MAX_ALLOWED_HOSTS = 256  # Hard ceiling: at most a /24 subnet (256 addresses)


class ScanTargetError(ValueError):
    """Raised when a scan target violates security or validation policies."""
    pass


def validate_scan_target(target_input: str) -> Dict[str, Any]:
    """
    Validates a target string (IP, hostname, or CIDR).
    
    Returns structured metadata:
        {
            "target": str,
            "type": "single_ip" | "network" | "hostname",
            "is_private": bool,
            "host_count": int,
            "hosts_preview": List[str]
        }
    
    Raises:
        ScanTargetError if target is malformed, overly broad, or contains dangerous characters.
    """
    if not target_input or not isinstance(target_input, str):
        raise ScanTargetError("Target cannot be empty.")

    target = target_input.strip()

    # 1. Command injection defense: strictly forbid shell metacharacters & whitespace
    if FORBIDDEN_CHARS_PATTERN.search(target):
        raise ScanTargetError("Target contains invalid or dangerous characters. Shell metacharacters are forbidden.")

    # 2. Check for localhost hostname alias
    if target.lower() in ("localhost", "127.0.0.1", "::1"):
        return {
            "target": "127.0.0.1",
            "type": "single_ip",
            "is_private": True,
            "host_count": 1,
            "hosts_preview": ["127.0.0.1"],
        }

    # 3. Check if target is a CIDR network
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as ex:
            raise ScanTargetError(f"Invalid CIDR network format: {ex}")

        # Guard against zero or single bit masks
        if net.version == 4:
            if net.prefixlen < 24:
                raise ScanTargetError(
                    f"Subnet /{net.prefixlen} is too broad ({net.num_addresses} addresses). "
                    f"For performance and safety, scan size is restricted to at most a /24 (256 addresses)."
                )
        elif net.version == 6:
            if net.prefixlen < 120:
                raise ScanTargetError("IPv6 subnet is too broad. Please specify at least a /120.")

        # Safeguard: disallow sweeping public CIDR subnet ranges
        is_priv = net.is_private or net.is_loopback or net.is_link_local
        if not is_priv:
            raise ScanTargetError(
                "Scanning public CIDR subnets is restricted for safety and authorization compliance. "
                "Only private subnets (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or loopback 127.0.0.0/8) or a single authorized IP may be scanned."
            )

        num_hosts = net.num_addresses
        if num_hosts > MAX_ALLOWED_HOSTS:
            raise ScanTargetError(f"Target contains {num_hosts} hosts, which exceeds maximum safety ceiling of {MAX_ALLOWED_HOSTS}.")

        # Generate hosts list
        hosts_list = [str(ip) for ip in net.hosts()]
        if not hosts_list:  # e.g., /32 or /31
            hosts_list = [str(net.network_address)]

        return {
            "target": str(net),
            "type": "network",
            "is_private": is_priv,
            "host_count": len(hosts_list),
            "hosts_preview": hosts_list[:10],
            "all_hosts": hosts_list,
        }

    # 4. Check if target is a single IP address
    try:
        ip = ipaddress.ip_address(target)
        is_priv = ip.is_private or ip.is_loopback or ip.is_link_local
        return {
            "target": str(ip),
            "type": "single_ip",
            "is_private": is_priv,
            "host_count": 1,
            "hosts_preview": [str(ip)],
            "all_hosts": [str(ip)],
        }
    except ValueError:
        pass

    # 5. Reject anything that looks like a dotted-decimal IP but failed IP parsing
    # (e.g. "999.999.999.999" – all digits and dots = bogus IP, not a hostname)
    if re.match(r"^\d+(\.\d+)+$", target):
        raise ScanTargetError(f"Target '{target}' resembles an IP address but is not a valid one.")

    # 6. Check if target is a valid simple hostname (e.g. host.local or my-server)
    # Strictly alphanumeric, hyphen, dot  — must start with a letter or digit
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", target):
        return {
            "target": target,
            "type": "hostname",
            "is_private": target.endswith(".local") or target.endswith(".internal") or target == "localhost",
            "host_count": 1,
            "hosts_preview": [target],
            "all_hosts": [target],
        }

    raise ScanTargetError(f"Target '{target}' is not a valid IP address, CIDR range, or hostname.")
