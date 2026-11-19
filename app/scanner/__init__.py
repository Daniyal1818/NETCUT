"""
NetCut - Network Discovery Module
Handles dependency detection, target IP/CIDR validation, safe Nmap execution,
and fallback socket scanning.
"""

from .detector import detect_nmap, get_nmap_info
from .validator import validate_scan_target, ScanTargetError
from .nmap_scanner import NmapScanner, ScanResult
from .socket_scanner import SocketScanner

__all__ = [
    "detect_nmap",
    "get_nmap_info",
    "validate_scan_target",
    "ScanTargetError",
    "NmapScanner",
    "ScanResult",
    "SocketScanner",
]
