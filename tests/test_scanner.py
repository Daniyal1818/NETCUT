"""
NetCut - Scanner Module Unit Tests
Tests for: IP/CIDR validation, dangerous character rejection,
           Nmap detection, socket scanner basic operation,
           and sample scan data integrity.
"""

import sys
import os

# Ensure project root is in path regardless of CWD
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.scanner.validator import validate_scan_target, ScanTargetError
from app.scanner.detector import get_nmap_info, find_nmap_binary
from app.scanner.sample_scans import SAMPLE_SCANS


# ─── Validator: Valid targets ────────────────────────────────────────────────

def test_valid_single_ip():
    result = validate_scan_target("192.168.1.1")
    assert result["type"] == "single_ip"
    assert result["host_count"] == 1
    assert result["hosts_preview"] == ["192.168.1.1"]


def test_valid_localhost_alias():
    result = validate_scan_target("localhost")
    assert result["target"] == "127.0.0.1"
    assert result["type"] == "single_ip"
    assert result["is_private"] is True


def test_valid_loopback_ip():
    result = validate_scan_target("127.0.0.1")
    assert result["type"] == "single_ip"
    assert result["is_private"] is True


def test_valid_cidr_24():
    result = validate_scan_target("192.168.1.0/24")
    assert result["type"] == "network"
    assert result["host_count"] == 254   # /24 → 254 usable hosts
    assert result["is_private"] is True


def test_valid_cidr_30():
    result = validate_scan_target("10.0.0.0/30")
    assert result["type"] == "network"
    assert result["host_count"] == 2


def test_valid_cidr_32():
    """Single-host CIDR (/32) is acceptable."""
    result = validate_scan_target("10.10.10.10/32")
    assert result["type"] == "network"
    assert result["host_count"] >= 1


def test_valid_private_hostname():
    result = validate_scan_target("my-server.local")
    assert result["type"] == "hostname"
    assert result["is_private"] is True


def test_valid_simple_hostname():
    result = validate_scan_target("fileserver")
    assert result["type"] == "hostname"


# ─── Validator: Rejections ────────────────────────────────────────────────────

def test_reject_shell_semicolon():
    try:
        validate_scan_target("192.168.1.1; rm -rf /")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_shell_pipe():
    try:
        validate_scan_target("192.168.1.1|id")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_shell_backtick():
    try:
        validate_scan_target("`whoami`")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_shell_dollar():
    try:
        validate_scan_target("$HOME")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_shell_ampersand():
    try:
        validate_scan_target("192.168.1.1&id")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_shell_redirect():
    try:
        validate_scan_target("192.168.1.1>file")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_whitespace_in_target():
    try:
        validate_scan_target("192.168.1.1 192.168.1.2")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_empty_target():
    try:
        validate_scan_target("")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_none_target():
    try:
        validate_scan_target(None)  # type: ignore
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_too_broad_cidr_16():
    """A /16 subnet (65536 hosts) must be rejected."""
    try:
        validate_scan_target("10.0.0.0/16")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError as e:
        assert "broad" in str(e).lower() or "exceeded" in str(e).lower() or "too broad" in str(e).lower()


def test_reject_too_broad_cidr_8():
    try:
        validate_scan_target("10.0.0.0/8")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_invalid_ip_format():
    try:
        validate_scan_target("999.999.999.999")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_malformed_cidr():
    try:
        validate_scan_target("192.168.1.0/999")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


def test_reject_obviously_bad_string():
    try:
        validate_scan_target("not_a_valid_target!!!")
        assert False, "Should have raised ScanTargetError"
    except ScanTargetError:
        pass


# ─── Detector ────────────────────────────────────────────────────────────────

def test_nmap_info_returns_dict():
    info = get_nmap_info()
    assert isinstance(info, dict)
    assert "available" in info
    assert isinstance(info["available"], bool)
    assert "message" in info
    assert "instructions" in info


def test_nmap_info_has_install_instructions():
    info = get_nmap_info()
    instructions = info["instructions"]
    assert "windows" in instructions
    assert "linux" in instructions
    assert "nmap" in instructions["windows"].lower()


def test_nmap_path_none_or_string():
    info = get_nmap_info()
    assert info["path"] is None or isinstance(info["path"], str)


def test_nmap_version_none_or_string():
    info = get_nmap_info()
    # If not available, version should be None; if available, a string
    if info["available"]:
        assert isinstance(info["version"], str)
    else:
        assert info["version"] is None


def test_find_nmap_binary_returns_none_or_str():
    path = find_nmap_binary()
    assert path is None or isinstance(path, str)


# ─── Sample Scans ────────────────────────────────────────────────────────────

def test_sample_scans_exist():
    assert "corporate_subnet" in SAMPLE_SCANS
    assert "cloud_vpc" in SAMPLE_SCANS
    assert "hardened_network" in SAMPLE_SCANS


def test_corporate_subnet_structure():
    cs = SAMPLE_SCANS["corporate_subnet"]
    assert "title" in cs
    assert "target" in cs
    assert "hosts" in cs
    assert len(cs["hosts"]) > 0


def test_corporate_subnet_has_ports():
    hosts = SAMPLE_SCANS["corporate_subnet"]["hosts"]
    for host in hosts:
        assert "ip" in host
        assert "ports" in host
        assert len(host["ports"]) > 0


def test_all_sample_host_ips_valid():
    """Every host IP in every sample scan must be a parseable address."""
    import ipaddress
    for key, scan in SAMPLE_SCANS.items():
        for host in scan.get("hosts", []):
            try:
                ipaddress.ip_address(host["ip"])
            except ValueError:
                assert False, f"Invalid IP '{host['ip']}' in sample scan '{key}'"


def test_all_sample_ports_are_integers():
    for key, scan in SAMPLE_SCANS.items():
        for host in scan.get("hosts", []):
            for port_entry in host.get("ports", []):
                assert isinstance(port_entry["port"], int), (
                    f"Non-integer port in sample '{key}', host '{host['ip']}'"
                )
                assert 1 <= port_entry["port"] <= 65535


def test_hardened_network_exists():
    hn = SAMPLE_SCANS["hardened_network"]
    assert "hosts" in hn
    assert len(hn["hosts"]) > 0


# ─── Nmap Scanner & Parser Tests ──────────────────────────────────────────────

def test_reject_public_cidr_sweeps():
    """Sweeping broad public CIDR ranges must be rejected for security and authorization."""
    try:
        validate_scan_target("8.8.8.0/24")
        assert False, "Should have rejected public CIDR subnet"
    except ScanTargetError as ex:
        assert "public" in str(ex).lower()


def test_nmap_scanner_missing_binary_returns_failure():
    """When nmap binary is missing, scan() must cleanly return success=False."""
    from app.scanner.nmap_scanner import NmapScanner
    scanner = NmapScanner(nmap_path="/nonexistent/bin/nmap_fake")
    assert scanner.is_available() is False
    res = scanner.scan("192.168.1.1")
    assert res.success is False
    assert "not installed" in res.error_message.lower() or "not in path" in res.error_message.lower()


def test_nmap_xml_parser_valid_output():
    """Verify Nmap XML parsing extracts only up hosts, ports, services, and versions."""
    from app.scanner.nmap_scanner import NmapScanner
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames><hostname name="gateway.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.51" addrtype="ipv4"/>
  </host>
</nmaprun>"""
    scanner = NmapScanner()
    hosts = scanner._parse_nmap_xml(sample_xml)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.1.50"
    assert hosts[0]["hostname"] == "gateway.local"
    assert len(hosts[0]["ports"]) == 2
    ports = [p["port"] for p in hosts[0]["ports"]]
    assert 22 in ports and 80 in ports
    assert 443 not in ports  # closed port excluded


def test_nmap_xml_parser_empty_string():
    from app.scanner.nmap_scanner import NmapScanner
    scanner = NmapScanner()
    assert scanner._parse_nmap_xml("") == []
    assert scanner._parse_nmap_xml("   ") == []


def test_socket_scanner_invalid_target_fails_safely():
    from app.scanner.socket_scanner import SocketScanner
    scanner = SocketScanner()
    res = scanner.scan("invalid;target")
    assert res.success is False
    assert "dangerous" in res.error_message.lower() or "shell" in res.error_message.lower()


if __name__ == "__main__":
    import sys
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {t.__name__}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests.")
    sys.exit(1 if failed else 0)
