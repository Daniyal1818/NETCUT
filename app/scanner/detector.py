"""
NetCut - Nmap Dependency Detector
Safely verifies whether Nmap is available on the host system and retrieves its version.
Provides platform-specific installation instructions if missing.
"""

import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

COMMON_WINDOWS_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
]

COMMON_UNIX_PATHS = [
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
]

INSTALL_INSTRUCTIONS = {
    "windows": (
        "1. Install via winget: winget install Insecure.Nmap\n"
        "2. Or download the Windows installer from https://nmap.org/download.html\n"
        "3. Restart the NETCUT terminal/server after installation."
    ),
    "linux": (
        "Ubuntu/Debian: sudo apt update && sudo apt install -y nmap\n"
        "Fedora/RHEL:   sudo dnf install -y nmap\n"
        "Arch Linux:    sudo pacman -S nmap"
    ),
    "macos": (
        "Install via Homebrew: brew install nmap"
    ),
}


def find_nmap_binary() -> Optional[str]:
    """Finds path to nmap binary on system or returns None."""
    # Check standard PATH first
    found = shutil.which("nmap")
    if found:
        return found

    candidates = COMMON_WINDOWS_PATHS if os.name == "nt" else COMMON_UNIX_PATHS
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK if os.name != "nt" else os.F_OK):
            return path
    return None


def get_nmap_info() -> Dict[str, Any]:
    """
    Returns structured availability information for Nmap.
    """
    path = find_nmap_binary()
    if not path:
        return {
            "available": False,
            "path": None,
            "version": None,
            "engine": "nmap",
            "instructions": INSTALL_INSTRUCTIONS,
            "message": "Nmap binary not found. Network discovery can use the built-in socket scanner fallback or sample scans.",
        }

    # Safe version query (timeout bounded, structured args)
    version_str = "Unknown"
    try:
        proc = subprocess.run(
            [path, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            match = re.search(r"Nmap version\s+([\d\.]+)", proc.stdout)
            if match:
                version_str = match.group(1)
            else:
                first_line = proc.stdout.splitlines()[0] if proc.stdout else ""
                version_str = first_line.strip()
    except Exception as ex:
        version_str = f"Installed (version check failed: {ex})"

    return {
        "available": True,
        "path": path,
        "version": version_str,
        "engine": "nmap",
        "instructions": INSTALL_INSTRUCTIONS,
        "message": f"Nmap {version_str} is ready for network discovery.",
    }


def detect_nmap() -> Tuple[bool, Optional[str]]:
    """Quick boolean and path helper."""
    info = get_nmap_info()
    return info["available"], info["path"]
