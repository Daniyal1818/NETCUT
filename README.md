# NETCUT — Attack-Path Analysis & Minimum-Cut Defense Planner

> **Course:** Design and Analysis of Algorithms (DAA)  
> **Team:** Muhammad Ibrahim (CT-24144) · Muhammad Daniyal Akbar (CT-24145)  
> **Instructor:** Ms. Tooba Sheikh  
> **Institution:** COMSATS University Islamabad  

---

## Overview

NETCUT is a **hybrid cybersecurity decision-support tool** that merges formal graph algorithms from the DAA curriculum with real network discovery and basic vulnerability assessment. It helps security analysts understand attack paths through a network, identify the cheapest set of defensive controls to block those paths, and prioritise remediation based on CVE severity.

**It is a decision-support and educational tool — not a certified penetration-testing platform.**

---

## Feature Summary

| Capability | Description |
|---|---|
| **Graph Modeling** | Model any network as a weighted directed graph |
| **Attack Path (Dijkstra)** | Find the shortest / least-resistance path from attacker to target |
| **Min-Cut Defense (Edmonds-Karp)** | Identify the minimum set of edges to cut that blocks all attack paths |
| **Budget Defense** | Greedy heuristic: block the most critical edges within a spending budget |
| **Network Discovery** | Nmap-based scanning or zero-dependency socket fallback |
| **Vulnerability Assessment** | CVE matching, CVSS severity, remediation recommendations |
| **Graph Integration** | Discovered hosts auto-convert to graph nodes with risk-aware weights |
| **Professional UI** | Dark SOC dashboard with 4 switchable themes, severity indicators, host detail drawer |

---

## DAA Algorithms Used

### 1. Dijkstra's Shortest Path — Attack Path Analysis

Finds the shortest (least exploit-resistance) path from the attacker entry point to the high-value target.

- **Time complexity:** O((V + E) log V)
- **Weight used:** `difficulty` — inversely proportional to CVE severity (Critical hosts have difficulty = 1.0)
- **Why it fits:** Models the attacker preferring the path of least resistance through vulnerable hosts.

### 2. Edmonds-Karp Max-Flow / Min-Cut — Defense Planning

Implements the BFS-based augmenting-path algorithm to find maximum flow and derive the minimum cut.

- **Time complexity:** O(V · E²)
- **Weight used:** `cost` — remediation / blocking cost per edge
- **Min-Cut Theorem:** The minimum cost of edges to remove equals the maximum flow value. Removing the min-cut completely disconnects attacker from target.
- **Locked edges:** Edges marked `blockable: false` receive a `BIG = 1e12` cost penalty, making them practically uncuttable.

### 3. Greedy Budget Defense

When a full min-cut exceeds the available budget, the greedy heuristic iteratively blocks the cheapest critical edge until the budget is exhausted or no more paths exist.

- **Complexity:** O(k × (Dijkstra + Edmonds-Karp)) where k = iterations until budget depleted.

---

## Architecture

```
NETCUT/
├── app/
│   ├── main.py                 # Core API + computation pipeline
│   ├── algorithms/
│   │   ├── dijkstra.py         # Dijkstra shortest path
│   │   ├── edmonds_karp.py     # BFS max-flow + min-cut
│   │   └── budget.py           # Greedy budget defense heuristic
│   ├── scanner/
│   │   ├── detector.py         # Nmap availability detection
│   │   ├── validator.py        # IP/CIDR security gate (injection prevention)
│   │   ├── nmap_scanner.py     # Structured Nmap subprocess runner
│   │   ├── socket_scanner.py   # Zero-dependency fallback scanner
│   │   └── sample_scans.py     # Offline benchmark datasets
│   └── vulnerability/
│       ├── cve_database.py     # Curated CVE signature intelligence base
│       ├── analyzer.py         # Service → CVE matching & severity classification
│       └── graph_converter.py  # Assessment → NETCUT graph topology
├── static/
│   ├── index.html              # Single-page application
│   ├── app.js                  # Frontend logic
│   ├── style.css               # Dark SOC theme engine (4 presets)
│   └── algorithms.js           # Client-side algorithm visualisation helpers
├── tests/
│   ├── test_algorithms.py      # 12 Dijkstra / Edmonds-Karp / locked-edge tests
│   ├── test_budget.py          # 6 greedy budget defense tests
│   ├── test_frontend.py        # DOM ID alignment test
│   ├── test_scanner.py         # 33 validator + detector + sample scan tests
│   └── test_vulnerability.py   # 34 CVE + analyzer + graph-converter tests
├── server.py                   # Zero-dependency HTTP server (std-lib only)
├── run.py                      # Convenience launcher
├── run_tests.py                # Master test runner (no pytest needed)
└── run.bat                     # Windows one-click launcher
```

---

## Installation

### Requirements

- **Python 3.9+** (Python 3.14 confirmed working)
- No third-party Python packages required for the core server.
- FastAPI + Uvicorn are **optional** (auto-detected; standard library fallback used if absent).

### Install Nmap (Optional but Recommended)

Nmap enables real-network host discovery and service version detection.  
Without it, NETCUT uses a built-in socket scanner or offline sample datasets.

**Windows:**
```powershell
winget install Insecure.Nmap
# Or download the installer from: https://nmap.org/download.html
```

**Ubuntu / Debian:**
```bash
sudo apt update && sudo apt install -y nmap
```

**Fedora / RHEL:**
```bash
sudo dnf install -y nmap
```

**Arch Linux:**
```bash
sudo pacman -S nmap
```

**macOS:**
```bash
brew install nmap
```

After installing Nmap, restart the NETCUT server.

---

## Running NETCUT

### Option 1 — Python (Recommended)

```powershell
cd "daa project/NETCUT"
python run.py
```

### Option 2 — Windows Batch File

Double-click `run.bat` or:

```powershell
.\run.bat
```

### Option 3 — Direct Server

```powershell
python server.py
python server.py --port 8080
python server.py --no-browser
```

The server binds to `0.0.0.0` and is accessible at:

- **http://localhost:8000**
- **http://127.0.0.1:8000**

If port 8000 is busy, the server automatically tries the next available port.

---

## Running Tests

```powershell
python run_tests.py
```

Expected output: **86 tests, 86 passed, 0 failed.**

Individual modules:

```powershell
python -m tests.test_algorithms
python -m tests.test_budget
python -m tests.test_frontend
python -m tests.test_scanner
python -m tests.test_vulnerability
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Server health check |
| GET | `/api/presets` | Pre-built network topology presets |
| GET | `/api/scanner/status` | Nmap availability + version |
| GET | `/api/scanner/samples` | Available offline sample scan datasets |
| POST | `/api/analyze` | Run Dijkstra + Edmonds-Karp + budget defense on a graph |
| POST | `/api/scanner/scan` | Perform live network scan (Nmap or socket fallback) |
| POST | `/api/scanner/load-sample` | Load a sample scan + run full vulnerability assessment |

---

## Using the Discovery & CVE Tab

### Performing a Scan

1. Click the **Discovery & CVE** tab.
2. Enter a target:
   - Single IP: `192.168.1.10`
   - CIDR subnet (max /24): `192.168.1.0/24`
   - Hostname: `my-server.local`
3. Read and acknowledge the **authorisation warning**.
4. Click **Scan**.

> **You must have explicit written permission to scan any network or device you do not personally own.**

### Using Sample Scans

Click **Corporate Subnet**, **Cloud VPC**, or **Hardened Network** to load a realistic pre-built dataset without requiring Nmap or network access.

### Importing into the Graph

After a scan, click **Import to Graph** to automatically convert discovered hosts into a NETCUT graph topology. The graph pre-assigns:

- **Difficulty weights** based on CVE severity (Critical = 1.0, Hardened = 8.0)
- **Cut costs** based on remediation complexity
- **Entry node**: Perimeter Gateway (external attacker)
- **Target node**: Highest risk host

Then run Dijkstra and Min-Cut from the **Analysis** tab.

---

## Vulnerability Assessment

### How CVE Matching Works

NETCUT maintains a curated signature database (`app/vulnerability/cve_database.py`) of known CVEs for common network services. For each discovered service, the analyzer:

1. Matches the service name, product pattern, and version pattern against each signature using regex.
2. Optionally runs an `affected_check` function for fine-grained version range logic.
3. Assigns the highest-severity matching CVE finding to the host.
4. If no high-severity CVE matches, generates an **Informational** finding noting the open port.

### Severity Levels

| Level | CVSS Range | Color |
|---|---|---|
| Critical | 9.0 – 10.0 | 🔴 `#FB7185` |
| High | 7.0 – 8.9 | 🟠 `#FB923C` |
| Medium | 4.0 – 6.9 | 🟡 `#F59E0B` |
| Low | 0.1 – 3.9 | 🔵 `#60A5FA` |
| Informational | 0.0 | 🟢 `#34D399` |

### CVE Intelligence in This Build

| CVE ID | Service | Severity | Description |
|---|---|---|---|
| CVE-2024-6387 | OpenSSH ≤ 9.7 | Critical | regreSSHion — unauthenticated RCE |
| CVE-2023-38408 | OpenSSH < 9.3p2 | High | PKCS#11 agent code execution |
| CVE-2021-41773 | Apache 2.4.49/50 | Critical | Path traversal + RCE |
| CVE-2022-31813 | Apache 2.4 < 2.4.54 | Medium | X-Forwarded-For bypass |
| CVE-2011-2523 | vsftpd 2.3.4 | Critical | Backdoor RCE |
| CVE-2015-3306 | ProFTPD < 1.3.5 | Critical | Mod_copy arbitrary write |
| CVE-2017-7494 | Samba < 4.6.4 | Critical | SambaCry RCE |
| CVE-2017-0144 | SMB/Samba | Critical | EternalBlue |
| CVE-2019-0708 | RDP < Win10/Server2019 | Critical | BlueKeep RCE |
| CVE-2022-0543 | Redis Debian packages | Critical | Lua sandbox escape |
| — | Telnet | High | Cleartext credential exposure |
| — | FTP | Medium | Cleartext protocol warning |

---

## Known Limitations & Ethical Use

### Limitations

- **Version-based matching only.** NETCUT does not exploit or verify vulnerabilities — it identifies potential risk based on detected service versions. False positives and false negatives are inherent in this approach.
- **Small CVE database.** The built-in signature set covers representative high-impact CVEs. It is not a comprehensive scanner like Tenable Nessus or OpenVAS.
- **No credential scanning.** NETCUT never attempts authentication, brute-force, or exploitation.
- **Scan size limit.** Maximum scan target is a /24 subnet (256 hosts). Larger networks must be scanned in segments.
- **Nmap is optional.** Without Nmap, only the top 20 TCP ports are probed via raw sockets; service version detection is unavailable.
- **No CVE database auto-update.** The included CVE signatures are static. Update `cve_database.py` manually to add new CVEs.

### Ethical Use

> ⚠️ **NETCUT must only be used on networks and systems you own or have explicit, written authorization to assess.**
>
> Unauthorized scanning or probing of computer systems is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent laws worldwide.
>
> This tool is built for educational use in an academic DAA course. Any real-world use is the sole responsibility of the operator.

---

## UI Themes

Switch themes using the palette icon in the top-right header:

| Theme | Description |
|---|---|
| **Cyber Cyan** | Default SOC teal/cyan palette |
| **Neon Violet** | Purple/violet accents |
| **Emerald Ops** | Green operational theme |
| **Crimson Alert** | Red high-alert theme |

Theme choice is persisted in browser `localStorage`.

---

## Project Attribution

This project was developed as a Complex Engineering Project (CEP) for the Design and Analysis of Algorithms course at COMSATS University Islamabad.

| Role | Name | ID |
|---|---|---|
| Developer | Muhammad Ibrahim | CT-24144 |
| Developer | Muhammad Daniyal Akbar | CT-24145 |
| Instructor | Ms. Tooba Sheikh | — |
