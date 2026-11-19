# NETCUT — Professional Attack-Path Analysis & Minimum-Cut Defense Planner

> **Course:** Design and Analysis of Algorithms (DAA)  
> **Team Members:** Muhammad Ibrahim (CT-24144) · Muhammad Daniyal Akbar (CT-24145)  
> **Instructor:** Ms. Tooba Sheikh  
> **Institution:** COMSATS University Islamabad  

---

## Executive Overview

**NETCUT** is a hybrid cybersecurity decision-support application that unifies formal graph algorithms from the DAA curriculum with real-world network discovery (Nmap / socket fallback) and basic vulnerability assessment. It enables security analysts, system administrators, and students to:

1. **Discover live network topologies** safely via structured Nmap scans or zero-dependency socket probing.
2. **Assess vulnerabilities and exposure** using curated CVE intelligence, CVSS scoring, and live NIST NVD API 2.0 queries.
3. **Map discovery data directly into graph topologies**, assigning exploit difficulty weights inversely proportional to vulnerability severity.
4. **Identify critical attack paths** using Dijkstra's shortest path algorithm (identifying the attacker's path of least exploit resistance).
5. **Compute optimal bottleneck defense** using the Edmonds-Karp Max-Flow / Min-Cut algorithm to sever attack vectors at minimum operational cost.
6. **Enforce budget constraints** using greedy heuristics when defense funds are bounded.
7. **Verify defensive isolation** mathematically, proving post-defense reachability to crown jewels is infinite ($\infty$).

> ⚠️ **Educational & Decision-Support Notice:** NETCUT is an educational decision-support model. Basic version-based matching is not equivalent to full enterprise-grade vulnerability scanning (such as Tenable Nessus, Qualys, or OpenVAS), as it does not execute active intrusive proofs.

---

## Core Algorithmic Pipeline

```
[Network Discovery] ──► [Host & Port Probe] ──► [Vulnerability & CVE Assessment]
                                                               │
                                                               ▼
[Post-Defense Verification] ◄── [Edmonds-Karp Min-Cut] ◄── [Weighted Directed Graph]
     (Dijkstra dist=∞)            (Bottleneck Cuts)        (Dijkstra Attack Path)
```

### 1. Dijkstra's Algorithm — Attack Path Analysis
- **Time Complexity:** $\mathcal{O}((|V| + |E|) \log |V|)$ using Min-Heap Priority Queue.
- **Weight Metric:** `difficulty` (exploit resistance).
- **Vulnerability Linkage:** Hosts with Critical CVEs (CVSS 9.0–10.0) receive low difficulty weights ($1.0$), modeling how attackers preferentially traverse high-risk vulnerabilities.

### 2. Edmonds-Karp Algorithm — Min-Cut Defense Optimization
- **Time Complexity:** $\mathcal{O}(|V| \cdot |E|^2)$ using BFS augmenting paths.
- **Weight Metric:** `cost` (remediation, firewall configuration, or link isolation expenditure).
- **Max-Flow Min-Cut Theorem:** Guarantees that the minimum cost required to sever all attack vectors between entry point $s$ and crown jewel $t$ exactly equals the maximum flow capacity.
- **Unblockable Links:** Essential operational edges marked `blockable: false` receive a capacity penalty ($10^{12}$), ensuring the cut avoids vital business links.

### 3. Greedy Budget Defense Heuristic
- When available remediation budget is less than the theoretical minimum cut cost, the greedy planner iteratively selects and severs the most cost-effective bottlenecks until the budget is depleted.

### 4. Chained Verification Audit
- Reruns Dijkstra's algorithm on the defended network topology to prove that target distance is infinite ($\text{dist}[t] = \infty$), guaranteeing 100% path elimination.

---

## Architecture & Directory Structure

```
NETCUT/
├── app/
│   ├── main.py                 # Core FastAPI/native application & computation pipeline
│   ├── algorithms/
│   │   ├── dijkstra.py         # Dijkstra shortest path with edge step tracking
│   │   ├── edmonds_karp.py     # BFS Edmonds-Karp max-flow & S-T partition cut
│   │   └── budget.py           # Greedy budget-constrained defense heuristic
│   ├── scanner/
│   │   ├── detector.py         # Safe Nmap binary detection & installation guides
│   │   ├── validator.py        # Strict IP/CIDR input gate & injection defense
│   │   ├── nmap_scanner.py     # Structured Nmap subprocess runner & XML parser
│   │   ├── socket_scanner.py   # Multi-threaded socket fallback scanner
│   │   └── sample_scans.py     # Offline benchmark datasets (Corporate, Cloud, Hardened)
│   └── vulnerability/
│       ├── cve_database.py     # Verified CVE signatures (OpenSSH, Apache, SMB, etc.)
│       ├── cve_lookup.py       # Live NIST NVD API 2.0 client with offline cache
│       ├── analyzer.py         # Port/service evaluator & severity classifier
│       └── graph_converter.py  # Assessment results → NETCUT graph topology converter
├── static/
│   ├── index.html              # Modern dark cybersecurity operations dashboard
│   ├── app.js                  # Frontend state machine & Cytoscape controller
│   ├── style.css               # SOC dark design system & 4 preset themes
│   └── algorithms.js           # Client-side algorithmic fallback engine
├── tests/
│   ├── test_algorithms.py      # Dijkstra & Edmonds-Karp algorithm unit tests
│   ├── test_budget.py          # Budget defense heuristic tests
│   ├── test_frontend.py        # DOM element ID alignment tests
│   ├── test_scanner.py         # Input validation, Nmap XML parsing & detector tests
│   └── test_vulnerability.py   # CVE signatures, NVD lookup & graph converter tests
├── server.py                   # High-reliability, zero-dependency HTTP server
├── run.py                      # Master convenience launcher
├── run_tests.py                # Standalone test runner (no pytest required)
├── run.bat                     # Windows one-click batch launcher
└── requirements.txt            # Optional dependencies (FastAPI, Uvicorn)
```

---

## Installation & Setup

### Requirements
- **Python 3.9+** (Tested and verified on Python 3.12 / 3.14).
- Standard library only for core execution. No third-party wheels required!
- Optional: `pip install -r requirements.txt` for FastAPI and Uvicorn.

### Installing Nmap (Optional but Recommended)
Nmap provides safe port discovery and service banner extraction. If Nmap is not present, NETCUT automatically switches to its built-in threaded socket scanner or pre-built sample datasets.

#### Windows
```powershell
# Using Windows Package Manager:
winget install Insecure.Nmap

# Or download official Windows setup (.exe) from:
# https://nmap.org/download.html
```

#### Linux (Ubuntu / Debian)
```bash
sudo apt update && sudo apt install -y nmap
```

#### Linux (Fedora / RHEL)
```bash
sudo dnf install -y nmap
```

#### Linux (Arch)
```bash
sudo pacman -S nmap
```

#### macOS
```bash
brew install nmap
```

---

## How to Run NETCUT

### Quick Launch
```powershell
python run.py
```

### Windows Batch File
Double-click `run.bat` or execute in PowerShell:
```powershell
.\run.bat
```

### Direct Server Options
```powershell
# Run on default port 8000
python server.py

# Specify custom port
python server.py --port 8080

# Headless mode (do not auto-open browser)
python server.py --no-browser
```

Open your browser to:
- **http://localhost:8000** or **http://127.0.0.1:8000**

---

## How to Perform a Scan & Security Assessment

1. Navigate to the **Discovery & CVE** tab on the left console.
2. Enter your scan target:
   - **Single Private IP:** `192.168.1.15`
   - **Authorized Private CIDR:** `192.168.1.0/24` (Safety limit: maximum /24 subnet, 256 addresses)
   - **Loopback Testing:** `127.0.0.1` or `localhost`
3. Select your **Scan Profile**:
   - `Fast Port Scan (-F + Services)`: Top 100 ports with fast service probing.
   - `Full Service & Version Probe (-sV)`: Deep banner and version probe.
   - `Host Ping Sweep (-sn)`: Rapid ICMP/ARP host discovery.
4. Select your **Discovery Engine**:
   - `Auto`: Uses Nmap if installed, falls back to Socket Scanner.
   - `Force Nmap Engine`: Uses structured Nmap binary execution.
   - `Fast Socket Scanner`: Multi-threaded TCP connect and banner grabbing.
5. Click **Scan Target**.
6. Alternatively, click **Load Dataset** to test with pre-analyzed benchmark networks:
   - `Corporate Subnet`: 3 hosts (Apache 2.4.49, OpenSSH 8.9p1, MySQL).
   - `Cloud VPC`: Microservice cluster (Kubernetes Ingress, Express API, PostgreSQL).
   - `Hardened Enclave`: Defense-in-depth posture (Patched OpenSSH 9.8p1, TLS 1.3).
7. Review the **Discovered Network Hosts** table and **Vulnerability Assessment Findings** table.
8. Click **Import to Graph** to generate an interactive Cytoscape topology.
9. Click **Execute Chained Pipeline** to solve Dijkstra, Edmonds-Karp, and verification.

---

## Live NIST NVD API 2.0 Lookup

NETCUT features on-demand vulnerability retrieval from the official NIST National Vulnerability Database API 2.0:
- Query any real CVE (e.g. `CVE-2024-6387`, `CVE-2021-41773`, `CVE-2017-0144`).
- Fetches real-time CVSS base score, severity rating, official NVD vulnerability descriptions, and vendor remediation advice.
- **Optional NVD API Key:** Set the environment variable `NVD_API_KEY` for higher query rate limits:
  ```powershell
  $env:NVD_API_KEY = "your-api-key-here"
  ```
- **Graceful Offline Fallback:** If internet access is unavailable or NIST rate limits are encountered, NETCUT falls back to its local curated signature base without interrupting operations.

---

## Curated CVE Intelligence Base

All signatures use genuine, verified CVE identifiers and CVSS ratings:

| CVE ID | Service / Component | Severity | CVSS | Vulnerability Title |
|---|---|---|---|---|
| **CVE-2024-6387** | OpenSSH 8.5p1 ≤ 9.7p1 | **Critical** | 9.8 | regreSSHion Pre-Auth RCE (glibc signal race) |
| **CVE-2023-38408** | OpenSSH < 9.3p2 | **High** | 8.1 | PKCS#11 Provider Arbitrary Code Execution |
| **CVE-2021-41773** | Apache HTTPD 2.4.49 / 2.4.50 | **Critical** | 9.8 | Path Normalization Traversal & RCE |
| **CVE-2022-31813** | Apache HTTPD < 2.4.54 | **Medium** | 6.5 | X-Forwarded-For Proxy Bypass |
| **CVE-2011-2523** | vsftpd 2.3.4 | **Critical** | 9.8 | Malicious Smiley Face Backdoor RCE |
| **CVE-2015-3306** | ProFTPD 1.3.5 | **Critical** | 9.8 | mod_copy Unauthenticated File Manipulation |
| **CVE-2017-0144** | Microsoft SMBv1 (Port 445) | **Critical** | 9.8 | EternalBlue Remote Kernel Code Execution |
| **CVE-2017-7494** | Samba 3.5.0 – 4.6.4 | **Critical** | 9.8 | SambaCry Shared Library Injection RCE |
| **CVE-2019-0708** | Microsoft RDP (Port 3389) | **High** | 8.5 | BlueKeep Pre-Authentication RCE |
| **CVE-2022-0543** | Redis (Port 6379) | **High** | 8.8 | Lua Sandbox Escape Remote Code Execution |
| **CVE-2021-23017** | Nginx 0.6.18 – 1.20.0 | **High** | 7.7 | DNS Resolver 1-Byte Memory Overwrite |
| **CVE-2019-9193** | PostgreSQL (Port 5432) | **High** | 8.8 | Superuser Command Execution via COPY PROGRAM |
| **CVE-2021-31166** | Microsoft IIS HTTP.sys | **Critical** | 9.8 | HTTP Protocol Stack Kernel Remote Code Execution |
| **CVE-2021-44228** | Java / Tomcat / Spring | **Critical** | 10.0 | Log4Shell JNDI Remote Code Execution |
| **CWE-319** | Telnet (Port 23) | **High** | 7.5 | Cleartext Administrative Protocol Exposure |
| **CWE-319** | FTP (Port 21) | **Medium** | 5.3 | Unencrypted Authentication Transmission |
| **CWE-200** | MySQL (Port 3306) | **Medium** | 6.5 | Direct Database Network Exposure |

---

## UI Themes & Design System

Switch between dark cybersecurity presets using the header selector:

1. **Cyber Cyan (Default):** Deep navy `#0B1120`, Electric Cyan `#00D4FF` accents, futuristic SOC aesthetic.
2. **Neon Violet:** Midnight `#0F0E1E`, Violet `#A78BFA` accents, modern cyberpunk aesthetic.
3. **Emerald Ops:** Dark charcoal `#091410`, Tactical Emerald `#34D399` accents, military SOC aesthetic.
4. **Crimson Alert:** Dark graphite `#180D10`, Crimson `#FB7185` accents, high-threat incident response aesthetic.

> 🔒 **Consistency Rule:** Vulnerability severity badges (**Critical** `#FB7185`, **High** `#FB923C`, **Medium** `#F59E0B`, **Low** `#60A5FA`, **Info** `#34D399`) remain visually immutable across all themes to preserve instant hazard identification.

---

## Running the Automated Test Suite

NETCUT includes 96 comprehensive tests covering algorithmic edge cases, security gates, Nmap output parsing, and CVE logic:

```powershell
python run_tests.py
```

### Module Breakdown
- `tests/test_algorithms.py`: Dijkstra shortest paths, Edmonds-Karp max-flow, unblockable edge handling, min-cut blocking verification (12 tests).
- `tests/test_budget.py`: Greedy budget defense limits, zero budget, surplus allocation (6 tests).
- `tests/test_frontend.py`: Static verification ensuring all JavaScript DOM selectors align with HTML IDs (1 test).
- `tests/test_scanner.py`: Command injection blocking, IP/CIDR syntax validation, broad sweep rejection, public CIDR protection, Nmap XML output parsing, missing binary handling (38 tests).
- `tests/test_vulnerability.py`: Version pattern matching, CVSS scores, NVD lookup fallback, multi-vulnerability hosts, clean host disclaimers, graph topology conversion (39 tests).

---

## Known Limitations & False Positives / Negatives

1. **Version-Based Heuristics:** Version matching analyzes service banners. Operating system vendors (such as Red Hat, Debian, or Ubuntu) frequently backport security fixes into older package versions without incrementing the upstream version number. This can produce false positives on properly backported systems.
2. **No Intrusive Exploitation:** NETCUT deliberately does not execute live exploits or payloads. A finding indicates potential exposure rather than confirmed exploitation.
3. **Absence of Findings Is Not Guaranteed Security:** A host reporting no CVE findings indicates only that its exposed services did not match known signatures. It does not certify the host is secure.
4. **Scope Boundaries:** Subnet sweeps are hard-capped at a `/24` subnet (256 addresses) and restricted to private RFC 1918 addresses to prevent accidental network flooding or unauthorized scanning.

---

## Legal & Authorized-Use Policy

> ⚖️ **Mandatory Compliance Notice:**
> Scanning networks without explicit, documented authorization is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030), the UK Computer Misuse Act 1990, and international cybersecurity laws.
>
> NETCUT must strictly be operated against networks you own or where you have received explicit written authorization from the system owner. The authors and institution disclaim all liability for unauthorized or misuse of this tool.
