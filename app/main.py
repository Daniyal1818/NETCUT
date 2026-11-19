"""
NetCut - Backend Application Entry Point
FastAPI Application serving DAA Attack-Path Analysis, Minimum-Cut Defense Planner,
and Network Discovery & Vulnerability Assessment Engine.

Authors: Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)
Course: Design and Analysis of Algorithms (DAA)
Instructor: Ms. Tooba Sheikh
"""

import os
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp, BIG
from app.algorithms.budget import greedy_budget_defense
from app.scanner import (
    get_nmap_info,
    validate_scan_target,
    ScanTargetError,
    NmapScanner,
    SocketScanner,
)
from app.scanner.sample_scans import SAMPLE_SCANS
from app.vulnerability import (
    assess_network_hosts,
    convert_assessment_to_network,
    get_cve_details,
)

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    HTTPException = Exception
    StaticFiles = None
    BaseModel = object
    Field = lambda *args, **kwargs: None


class Edge(BaseModel if FASTAPI_AVAILABLE else object):
    src: str
    dst: str
    difficulty: float = 1.0
    cost: float = 1.0
    blockable: bool = True
    label: Optional[str] = None

    def model_dump(self):
        return {
            "src": self.src,
            "dst": self.dst,
            "difficulty": float(self.difficulty),
            "cost": float(self.cost),
            "blockable": bool(self.blockable),
            "label": self.label or "",
        }


class Network(BaseModel if FASTAPI_AVAILABLE else object):
    nodes: List[str]
    edges: List[Edge] = []
    entry: str
    target: str
    budget: Optional[float] = None


class ScanRequest(BaseModel if FASTAPI_AVAILABLE else object):
    target: str
    profile: Optional[str] = "fast"
    engine: Optional[str] = "auto"
    timeout: Optional[int] = 45


PRESETS = {
    "benchmark": {
        "title": "Academic Benchmark Network",
        "description": "Standard DAA course project benchmark containing 6 nodes and multiple divergent attack vectors.",
        "nodes": ["Laptop", "Workstation", "Mail", "FileServer", "AppServer", "DB"],
        "edges": [
            {"src": "Laptop", "dst": "Workstation", "difficulty": 2, "cost": 4, "blockable": True, "label": "SMB (Port 445)"},
            {"src": "Laptop", "dst": "Mail", "difficulty": 1, "cost": 3, "blockable": True, "label": "Phish / SMTP"},
            {"src": "Workstation", "dst": "FileServer", "difficulty": 3, "cost": 5, "blockable": True, "label": "NFS / RPC"},
            {"src": "Mail", "dst": "FileServer", "difficulty": 4, "cost": 2, "blockable": True, "label": "Internal Relay"},
            {"src": "Mail", "dst": "AppServer", "difficulty": 5, "cost": 3, "blockable": True, "label": "API Access"},
            {"src": "FileServer", "dst": "DB", "difficulty": 2, "cost": 6, "blockable": True, "label": "SQL Connect"},
            {"src": "AppServer", "dst": "DB", "difficulty": 1, "cost": 2, "blockable": True, "label": "Direct SQL Pool"},
        ],
        "entry": "Laptop",
        "target": "DB",
        "budget": 10.0,
    },
    "enterprise": {
        "title": "Enterprise Corporate DMZ",
        "description": "Multi-tier corporate architecture spanning perimeter DMZ, Active Directory domain, and Core Finance Vault.",
        "nodes": ["RemoteLaptop", "VPN_Gateway", "DMZ_Proxy", "ActiveDirectory", "InternalSwitch", "HR_Portal", "FinanceVault"],
        "edges": [
            {"src": "RemoteLaptop", "dst": "VPN_Gateway", "difficulty": 2, "cost": 8, "blockable": True, "label": "Credential Stuffing"},
            {"src": "RemoteLaptop", "dst": "DMZ_Proxy", "difficulty": 3, "cost": 4, "blockable": True, "label": "Web Exploit"},
            {"src": "VPN_Gateway", "dst": "ActiveDirectory", "difficulty": 4, "cost": 7, "blockable": True, "label": "Kerberoast"},
            {"src": "VPN_Gateway", "dst": "InternalSwitch", "difficulty": 2, "cost": 5, "blockable": True, "label": "VLAN Hop"},
            {"src": "DMZ_Proxy", "dst": "HR_Portal", "difficulty": 2, "cost": 3, "blockable": True, "label": "SSRF Injection"},
            {"src": "InternalSwitch", "dst": "ActiveDirectory", "difficulty": 3, "cost": 6, "blockable": True, "label": "LDAP Exploit"},
            {"src": "InternalSwitch", "dst": "HR_Portal", "difficulty": 2, "cost": 3, "blockable": True, "label": "Lateral SMB"},
            {"src": "ActiveDirectory", "dst": "FinanceVault", "difficulty": 2, "cost": 12, "blockable": True, "label": "Domain Admin Auth"},
            {"src": "HR_Portal", "dst": "FinanceVault", "difficulty": 6, "cost": 4, "blockable": True, "label": "SQL Pivot"},
        ],
        "entry": "RemoteLaptop",
        "target": "FinanceVault",
        "budget": 15.0,
    },
    "cloud": {
        "title": "Cloud VPC & Kubernetes Microservices",
        "description": "Modern cloud-native cluster: Ingress gateway, Auth Service, Billing Worker, Redis Cache, and PII DB.",
        "nodes": ["InternetAttacker", "IngressController", "AuthService", "PaymentGateway", "RedisCache", "PII_Database"],
        "edges": [
            {"src": "InternetAttacker", "dst": "IngressController", "difficulty": 1, "cost": 10, "blockable": True, "label": "HTTP Flood / RCE"},
            {"src": "IngressController", "dst": "AuthService", "difficulty": 3, "cost": 6, "blockable": True, "label": "JWT Bypass"},
            {"src": "IngressController", "dst": "PaymentGateway", "difficulty": 5, "cost": 8, "blockable": True, "label": "mTLS Tunnel"},
            {"src": "AuthService", "dst": "RedisCache", "difficulty": 2, "cost": 3, "blockable": True, "label": "Unauth Redis"},
            {"src": "RedisCache", "dst": "PaymentGateway", "difficulty": 2, "cost": 4, "blockable": True, "label": "Token Extraction"},
            {"src": "AuthService", "dst": "PII_Database", "difficulty": 6, "cost": 9, "blockable": True, "label": "Privilege Escalation"},
            {"src": "PaymentGateway", "dst": "PII_Database", "difficulty": 2, "cost": 5, "blockable": True, "label": "Encrypted JDBC"},
        ],
        "entry": "InternetAttacker",
        "target": "PII_Database",
        "budget": 12.0,
    },
    "scada": {
        "title": "Critical Infrastructure SCADA / ICS",
        "description": "Industrial control network modeling Purdue Enterprise Level 4 down to Level 0 Safety Instrumented System.",
        "nodes": ["ContractorUSB", "EngineeringWorkstation", "HistorianServer", "PLC_Gateway", "SafetySystem"],
        "edges": [
            {"src": "ContractorUSB", "dst": "EngineeringWorkstation", "difficulty": 1, "cost": 6, "blockable": True, "label": "Airgap Jump"},
            {"src": "ContractorUSB", "dst": "HistorianServer", "difficulty": 4, "cost": 4, "blockable": True, "label": "Modbus Sniff"},
            {"src": "EngineeringWorkstation", "dst": "PLC_Gateway", "difficulty": 2, "cost": 5, "blockable": True, "label": "Firmware Flash"},
            {"src": "HistorianServer", "dst": "PLC_Gateway", "difficulty": 3, "cost": 3, "blockable": True, "label": "OPC-UA Pivot"},
            {"src": "PLC_Gateway", "dst": "SafetySystem", "difficulty": 2, "cost": 8, "blockable": True, "label": "Stuxnet-Style Logic"},
        ],
        "entry": "ContractorUSB",
        "target": "SafetySystem",
        "budget": 11.0,
    },
}


def validate_network(net: Network):
    ids = set(net.nodes)
    if len(ids) != len(net.nodes):
        raise HTTPException(status_code=400, detail="All node identifiers must be distinct and unique.")
    if net.entry not in ids or net.target not in ids:
        raise HTTPException(
            status_code=400,
            detail=f"Specified entry point '{net.entry}' or target asset '{net.target}' does not exist in the network topology.",
        )
    if net.entry == net.target:
        raise HTTPException(
            status_code=400,
            detail="Attacker entry point and crown jewel target must be distinct nodes.",
        )
    if net.budget is not None and net.budget < 0:
        raise HTTPException(status_code=400, detail="Defense budget cannot be negative.")

    seen = set()
    for e in net.edges:
        if e.src not in ids or e.dst not in ids:
            raise HTTPException(
                status_code=400,
                detail=f"Edge '{e.src} -> {e.dst}' references an undefined host.",
            )
        if e.difficulty < 0 or e.cost < 0:
            raise HTTPException(
                status_code=400,
                detail="Exploit difficulty and remediation cost must be non-negative values.",
            )
        pair = (e.src, e.dst)
        if pair in seen:
            raise HTTPException(status_code=400, detail=f"Duplicate directed link {e.src} -> {e.dst} detected.")
        seen.add(pair)


def compute_pipeline(net_dict: Dict[str, Any]) -> Dict[str, Any]:
    nodes = net_dict["nodes"]
    raw_edges = net_dict.get("edges", [])
    entry = net_dict["entry"]
    target = net_dict["target"]
    budget_val = net_dict.get("budget")
    budget = float(budget_val) if budget_val is not None else float("inf")

    # Input validation (the native server does not use validate_network)
    if not isinstance(nodes, list) or len(set(nodes)) != len(nodes):
        raise ValueError("Node identifiers must be a list of unique names.")
    if entry not in nodes or target not in nodes:
        raise ValueError("Entry point and target must exist in the node list.")
    if entry == target:
        raise ValueError("Entry point and target must be different nodes.")
    if budget < 0:
        raise ValueError("Budget cannot be negative.")
    for e in raw_edges:
        g = (lambda k, d=None: getattr(e, k, d)) if hasattr(e, "model_dump") else (lambda k, d=None: e.get(k, d))
        if g("src") not in nodes or g("dst") not in nodes:
            raise ValueError(f"Link {g('src')} -> {g('dst')} references an unknown host.")
        if float(g("difficulty", 1.0)) < 0 or float(g("cost", 1.0)) < 0:
            raise ValueError("Difficulty and cost must be non-negative.")

    edges = []
    for e in raw_edges:
        if hasattr(e, "model_dump"):
            edges.append(e.model_dump())
        else:
            edges.append({
                "src": e["src"],
                "dst": e["dst"],
                "difficulty": float(e.get("difficulty", 1.0)),
                "cost": float(e.get("cost", 1.0)),
                "blockable": bool(e.get("blockable", True)),
                "label": e.get("label", ""),
            })

    # Step 1: Pre-defense Dijkstra
    before_dist, before_path, dijkstra_meta = dijkstra(
        nodes, edges, entry, target, return_details=True
    )

    # Step 2: Edmonds-Karp Min-Cut
    flow, cut, ek_meta = edmonds_karp(
        nodes, edges, entry, target, return_details=True
    )
    fully_blockable = flow < BIG

    # Choose defense strategy based on budget availability
    if fully_blockable and flow <= budget:
        strategy = "min_cut"
        defense = cut
        spent = flow
    else:
        strategy = "greedy"
        defense, spent = greedy_budget_defense(nodes, edges, entry, target, budget)

    # Step 3: Sever defensive links
    keys = {(e["src"], e["dst"]) for e in defense}
    remaining = [e for e in edges if (e["src"], e["dst"]) not in keys]

    # Step 4: Post-defense Dijkstra verification
    after_dist, after_path, verify_meta = dijkstra(
        nodes, remaining, entry, target, return_details=True
    )

    is_verified = (after_path == [])
    shortfall = max(0.0, flow - budget_val) if (fully_blockable and budget_val is not None) else 0.0

    budget_status = None
    if budget_val is not None:
        allocated = float(budget_val)
        required = float(flow) if fully_blockable else float(spent)
        is_feasible = (spent <= allocated)
        surplus = allocated - spent
        utilization = (spent / allocated * 100.0) if allocated > 0 else 0.0
        budget_status = {
            "allocated": round(allocated, 2),
            "required": round(flow, 2) if fully_blockable else round(spent, 2),
            "spent": round(spent, 2),
            "feasible": is_feasible,
            "surplus": round(surplus, 2),
            "shortfall": round(shortfall, 2),
            "utilization_pct": round(utilization, 1),
        }

    return {
        # Core response fields
        "attack_path": before_path,
        "attack_difficulty": before_dist,
        "strategy": strategy,
        "min_cut_cost": flow if fully_blockable else None,
        "cut_edges": cut,
        "cut_cost": flow,
        "defense_edges": defense,
        "defense_cost": spent,
        "budget": budget_val,
        "shortfall": shortfall,
        "verified": is_verified,
        "path_after_fix": after_path,
        "difficulty_after_fix": after_dist,

        # Extended DAA analytics
        "edge_steps": dijkstra_meta.get("edge_steps", []),
        "source_partition": ek_meta.get("source_partition", []),
        "target_partition": ek_meta.get("target_partition", []),
        "augmenting_paths": ek_meta.get("augmenting_paths", []),
        "augmenting_path_count": len(ek_meta.get("augmenting_paths", [])),
        "budget_status": budget_status,
        "metrics": {
            "dijkstra_runtime_ms": dijkstra_meta.get("execution_time_ms", 0.0),
            "edmonds_karp_runtime_ms": ek_meta.get("execution_time_ms", 0.0),
            "verification_runtime_ms": verify_meta.get("execution_time_ms", 0.0),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "cut_edge_count": len(defense),
            "remaining_edges": len(remaining),
        },
    }


def execute_network_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = payload.get("target", "").strip()
    profile = payload.get("profile", "fast")
    engine_pref = payload.get("engine", "auto")
    timeout = int(payload.get("timeout", 45))

    # Validate target
    try:
        val_result = validate_scan_target(target)
    except ScanTargetError as ex:
        raise ValueError(str(ex))

    nmap_scanner = NmapScanner()
    use_nmap = False

    if engine_pref == "nmap":
        if not nmap_scanner.is_available():
            raise ValueError("Nmap is not installed on this system. Please install Nmap or select 'auto' to use socket fallback.")
        use_nmap = True
    elif engine_pref == "socket":
        use_nmap = False
    else:  # auto
        use_nmap = nmap_scanner.is_available()

    if use_nmap:
        scan_res = nmap_scanner.scan(target, profile=profile, timeout_seconds=timeout)
    else:
        socket_scanner = SocketScanner()
        scan_res = socket_scanner.scan(target, timeout_seconds=timeout)

    # Perform vulnerability assessment on discovered hosts
    assessment = assess_network_hosts(scan_res.hosts)

    # Convert to NETCUT topology for graph visualization
    generated_network = convert_assessment_to_network(assessment)

    return {
        "scan": scan_res.to_dict(),
        "assessment": assessment,
        "generated_network": generated_network,
        "engine_used": "nmap" if use_nmap else "socket_fallback",
    }


if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="NetCut - Attack-Path Analysis & Min-Cut Defense Planner",
        description="DAA Decision-Support Engine using Dijkstra and Edmonds-Karp with Nmap Discovery and CVE Assessment.",
        version="2.1.0",
    )

    @app.post("/api/analyze")
    def analyze(net: Network) -> Dict[str, Any]:
        validate_network(net)
        return compute_pipeline({
            "nodes": net.nodes,
            "edges": [e.model_dump() for e in net.edges],
            "entry": net.entry,
            "target": net.target,
            "budget": net.budget,
        })

    @app.get("/api/presets")
    def get_presets() -> Dict[str, Any]:
        return PRESETS

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "operational", "engine": "NetCut DAA Chained v2.1 (FastAPI)"}

    @app.get("/api/scanner/status")
    def scanner_status() -> Dict[str, Any]:
        return get_nmap_info()

    @app.post("/api/scanner/scan")
    def run_scan(req: ScanRequest) -> Dict[str, Any]:
        try:
            return execute_network_scan(req.model_dump())
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as ex:
            raise HTTPException(status_code=500, detail=f"Scan execution error: {ex}")

    @app.get("/api/scanner/samples")
    def get_scan_samples() -> Dict[str, Any]:
        return SAMPLE_SCANS

    @app.post("/api/scanner/load-sample")
    def load_scan_sample(payload: Dict[str, str]) -> Dict[str, Any]:
        sample_key = payload.get("sample_key", "corporate_subnet")
        sample = SAMPLE_SCANS.get(sample_key)
        if not sample:
            raise HTTPException(status_code=404, detail=f"Sample '{sample_key}' not found.")
        assessment = assess_network_hosts(sample["hosts"])
        generated_network = convert_assessment_to_network(assessment)
        return {
            "sample_key": sample_key,
            "title": sample["title"],
            "description": sample["description"],
            "scan": {
                "target": sample["target"],
                "engine": "sample_benchmark",
                "success": True,
                "hosts": sample["hosts"],
                "hosts_count": len(sample["hosts"]),
            },
            "assessment": assessment,
            "generated_network": generated_network,
        }

    @app.get("/api/cve/lookup")
    def cve_lookup_get(cve_id: str = "") -> Dict[str, Any]:
        return get_cve_details(cve_id)

    @app.post("/api/cve/lookup")
    def cve_lookup_post(payload: Dict[str, str]) -> Dict[str, Any]:
        return get_cve_details(payload.get("cve_id", ""))

    static_path = os.path.join(BASE_DIR, "static")
    if os.path.exists(static_path):
        app.mount("/", StaticFiles(directory=static_path, html=True), name="static")
else:
    app = None


if __name__ == "__main__":
    from server import main
    main()
