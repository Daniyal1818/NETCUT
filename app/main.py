"""
NetCut - Backend Application Entry Point
FastAPI Application serving DAA Attack-Path Analysis & Minimum-Cut Defense Planner.

Authors: Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)
Course: Design and Analysis of Algorithms (DAA)
Instructor: Ms. Tooba Sheikh
"""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp, BIG
from app.algorithms.budget import greedy_budget_defense

app = FastAPI(
    title="NetCut - Attack-Path Analysis & Min-Cut Defense Planner",
    description="DAA Decision-Support Engine using Dijkstra and Edmonds-Karp algorithms.",
    version="2.0.0",
)


class Edge(BaseModel):
<<<<<<< HEAD
    src: str
    dst: str
    difficulty: float
    cost: float
    blockable: bool = True


class Network(BaseModel):
    nodes: list[str]
    edges: list[Edge]
    entry: str
    target: str
    budget: float | None = None
=======
    src: str = Field(..., description="Source node identifier")
    dst: str = Field(..., description="Destination node identifier")
    difficulty: float = Field(..., ge=0, description="Exploit resistance/difficulty for attacker (weight for Dijkstra)")
    cost: float = Field(..., ge=0, description="Remediation or firewall deployment cost (capacity for Edmonds-Karp)")
    label: Optional[str] = Field(None, description="Optional connection protocol or port name")


class Network(BaseModel):
    nodes: List[str] = Field(..., min_length=2, description="List of unique node identifiers in network")
    edges: List[Edge] = Field(default_factory=list, description="List of directed edges connecting nodes")
    entry: str = Field(..., description="Threat actor entry point node")
    target: str = Field(..., description="Critical crown jewel asset node")
    budget: Optional[float] = Field(None, ge=0, description="Optional defense budget limit")
>>>>>>> 18b5934 (major changes)


PRESETS = {
    "benchmark": {
        "title": "Academic Benchmark Network",
        "description": "Standard DAA course project benchmark containing 6 nodes and multiple divergent attack vectors.",
        "nodes": ["Laptop", "Workstation", "Mail", "FileServer", "AppServer", "DB"],
        "edges": [
            {"src": "Laptop", "dst": "Workstation", "difficulty": 2, "cost": 4, "label": "SMB (Port 445)"},
            {"src": "Laptop", "dst": "Mail", "difficulty": 1, "cost": 3, "label": "Phish / SMTP"},
            {"src": "Workstation", "dst": "FileServer", "difficulty": 3, "cost": 5, "label": "NFS / RPC"},
            {"src": "Mail", "dst": "FileServer", "difficulty": 4, "cost": 2, "label": "Internal Relay"},
            {"src": "Mail", "dst": "AppServer", "difficulty": 5, "cost": 3, "label": "API Access"},
            {"src": "FileServer", "dst": "DB", "difficulty": 2, "cost": 6, "label": "SQL Connect"},
            {"src": "AppServer", "dst": "DB", "difficulty": 1, "cost": 2, "label": "Direct SQL Pool"},
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
            {"src": "RemoteLaptop", "dst": "VPN_Gateway", "difficulty": 2, "cost": 8, "label": "Credential Stuffing"},
            {"src": "RemoteLaptop", "dst": "DMZ_Proxy", "difficulty": 3, "cost": 4, "label": "Web Exploit"},
            {"src": "VPN_Gateway", "dst": "ActiveDirectory", "difficulty": 4, "cost": 7, "label": "Kerberoast"},
            {"src": "VPN_Gateway", "dst": "InternalSwitch", "difficulty": 2, "cost": 5, "label": "VLAN Hop"},
            {"src": "DMZ_Proxy", "dst": "HR_Portal", "difficulty": 2, "cost": 3, "label": "SSRF Injection"},
            {"src": "InternalSwitch", "dst": "ActiveDirectory", "difficulty": 3, "cost": 6, "label": "LDAP Exploit"},
            {"src": "InternalSwitch", "dst": "HR_Portal", "difficulty": 2, "cost": 3, "label": "Lateral SMB"},
            {"src": "ActiveDirectory", "dst": "FinanceVault", "difficulty": 2, "cost": 12, "label": "Domain Admin Auth"},
            {"src": "HR_Portal", "dst": "FinanceVault", "difficulty": 6, "cost": 4, "label": "SQL Pivot"},
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
            {"src": "InternetAttacker", "dst": "IngressController", "difficulty": 1, "cost": 10, "label": "HTTP Flood / RCE"},
            {"src": "IngressController", "dst": "AuthService", "difficulty": 3, "cost": 6, "label": "JWT Bypass"},
            {"src": "IngressController", "dst": "PaymentGateway", "difficulty": 5, "cost": 8, "label": "mTLS Tunnel"},
            {"src": "AuthService", "dst": "RedisCache", "difficulty": 2, "cost": 3, "label": "Unauth Redis"},
            {"src": "RedisCache", "dst": "PaymentGateway", "difficulty": 2, "cost": 4, "label": "Token Extraction"},
            {"src": "AuthService", "dst": "PII_Database", "difficulty": 6, "cost": 9, "label": "Privilege Escalation"},
            {"src": "PaymentGateway", "dst": "PII_Database", "difficulty": 2, "cost": 5, "label": "Encrypted JDBC"},
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
            {"src": "ContractorUSB", "dst": "EngineeringWorkstation", "difficulty": 1, "cost": 6, "label": "Airgap Jump"},
            {"src": "ContractorUSB", "dst": "HistorianServer", "difficulty": 4, "cost": 4, "label": "Modbus Sniff"},
            {"src": "EngineeringWorkstation", "dst": "PLC_Gateway", "difficulty": 2, "cost": 5, "label": "Firmware Flash"},
            {"src": "HistorianServer", "dst": "PLC_Gateway", "difficulty": 3, "cost": 3, "label": "OPC-UA Pivot"},
            {"src": "PLC_Gateway", "dst": "SafetySystem", "difficulty": 2, "cost": 8, "label": "Stuxnet-Style Logic"},
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
<<<<<<< HEAD
        raise HTTPException(400, "Entry aur target alag hone chahiye")
    if net.budget is not None and net.budget < 0:
        raise HTTPException(400, "Budget negative nahi ho sakta")
    seen = set()
=======
        raise HTTPException(
            status_code=400,
            detail="Attacker entry point and crown jewel target must be distinct nodes.",
        )
>>>>>>> 18b5934 (major changes)
    for e in net.edges:
        if e.src not in ids or e.dst not in ids:
            raise HTTPException(
                status_code=400,
                detail=f"Edge '{e.src} -> {e.dst}' references an undefined host.",
            )
        if e.difficulty < 0 or e.cost < 0:
<<<<<<< HEAD
            raise HTTPException(400, "Weights negative nahi ho sakte")
        if (e.src, e.dst) in seen:
            raise HTTPException(400, f"Link {e.src}->{e.dst} do dafa hai")
        seen.add((e.src, e.dst))
=======
            raise HTTPException(
                status_code=400,
                detail="Exploit difficulty and remediation cost must be non-negative values.",
            )
>>>>>>> 18b5934 (major changes)


@app.post("/api/analyze")
def analyze(net: Network) -> Dict[str, Any]:
    """
    Executes the chained DAA security defense pipeline:
    1. Pre-defense Dijkstra shortest path: Identifies the primary attack vector of least resistance.
    2. Edmonds-Karp max-flow min-cut: Computes the optimal set of defensive severances minimizing cost.
    3. Post-defense Dijkstra verification: Verifies that crown jewel is isolated (no attack path remains).
    4. Budget constraint verification: Evaluates defense cost against operational budget limit.
    """
    validate_network(net)
    nodes = net.nodes
    edges = [e.model_dump() for e in net.edges]
    budget = net.budget if net.budget is not None else float("inf")

<<<<<<< HEAD
    before_dist, before_path = dijkstra(nodes, edges, net.entry, net.target)
    flow, cut = edmonds_karp(nodes, edges, net.entry, net.target)
    fully_blockable = flow < BIG

    if fully_blockable and flow <= budget:
        strategy = "min_cut"
        defense, spent = cut, flow
    else:
        strategy = "greedy"
        defense, spent = greedy_budget_defense(
            nodes, edges, net.entry, net.target, budget)

    keys = {(e["src"], e["dst"]) for e in defense}
    remaining = [e for e in edges if (e["src"], e["dst"]) not in keys]
    after_dist, after_path = dijkstra(nodes, remaining, net.entry, net.target)
=======
    # Step 1: Pre-defense attack vector discovery using Dijkstra
    before_dist, before_path, dijkstra_meta = dijkstra(
        nodes, edges, net.entry, net.target, return_details=True
    )

    # Step 2: Compute optimal minimum cut using Edmonds-Karp
    max_flow, cut, ek_meta = edmonds_karp(
        nodes, edges, net.entry, net.target, return_details=True
    )

    # Step 3: Remove cut edges to produce residual defense topology
    cut_keys = {(e["src"], e["dst"]) for e in cut}
    remaining_edges = [e for e in edges if (e["src"], e["dst"]) not in cut_keys]

    # Step 4: Post-defense verification using Dijkstra
    after_dist, after_path, verify_meta = dijkstra(
        nodes, remaining_edges, net.entry, net.target, return_details=True
    )

    is_verified = (after_path == [])

    # Budget and operational constraint evaluation
    budget_status = None
    if net.budget is not None:
        required = float(max_flow)
        allocated = float(net.budget)
        is_feasible = required <= allocated
        surplus = allocated - required
        utilization = (required / allocated * 100.0) if allocated > 0 else 0.0
        budget_status = {
            "allocated": round(allocated, 2),
            "required": round(required, 2),
            "feasible": is_feasible,
            "surplus": round(surplus, 2),
            "utilization_pct": round(utilization, 1),
        }
>>>>>>> 18b5934 (major changes)

    shortfall = 0.0
    if fully_blockable and net.budget is not None:
        shortfall = max(0.0, flow - net.budget)

    return {
        # Core response fields (backward compatible)
        "attack_path": before_path,
        "attack_difficulty": before_dist,
<<<<<<< HEAD
        "strategy": strategy,
        "min_cut_cost": flow if fully_blockable else None,
        "budget": net.budget,
        "shortfall": shortfall,
        "defense_edges": defense,
        "defense_cost": spent,
        "verified": after_path == [],
        "path_after_fix": after_path,
        "difficulty_after_fix": after_dist,
=======
        "cut_edges": cut,
        "cut_cost": max_flow,
        "verified": is_verified,
        "path_after_fix": after_path,

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
            "cut_edge_count": len(cut),
            "remaining_edges": len(remaining_edges),
        },
>>>>>>> 18b5934 (major changes)
    }


@app.get("/api/presets")
def get_presets() -> Dict[str, Any]:
    """Returns curated enterprise & benchmark network topologies."""
    return PRESETS


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "operational", "engine": "NetCut DAA Chained v2.0"}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
