"""
NetCut - Standalone Decision-Support Server
Zero-Dependency Standard Library Fallback + FastAPI/Uvicorn Launcher.

Allows NetCut to run out-of-the-box on ANY Python 3.8+ system without needing pip packages.

Usage:
    python server.py              # Starts on http://127.0.0.1:8000
    python server.py --port 5000  # Starts on custom port
"""

import argparse
import json
import mimetypes
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any, Dict

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp

STATIC_DIR = os.path.join(BASE_DIR, "static")

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


def run_pipeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    nodes = payload.get("nodes", [])
    raw_edges = payload.get("edges", [])
    entry = payload.get("entry")
    target = payload.get("target")
    budget = payload.get("budget")

    if not isinstance(nodes, list) or len(nodes) < 2:
        raise ValueError("Network topology requires at least 2 hosts.")

    node_set = set(nodes)
    if len(node_set) != len(nodes):
        raise ValueError("All host identifiers must be distinct and unique.")
    if entry not in node_set or target not in node_set:
        raise ValueError(f"Threat entry '{entry}' or target '{target}' does not exist in the network topology.")
    if entry == target:
        raise ValueError("Threat entry point and crown jewel target must be distinct nodes.")

    edges = []
    for e in raw_edges:
        src = e.get("src")
        dst = e.get("dst")
        if src not in node_set or dst not in node_set:
            raise ValueError(f"Edge '{src} -> {dst}' references an undefined host.")
        diff = float(e.get("difficulty", 1.0))
        cost = float(e.get("cost", 1.0))
        if diff < 0 or cost < 0:
            raise ValueError("Exploit difficulty and remediation cost must be non-negative values.")
        edges.append({
            "src": src,
            "dst": dst,
            "difficulty": diff,
            "cost": cost,
            "label": e.get("label", f"diff {diff} / cost {cost}"),
        })

    # Step 1: Pre-defense Dijkstra
    before_dist, before_path, dijkstra_meta = dijkstra(
        nodes, edges, entry, target, return_details=True
    )

    # Step 2: Edmonds-Karp Min-Cut
    max_flow, cut, ek_meta = edmonds_karp(
        nodes, edges, entry, target, return_details=True
    )

    # Step 3: Remove cut edges to produce residual defense topology
    cut_keys = {(e["src"], e["dst"]) for e in cut}
    remaining_edges = [e for e in edges if (e["src"], e["dst"]) not in cut_keys]

    # Step 4: Post-defense Dijkstra verification
    after_dist, after_path, verify_meta = dijkstra(
        nodes, remaining_edges, entry, target, return_details=True
    )

    is_verified = (after_path == [])

    # Budget status
    budget_status = None
    if budget is not None:
        try:
            allocated = float(budget)
            required = float(max_flow)
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
        except (ValueError, TypeError):
            pass

    return {
        "attack_path": before_path,
        "attack_difficulty": before_dist,
        "cut_edges": cut,
        "cut_cost": max_flow,
        "verified": is_verified,
        "path_after_fix": after_path,
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
    }


class NetCutHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/api/health":
            self.send_json_response(200, {"status": "operational", "engine": "NetCut DAA Chained v2.0 (Native Server)"})
        elif self.path == "/api/presets":
            self.send_json_response(200, PRESETS)
        else:
            # Map root to index.html
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(body)
                result = run_pipeline(payload)
                self.send_json_response(200, result)
            except ValueError as ve:
                self.send_json_response(400, {"detail": str(ve)})
            except Exception as ex:
                self.send_json_response(500, {"detail": f"Internal computation error: {str(ex)}"})
        else:
            self.send_json_response(404, {"detail": "Endpoint not found."})

    def send_json_response(self, code: int, data: Any):
        content = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        # Clean terminal output
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


def main():
    parser = argparse.ArgumentParser(description="NetCut Decision-Support Engine")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--fastapi", action="store_true", help="Force FastAPI/uvicorn runner if available")
    args = parser.parse_args()

    # Try FastAPI if requested
    if args.fastapi:
        try:
            import uvicorn
            print(f"[NetCut] Starting with Uvicorn/FastAPI on http://{args.host}:{args.port}")
            uvicorn.run("app.main:app", host=args.host, port=args.port, reload=True)
            return
        except ImportError:
            print("[NetCut] FastAPI/Uvicorn not found. Falling back to native high-performance HTTP server...")

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, NetCutHTTPHandler)
    print("=" * 70)
    print("  NETCUT // Attack-Path Analysis & Minimum-Cut Defense Planner")
    print("  DAA Complex Project - Muhammad Ibrahim & Muhammad Daniyal Akbar")
    print(f"  Live Console: http://{args.host}:{args.port}")
    print("  Endpoints: /api/analyze | /api/presets | /api/health")
    print("  Press Ctrl+C to terminate.")
    print("=" * 70)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[NetCut] Server shut down cleanly.")
        httpd.server_close()


if __name__ == "__main__":
    main()
