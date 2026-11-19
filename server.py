"""
NetCut - Decision-Support Web Server
Zero-dependency, high-reliability server supporting both localhost and 127.0.0.1.

Can be run with:
    python server.py
    python run.py
    python app/main.py
"""

import argparse
import json
import mimetypes
import os
import socket
import sys
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any, Dict

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.main import (
    PRESETS,
    compute_pipeline,
    execute_network_scan,
    SAMPLE_SCANS,
    get_nmap_info,
)

STATIC_DIR = os.path.join(BASE_DIR, "static")

# Explicit MIME mappings to avoid Windows registry issues
mimetypes.init()
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("text/html", ".html")
mimetypes.add_type("application/json", ".json")


class NetCutHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        clean_path = self.path.split("?")[0]
        if clean_path == "/api/health":
            self.send_json_response(200, {"status": "operational", "engine": "NetCut DAA Chained v2.1"})
        elif clean_path == "/api/presets":
            self.send_json_response(200, PRESETS)
        elif clean_path == "/api/scanner/status":
            self.send_json_response(200, get_nmap_info())
        elif clean_path == "/api/scanner/samples":
            self.send_json_response(200, SAMPLE_SCANS)
        elif clean_path == "/" or clean_path == "":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        clean_path = self.path.split("?")[0]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if clean_path == "/api/analyze":
            try:
                result = compute_pipeline(payload)
                self.send_json_response(200, result)
            except ValueError as ve:
                self.send_json_response(400, {"detail": str(ve)})
            except Exception as ex:
                self.send_json_response(500, {"detail": f"Internal computation error: {str(ex)}"})

        elif clean_path == "/api/scanner/scan":
            try:
                result = execute_network_scan(payload)
                self.send_json_response(200, result)
            except ValueError as ve:
                self.send_json_response(400, {"detail": str(ve)})
            except Exception as ex:
                self.send_json_response(500, {"detail": f"Scan error: {str(ex)}"})

        elif clean_path == "/api/scanner/load-sample":
            sample_key = payload.get("sample_key", "corporate_subnet")
            sample = SAMPLE_SCANS.get(sample_key)
            if not sample:
                self.send_json_response(404, {"detail": f"Sample '{sample_key}' not found."})
                return

            from app.vulnerability import assess_network_hosts, convert_assessment_to_network
            assessment = assess_network_hosts(sample["hosts"])
            generated_network = convert_assessment_to_network(assessment)
            self.send_json_response(200, {
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
            })

        else:
            self.send_json_response(404, {"detail": "Endpoint not found."})

    def do_OPTIONS(self):
        # Handle CORS preflight
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

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


def is_port_available(port: int, host: str = "0.0.0.0") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description="NetCut Decision-Support Engine")
    parser.add_argument("--port", type=int, default=8000, help="Initial server port (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Server host binding (default: 0.0.0.0 for localhost & 127.0.0.1)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--fastapi", action="store_true", help="Force FastAPI/uvicorn runner if available")
    args = parser.parse_args()

    # Try FastAPI if explicitly requested and available
    if args.fastapi:
        try:
            import uvicorn
            print(f"[NetCut] Starting with Uvicorn/FastAPI on http://localhost:{args.port}")
            uvicorn.run("app.main:app", host="0.0.0.0", port=args.port, reload=True)
            return
        except ImportError:
            print("[NetCut] FastAPI/Uvicorn not installed. Falling back to native server...")

    port = args.port
    # Find next available port if port is already in use
    while not is_port_available(port, args.host) and port < args.port + 20:
        print(f"[NetCut] Port {port} is occupied, trying port {port + 1}...")
        port += 1

    server_address = (args.host, port)
    httpd = HTTPServer(server_address, NetCutHTTPHandler)

    local_url = f"http://localhost:{port}"
    ip_url = f"http://127.0.0.1:{port}"

    print("=" * 74)
    print("  NETCUT // Attack-Path Analysis & Minimum-Cut Defense Planner")
    print("  Hybrid Engine: DAA Graph Analysis + Nmap Discovery + CVE Assessment")
    print("  Course: Design and Analysis of Algorithms (DAA)")
    print("  Team: Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)")
    print("  Instructor: Ms. Tooba Sheikh")
    print("-" * 74)
    print(f"  [+] Localhost Access: {local_url}")
    print(f"  [+] Direct IP Access: {ip_url}")
    print("  [+] API Endpoints:   /api/analyze | /api/scanner/scan | /api/presets")
    print("  [+] Press Ctrl+C in this terminal to stop the server.")
    print("=" * 74)

    if not args.no_browser:
        try:
            webbrowser.open(local_url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[NetCut] Server shut down cleanly.")
        httpd.server_close()


if __name__ == "__main__":
    main()
