from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp

app = FastAPI()

class Edge(BaseModel):
    src: str
    dst: str
    difficulty: float
    cost: float

class Network(BaseModel):
    nodes: list[str]
    edges: list[Edge]
    entry: str
    target: str

@app.post("/api/analyze")
def analyze(net: Network):
    nodes = net.nodes
    edges = [e.model_dump() for e in net.edges]

    before_dist, before_path = dijkstra(nodes, edges, net.entry, net.target)
    flow, cut = edmonds_karp(nodes, edges, net.entry, net.target)

    cut_keys = {(e["src"], e["dst"]) for e in cut}
    remaining = [e for e in edges if (e["src"], e["dst"]) not in cut_keys]
    after_dist, after_path = dijkstra(nodes, remaining, net.entry, net.target)

    return {
        "attack_path": before_path,
        "attack_difficulty": before_dist,
        "cut_edges": cut,
        "cut_cost": flow,
        "verified": after_path == [],
        "path_after_fix": after_path,
    }

app.mount("/", StaticFiles(directory="static", html=True), name="static")