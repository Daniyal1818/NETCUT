from fastapi import FastAPI, HTTPException
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


def validate(net: Network):
    ids = set(net.nodes)
    if len(ids) != len(net.nodes):
        raise HTTPException(400, "Node names unique hone chahiye")
    if net.entry not in ids or net.target not in ids:
        raise HTTPException(400, "Entry ya target network mein nahi hai")
    if net.entry == net.target:
        raise HTTPException(400, "Entry aur target alag hone chahiye")
    for e in net.edges:
        if e.src not in ids or e.dst not in ids:
            raise HTTPException(400, f"Edge {e.src}->{e.dst} ka node maujood nahi")
        if e.difficulty < 0 or e.cost < 0:
            raise HTTPException(400, "Weights negative nahi ho sakte")


@app.post("/api/analyze")
def analyze(net: Network):
    validate(net)
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