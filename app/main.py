from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp, BIG
from app.algorithms.budget import greedy_budget_defense

app = FastAPI()


class Edge(BaseModel):
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


def validate(net: Network):
    ids = set(net.nodes)
    if len(ids) != len(net.nodes):
        raise HTTPException(400, "Node names unique hone chahiye")
    if net.entry not in ids or net.target not in ids:
        raise HTTPException(400, "Entry ya target network mein nahi hai")
    if net.entry == net.target:
        raise HTTPException(400, "Entry aur target alag hone chahiye")
    if net.budget is not None and net.budget < 0:
        raise HTTPException(400, "Budget negative nahi ho sakta")
    seen = set()
    for e in net.edges:
        if e.src not in ids or e.dst not in ids:
            raise HTTPException(400, f"Edge {e.src}->{e.dst} ka node maujood nahi")
        if e.difficulty < 0 or e.cost < 0:
            raise HTTPException(400, "Weights negative nahi ho sakte")
        if (e.src, e.dst) in seen:
            raise HTTPException(400, f"Link {e.src}->{e.dst} do dafa hai")
        seen.add((e.src, e.dst))


@app.post("/api/analyze")
def analyze(net: Network):
    validate(net)
    nodes = net.nodes
    edges = [e.model_dump() for e in net.edges]
    budget = net.budget if net.budget is not None else float("inf")

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

    shortfall = 0.0
    if fully_blockable and net.budget is not None:
        shortfall = max(0.0, flow - net.budget)

    return {
        "attack_path": before_path,
        "attack_difficulty": before_dist,
        "strategy": strategy,
        "min_cut_cost": flow if fully_blockable else None,
        "budget": net.budget,
        "shortfall": shortfall,
        "defense_edges": defense,
        "defense_cost": spent,
        "verified": after_path == [],
        "path_after_fix": after_path,
        "difficulty_after_fix": after_dist,
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")