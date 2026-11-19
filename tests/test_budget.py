
from app.algorithms.budget import greedy_budget_defense
from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp, BIG


def E(src, dst, difficulty, cost, blockable=True):
    return {"src": src, "dst": dst, "difficulty": difficulty,
            "cost": cost, "blockable": blockable}


NODES = ["Laptop", "Workstation", "Mail", "FileServer", "AppServer", "DB"]
EDGES = [
    E("Laptop", "Workstation", 2, 4),
    E("Laptop", "Mail", 1, 3),
    E("Workstation", "FileServer", 3, 5),
    E("Mail", "FileServer", 4, 2),
    E("Mail", "AppServer", 5, 3),
    E("FileServer", "DB", 2, 6),
    E("AppServer", "DB", 1, 2),
]


def test_greedy_zero_budget_removes_nothing():
    removed, spent = greedy_budget_defense(NODES, EDGES, "Laptop", "DB", 0)
    assert removed == []
    assert spent == 0


def test_greedy_never_exceeds_budget():
    removed, spent = greedy_budget_defense(NODES, EDGES, "Laptop", "DB", 5)
    assert spent <= 5
    assert spent == sum(e["cost"] for e in removed)


def test_greedy_below_mincut_cannot_block():
    # min-cut = 7, budget 6 se poora block mumkin nahi
    removed, spent = greedy_budget_defense(NODES, EDGES, "Laptop", "DB", 6)
    keys = {(e["src"], e["dst"]) for e in removed}
    remaining = [e for e in EDGES if (e["src"], e["dst"]) not in keys]
    dist, path = dijkstra(NODES, remaining, "Laptop", "DB")
    assert path != []
    assert spent <= 6


def test_greedy_unlimited_budget_blocks_everything():
    removed, spent = greedy_budget_defense(NODES, EDGES, "Laptop", "DB", float("inf"))
    keys = {(e["src"], e["dst"]) for e in removed}
    remaining = [e for e in EDGES if (e["src"], e["dst"]) not in keys]
    dist, path = dijkstra(NODES, remaining, "Laptop", "DB")
    assert path == []
    assert spent >= 7          # greedy kabhi min-cut (7) se sasta nahi ho sakta


def test_unblockable_chain_has_no_finite_cut():
    nodes = ["A", "B", "C"]
    edges = [E("A", "B", 1, 1, blockable=False), E("B", "C", 1, 1, blockable=False)]
    flow, cut = edmonds_karp(nodes, edges, "A", "C")
    assert flow >= BIG


def test_unblockable_edge_never_in_min_cut():
    nodes = ["S", "A", "T"]
    edges = [E("S", "A", 1, 10, blockable=False), E("A", "T", 1, 3)]
    flow, cut = edmonds_karp(nodes, edges, "S", "T")
    assert flow == 3
    assert {(e["src"], e["dst"]) for e in cut} == {("A", "T")}