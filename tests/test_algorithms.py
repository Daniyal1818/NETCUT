from app.algorithms.dijkstra import dijkstra
from app.algorithms.edmonds_karp import edmonds_karp


def E(src, dst, difficulty, cost):
    return {"src": src, "dst": dst, "difficulty": difficulty, "cost": cost}


SAMPLE_NODES = ["Laptop", "Workstation", "Mail", "FileServer", "AppServer", "DB"]
SAMPLE_EDGES = [
    E("Laptop", "Workstation", 2, 4),
    E("Laptop", "Mail", 1, 3),
    E("Workstation", "FileServer", 3, 5),
    E("Mail", "FileServer", 4, 2),
    E("Mail", "AppServer", 5, 3),
    E("FileServer", "DB", 2, 6),
    E("AppServer", "DB", 1, 2),
]


# ---------- Dijkstra ----------

def test_dijkstra_picks_cheaper_path():
    nodes = ["A", "B", "C"]
    edges = [E("A", "B", 1, 1), E("B", "C", 2, 1), E("A", "C", 10, 1)]
    dist, path = dijkstra(nodes, edges, "A", "C")
    assert dist == 3
    assert path == ["A", "B", "C"]


def test_dijkstra_no_path():
    nodes = ["A", "B", "C"]
    edges = [E("A", "B", 1, 1)]
    dist, path = dijkstra(nodes, edges, "A", "C")
    assert dist is None
    assert path == []


def test_dijkstra_respects_direction():
    nodes = ["A", "B"]
    edges = [E("B", "A", 1, 1)]
    dist, path = dijkstra(nodes, edges, "A", "B")
    assert dist is None


def test_dijkstra_sample_network():
    dist, path = dijkstra(SAMPLE_NODES, SAMPLE_EDGES, "Laptop", "DB")
    assert dist == 7
    assert path[0] == "Laptop" and path[-1] == "DB"


# ---------- Edmonds-Karp ----------

def test_maxflow_classic_graph():
    nodes = ["S", "A", "B", "T"]
    edges = [
        E("S", "A", 1, 3), E("S", "B", 1, 2), E("A", "B", 1, 1),
        E("A", "T", 1, 2), E("B", "T", 1, 3),
    ]
    flow, cut = edmonds_karp(nodes, edges, "S", "T")
    assert flow == 5


def test_maxflow_sample_network():
    flow, cut = edmonds_karp(SAMPLE_NODES, SAMPLE_EDGES, "Laptop", "DB")
    assert flow == 7
    cut_pairs = {(e["src"], e["dst"]) for e in cut}
    assert cut_pairs == {("Laptop", "Workstation"), ("Laptop", "Mail")}


def test_maxflow_no_path():
    nodes = ["A", "B", "C"]
    edges = [E("A", "B", 1, 5)]
    flow, cut = edmonds_karp(nodes, edges, "A", "C")
    assert flow == 0
    assert cut == []


# ---------- Chain: cut must block every path ----------

def test_removing_cut_blocks_all_paths():
    flow, cut = edmonds_karp(SAMPLE_NODES, SAMPLE_EDGES, "Laptop", "DB")
    assert sum(e["cost"] for e in cut) == flow       # min-cut value == max-flow value

    cut_pairs = {(e["src"], e["dst"]) for e in cut}
    remaining = [e for e in SAMPLE_EDGES if (e["src"], e["dst"]) not in cut_pairs]
    dist, path = dijkstra(SAMPLE_NODES, remaining, "Laptop", "DB")
    assert path == []