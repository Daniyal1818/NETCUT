from collections import deque

def edmonds_karp(nodes, edges, source, sink):
    res = {n: {} for n in nodes}
    for e in edges:
        u, v, c = e["src"], e["dst"], e["cost"]
        res[u][v] = res[u].get(v, 0) + c
        res[v].setdefault(u, 0)

    max_flow = 0
    while True:
        parent = {source: None}
        q = deque([source])
        while q and sink not in parent:
            u = q.popleft()
            for v, c in res[u].items():
                if c > 0 and v not in parent:
                    parent[v] = u
                    q.append(v)
        if sink not in parent:
            break

        bottleneck, v = float("inf"), sink
        while parent[v] is not None:
            bottleneck = min(bottleneck, res[parent[v]][v])
            v = parent[v]
        v = sink
        while parent[v] is not None:
            u = parent[v]
            res[u][v] -= bottleneck
            res[v][u] += bottleneck
            v = u
        max_flow += bottleneck

    reachable = set(parent)
    cut = [e for e in edges if e["src"] in reachable and e["dst"] not in reachable]
    return max_flow, cut