import heapq

def dijkstra(nodes, edges, source, target):
    adj = {n: [] for n in nodes}
    for e in edges:
        adj[e["src"]].append((e["dst"], e["difficulty"]))

    dist = {n: float("inf") for n in nodes}
    prev = {}
    dist[source] = 0
    pq = [(0, source)]

    while pq:
        d, u = heapq.heappop(pq)
        if d > dist[u]:
            continue
        if u == target:
            break
        for v, w in adj[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                prev[v] = u
                heapq.heappush(pq, (nd, v))

    if dist[target] == float("inf"):
        return None, []
    path = [target]
    while path[-1] != source:
        path.append(prev[path[-1]])
    return dist[target], path[::-1]