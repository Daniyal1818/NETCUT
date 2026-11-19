"""
NetCut - Attack-Path Analysis Engine
Algorithm: Dijkstra's Shortest Path Algorithm
Course: Design and Analysis of Algorithms (DAA)

Computes the path of least resistance (minimum cumulative exploit difficulty)
from an attacker entry point to a critical crown jewel asset.

Time Complexity: O((V + E) log V) using a min-priority queue (heapq).
Space Complexity: O(V + E) for adjacency list and distance mappings.
"""

import heapq
import time
from typing import Any, Dict, List, Optional, Tuple, Union


def dijkstra(
    nodes: List[str],
    edges: List[Dict[str, Any]],
    source: str,
    target: str,
    return_details: bool = False,
) -> Union[Tuple[Optional[float], List[str]], Tuple[Optional[float], List[str], Dict[str, Any]]]:
    """
    Finds the shortest attack path minimizing exploit difficulty.

    Args:
        nodes: List of all node identifiers.
        edges: List of edge dictionaries with keys 'src', 'dst', 'difficulty', 'cost'.
        source: Threat actor entry node identifier.
        target: Crown jewel target node identifier.
        return_details: If True, returns detailed metrics and edge step sequence.

    Returns:
        If return_details is False:
            (total_difficulty, path_of_node_ids)
            or (None, []) if target is unreachable.
        If return_details is True:
            (total_difficulty, path_of_node_ids, details_dictionary)
    """
    start_time = time.perf_counter()

    # Build directed adjacency list
    adj: Dict[str, List[Tuple[str, float, Dict[str, Any]]]] = {n: [] for n in nodes}
    for e in edges:
        src = e["src"]
        dst = e["dst"]
        difficulty = float(e.get("difficulty", 1.0))
        if src in adj:
            adj[src].append((dst, difficulty, e))

    dist: Dict[str, float] = {n: float("inf") for n in nodes}
    prev_node: Dict[str, str] = {}
    prev_edge: Dict[str, Dict[str, Any]] = {}
    settled_order: List[str] = []

    if source not in dist:
        elapsed = (time.perf_counter() - start_time) * 1000.0
        details = {
            "execution_time_ms": round(elapsed, 4),
            "visited_count": 0,
            "settled_order": [],
            "edge_steps": [],
            "reachable_nodes_count": 0,
            "complexity": "O((V + E) log V)",
        }
        return (None, [], details) if return_details else (None, [])

    dist[source] = 0.0
    pq: List[Tuple[float, str]] = [(0.0, source)]

    while pq:
        d, u = heapq.heappop(pq)
        if d > dist[u]:
            continue

        settled_order.append(u)
        if u == target:
            break

        for v, weight, edge_obj in adj.get(u, []):
            if v not in dist:
                continue
            new_dist = d + weight
            if new_dist < dist[v]:
                dist[v] = new_dist
                prev_node[v] = u
                prev_edge[v] = edge_obj
                heapq.heappush(pq, (new_dist, v))

    elapsed = (time.perf_counter() - start_time) * 1000.0

    if target not in dist or dist[target] == float("inf"):
        details = {
            "execution_time_ms": round(elapsed, 4),
            "visited_count": len(settled_order),
            "settled_order": settled_order,
            "edge_steps": [],
            "reachable_nodes_count": sum(1 for d in dist.values() if d < float("inf")),
            "complexity": "O((V + E) log V)",
        }
        return (None, [], details) if return_details else (None, [])

    # Reconstruct optimal attack path
    path = [target]
    edge_steps = []
    curr = target
    while curr != source and curr in prev_node:
        edge_steps.append(prev_edge[curr])
        curr = prev_node[curr]
        path.append(curr)

    path.reverse()
    edge_steps.reverse()
    total_dist = dist[target]

    if return_details:
        details = {
            "execution_time_ms": round(elapsed, 4),
            "visited_count": len(settled_order),
            "settled_order": settled_order,
            "edge_steps": edge_steps,
            "reachable_nodes_count": sum(1 for d in dist.values() if d < float("inf")),
            "hop_count": len(edge_steps),
            "complexity": "O((V + E) log V)",
        }
        return total_dist, path, details

    return total_dist, path
