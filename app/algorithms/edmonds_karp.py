"""
NetCut - Minimum-Cut Defense Planner Engine
Algorithm: Edmonds-Karp Maximum Flow / Minimum Cut Algorithm
Course: Design and Analysis of Algorithms (DAA)

Computes the minimum-cost set of defensive interventions (firewalls, link severances,
access control enforcements) to completely isolate a target asset from a threat entry point.
Based on the Max-Flow Min-Cut Theorem:
The maximum value of an s-t flow equals the minimum capacity of an s-t cut.

Time Complexity: O(V * E^2) using Breadth-First Search (BFS) for shortest augmenting paths.
Space Complexity: O(V + E) for residual capacity representation.
"""

from collections import deque
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

BIG = 1e12  # Locked (non-blockable) link capacity threshold


def edmonds_karp(
    nodes: List[str],
    edges: List[Dict[str, Any]],
    source: str,
    sink: str,
    return_details: bool = False,
) -> Union[Tuple[float, List[Dict[str, Any]]], Tuple[float, List[Dict[str, Any]], Dict[str, Any]]]:
    """
    Computes the maximum flow and the corresponding minimum s-t cut.

    Args:
        nodes: List of all node identifiers.
        edges: List of edge dictionaries with keys 'src', 'dst', 'difficulty', 'cost', and optional 'blockable'.
        source: Threat entry node (source s).
        sink: Critical target asset (sink t).
        return_details: If True, returns augmenting path history and partition details.

    Returns:
        If return_details is False:
            (max_flow_value, list_of_cut_edge_dicts)
        If return_details is True:
            (max_flow_value, list_of_cut_edge_dicts, details_dictionary)
    """
    start_time = time.perf_counter()

    # Residual capacity adjacency mapping: res[u][v] = residual capacity from u to v
    res: Dict[str, Dict[str, float]] = {n: {} for n in nodes}
    for e in edges:
        u, v = e["src"], e["dst"]
        is_blockable = e.get("blockable", True)
        c = float(e.get("cost", 1.0)) if is_blockable else BIG
        if u in res and v in res:
            res[u][v] = res[u].get(v, 0.0) + c
            res[v].setdefault(u, 0.0)

    max_flow = 0.0
    augmenting_paths_trace: List[Dict[str, Any]] = []
    iteration_count = 0

    if source in res and sink in res and source != sink:
        while True:
            iteration_count += 1
            # BFS to find the shortest augmenting path in terms of edge count
            parent: Dict[str, Optional[str]] = {source: None}
            queue = deque([source])

            while queue and sink not in parent:
                u = queue.popleft()
                for v, cap in res[u].items():
                    # Follow edges with remaining positive residual capacity
                    if cap > 1e-9 and v not in parent:
                        parent[v] = u
                        queue.append(v)

            # If sink was not reached, no more augmenting paths exist
            if sink not in parent:
                break

            # Reconstruct path and determine bottleneck residual capacity
            bottleneck = float("inf")
            curr = sink
            path_nodes = []
            while parent[curr] is not None:
                p = parent[curr]
                bottleneck = min(bottleneck, res[p][curr])
                path_nodes.append(curr)
                curr = p
            path_nodes.append(source)
            path_nodes.reverse()

            # Augment flow along the path and adjust residual network
            curr = sink
            while parent[curr] is not None:
                p = parent[curr]
                res[p][curr] -= bottleneck
                res[curr][p] += bottleneck
                curr = p

            max_flow += bottleneck
            augmenting_paths_trace.append({
                "iteration": iteration_count,
                "path": path_nodes,
                "bottleneck": round(bottleneck, 4),
                "cumulative_flow": round(max_flow, 4),
            })

    # Find the reachable component S from source in the residual graph
    reachable: Set[str] = set()
    if source in res:
        q_reach = deque([source])
        reachable.add(source)
        while q_reach:
            u = q_reach.popleft()
            for v, cap in res[u].items():
                if cap > 1e-9 and v not in reachable:
                    reachable.add(v)
                    q_reach.append(v)

    # In the Max-Flow Min-Cut Theorem:
    # Cut edges are original edges going from the reachable set S to unreachable set T
    cut: List[Dict[str, Any]] = []
    if source != sink and max_flow > 0:
        for e in edges:
            if e["src"] in reachable and e["dst"] not in reachable:
                cut.append(e)

    total_cut_capacity = sum(float(e.get("cost", 1.0)) for e in cut)
    elapsed = (time.perf_counter() - start_time) * 1000.0

    target_partition = [n for n in nodes if n not in reachable]

    if return_details:
        details = {
            "execution_time_ms": round(elapsed, 4),
            "iterations": len(augmenting_paths_trace),
            "augmenting_paths": augmenting_paths_trace,
            "source_partition": sorted(list(reachable)),
            "target_partition": sorted(target_partition),
            "cut_edge_count": len(cut),
            "total_cut_capacity": round(total_cut_capacity, 4),
            "max_flow_value": round(max_flow, 4),
            "complexity": "O(V * E^2)",
        }
        return max_flow, cut, details

    return max_flow, cut
