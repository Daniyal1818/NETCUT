"""
NetCut - Greedy Budget Defense Engine
Algorithm: Heuristic Greedy Attack-Path Defense under Budget Limits
Course: Design and Analysis of Algorithms (DAA)

Iteratively selects and removes the edge on the current shortest attack path
that maximizes the defense efficiency ratio:
    Efficiency Score = (Increase in Attacker Difficulty) / (Remediation Cost)
Subject to total spent <= allocated budget.
Locked (blockable=False) connections are strictly preserved.
"""

from typing import Any, Dict, List, Tuple
from app.algorithms.dijkstra import dijkstra


def greedy_budget_defense(
    nodes: List[str],
    edges: List[Dict[str, Any]],
    source: str,
    target: str,
    budget: float,
) -> Tuple[List[Dict[str, Any]], float]:
    """
    Computes a heuristic set of defensive link removals within budget.

    Args:
        nodes: List of all node identifiers.
        edges: List of directed edges.
        source: Threat entry point.
        target: Crown jewel target asset.
        budget: Maximum remediation cost limit.

    Returns:
        (removed_edges, total_cost_spent)
    """
    remaining = list(edges)
    removed: List[Dict[str, Any]] = []
    spent = 0.0

    while True:
        dist, path = dijkstra(nodes, remaining, source, target)
        if not path:
            break  # Attack path completely blocked

        on_path = set(zip(path, path[1:]))
        best_edge = None
        best_score = None

        for e in remaining:
            if (e["src"], e["dst"]) not in on_path:
                continue
            if not e.get("blockable", True):
                continue
            cost = float(e.get("cost", 1.0))
            if spent + cost > budget:
                continue

            # Simulate removal of this candidate edge
            trial = [x for x in remaining if x is not e]
            new_dist, new_path = dijkstra(nodes, trial, source, target)
            gain = float("inf") if not new_path else (new_dist - dist)

            if cost == 0:
                ratio = float("inf") if gain > 0 else 0.0
            else:
                ratio = gain / cost

            # Score prioritizes higher gain-to-cost ratio, tie-breaking on lower cost
            score = (ratio, -cost)
            if best_score is None or score > best_score:
                best_edge = e
                best_score = score

        if best_edge is None:
            break  # No affordable blocking edge on active attack path

        remaining = [x for x in remaining if x is not best_edge]
        removed.append(best_edge)
        spent += float(best_edge.get("cost", 1.0))

    return removed, spent
