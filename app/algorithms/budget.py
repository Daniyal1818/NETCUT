from app.algorithms.dijkstra import dijkstra


def greedy_budget_defense(nodes, edges, source, target, budget):
    """
    Budget ke andar greedy defense.
    Har round: current shortest attack path ka koi ek edge kaato jo
    (attacker ki difficulty ka izafa) / cost sabse zyada ho.
    Locked (blockable=False) edges kabhi nahi kaat-te.
    """
    remaining = list(edges)
    removed = []
    spent = 0.0

    while True:
        dist, path = dijkstra(nodes, remaining, source, target)
        if not path:
            break                                   # poora block ho gaya

        on_path = set(zip(path, path[1:]))
        best, best_score = None, None

        for e in remaining:
            if (e["src"], e["dst"]) not in on_path:
                continue
            if not e.get("blockable", True):
                continue
            if spent + e["cost"] > budget:
                continue

            trial = [x for x in remaining if x is not e]
            new_dist, new_path = dijkstra(nodes, trial, source, target)
            gain = float("inf") if not new_path else new_dist - dist
            c = e["cost"]
            if c == 0:
                ratio = float("inf") if gain > 0 else 0
            else:
                ratio = gain / c
            score = (ratio, -c)                     # barabari par sasta edge
            if best_score is None or score > best_score:
                best, best_score = e, score

        if best is None:
            break                                   # koi edge afford nahi ho sakta

        remaining = [x for x in remaining if x is not best]
        removed.append(best)
        spent += best["cost"]

    return removed, spent