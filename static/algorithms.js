/**
 * NetCut - Standalone Client-Side DAA Algorithm Engine
 * Dual-Engine Support: Allows the frontend to run fully offline or with zero server setup.
 *
 * Implements:
 * 1. Dijkstra's Algorithm for Shortest Path (Attack-Path of least resistance) - O((V + E) log V)
 * 2. Edmonds-Karp Algorithm for Max-Flow / Min-Cut (Defensive Isolation) - O(V * E^2)
 * 3. Chained Verification Pipeline
 */

class MinPriorityQueue {
  constructor() {
    this.heap = [];
  }

  push(item, priority) {
    this.heap.push({ item, priority });
    this._bubbleUp(this.heap.length - 1);
  }

  pop() {
    if (this.isEmpty()) return null;
    const top = this.heap[0];
    const bottom = this.heap.pop();
    if (this.heap.length > 0) {
      this.heap[0] = bottom;
      this._bubbleDown(0);
    }
    return top;
  }

  isEmpty() {
    return this.heap.length === 0;
  }

  _bubbleUp(idx) {
    while (idx > 0) {
      const parentIdx = Math.floor((idx - 1) / 2);
      if (this.heap[idx].priority < this.heap[parentIdx].priority) {
        [this.heap[idx], this.heap[parentIdx]] = [this.heap[parentIdx], this.heap[idx]];
        idx = parentIdx;
      } else {
        break;
      }
    }
  }

  _bubbleDown(idx) {
    const length = this.heap.length;
    while (true) {
      let smallest = idx;
      const left = 2 * idx + 1;
      const right = 2 * idx + 2;

      if (left < length && this.heap[left].priority < this.heap[smallest].priority) {
        smallest = left;
      }
      if (right < length && this.heap[right].priority < this.heap[smallest].priority) {
        smallest = right;
      }
      if (smallest !== idx) {
        [this.heap[idx], this.heap[smallest]] = [this.heap[smallest], this.heap[idx]];
        idx = smallest;
      } else {
        break;
      }
    }
  }
}

/**
 * Dijkstra's Shortest Path Algorithm
 */
function dijkstraJS(nodes, edges, source, target) {
  const t0 = performance.now();
  const adj = {};
  for (const n of nodes) adj[n] = [];
  for (const e of edges) {
    if (adj[e.src]) {
      adj[e.src].push({ dst: e.dst, difficulty: Number(e.difficulty) || 1.0, edge: e });
    }
  }

  const dist = {};
  const prevNode = {};
  const prevEdge = {};
  for (const n of nodes) dist[n] = Infinity;

  if (!(source in dist)) {
    return {
      distance: null,
      path: [],
      edgeSteps: [],
      runtimeMs: Number((performance.now() - t0).toFixed(4)),
    };
  }

  dist[source] = 0;
  const pq = new MinPriorityQueue();
  pq.push(source, 0);

  const settled = [];

  while (!pq.isEmpty()) {
    const { item: u, priority: d } = pq.pop();
    if (d > dist[u]) continue;

    settled.push(u);
    if (u === target) break;

    for (const { dst: v, difficulty: w, edge } of (adj[u] || [])) {
      if (!(v in dist)) continue;
      const newDist = d + w;
      if (newDist < dist[v]) {
        dist[v] = newDist;
        prevNode[v] = u;
        prevEdge[v] = edge;
        pq.push(v, newDist);
      }
    }
  }

  const t1 = performance.now();
  const runtimeMs = Number((t1 - t0).toFixed(4));

  if (dist[target] === Infinity) {
    return { distance: null, path: [], edgeSteps: [], runtimeMs };
  }

  const path = [target];
  const edgeSteps = [];
  let curr = target;
  while (curr !== source && prevNode[curr]) {
    edgeSteps.push(prevEdge[curr]);
    curr = prevNode[curr];
    path.push(curr);
  }

  path.reverse();
  edgeSteps.reverse();

  return {
    distance: dist[target],
    path,
    edgeSteps,
    runtimeMs,
  };
}

/**
 * Edmonds-Karp Max-Flow / Min-Cut Algorithm
 */
function edmondsKarpJS(nodes, edges, source, sink) {
  const t0 = performance.now();

  const res = {};
  for (const n of nodes) res[n] = {};
  for (const e of edges) {
    const u = e.src;
    const v = e.dst;
    const c = Number(e.cost) || 1.0;
    if (res[u] && res[v]) {
      res[u][v] = (res[u][v] || 0) + c;
      if (res[v][u] === undefined) res[v][u] = 0;
    }
  }

  let maxFlow = 0;
  const augmentingPaths = [];
  let iteration = 0;

  if (source in res && sink in res && source !== sink) {
    while (true) {
      iteration++;
      const parent = { [source]: null };
      const queue = [source];

      while (queue.length > 0 && !(sink in parent)) {
        const u = queue.shift();
        for (const [v, cap] of Object.entries(res[u])) {
          if (cap > 1e-9 && !(v in parent)) {
            parent[v] = u;
            queue.push(v);
          }
        }
      }

      if (!(sink in parent)) break;

      let bottleneck = Infinity;
      let curr = sink;
      const pathNodes = [];
      while (parent[curr] !== null) {
        const p = parent[curr];
        bottleneck = Math.min(bottleneck, res[p][curr]);
        pathNodes.push(curr);
        curr = p;
      }
      pathNodes.push(source);
      pathNodes.reverse();

      curr = sink;
      while (parent[curr] !== null) {
        const p = parent[curr];
        res[p][curr] -= bottleneck;
        res[curr][p] += bottleneck;
        curr = p;
      }

      maxFlow += bottleneck;
      augmentingPaths.push({
        iteration,
        path: pathNodes,
        bottleneck: Number(bottleneck.toFixed(4)),
        cumulativeFlow: Number(maxFlow.toFixed(4)),
      });
    }
  }

  // Reachable component S in residual graph
  const reachable = new Set();
  if (source in res) {
    const qReach = [source];
    reachable.add(source);
    while (qReach.length > 0) {
      const u = qReach.shift();
      for (const [v, cap] of Object.entries(res[u])) {
        if (cap > 1e-9 && !reachable.has(v)) {
          reachable.add(v);
          qReach.push(v);
        }
      }
    }
  }

  const cut = [];
  if (source !== sink && maxFlow > 0) {
    for (const e of edges) {
      if (reachable.has(e.src) && !reachable.has(e.dst)) {
        cut.push(e);
      }
    }
  }

  const targetPartition = nodes.filter((n) => !reachable.has(n));
  const t1 = performance.now();

  return {
    maxFlow: Number(maxFlow.toFixed(4)),
    cutEdges: cut,
    cutCost: Number(cut.reduce((s, e) => s + (Number(e.cost) || 1.0), 0).toFixed(4)),
    sourcePartition: Array.from(reachable).sort(),
    targetPartition: targetPartition.sort(),
    augmentingPaths,
    runtimeMs: Number((t1 - t0).toFixed(4)),
  };
}

/**
 * Chained DAA Execution Pipeline
 */
function chainedPipelineJS(network) {
  const nodes = network.nodes;
  const edges = network.edges;
  const entry = network.entry;
  const target = network.target;
  const budget = network.budget;

  // Step 1: Pre-defense Dijkstra
  const pre = dijkstraJS(nodes, edges, entry, target);

  // Step 2: Edmonds-Karp Min-Cut
  const ek = edmondsKarpJS(nodes, edges, entry, target);

  // Step 3: Sever cut edges
  const cutKeys = new Set(ek.cutEdges.map((e) => `${e.src}->${e.dst}`));
  const remaining = edges.filter((e) => !cutKeys.has(`${e.src}->${e.dst}`));

  // Step 4: Post-defense Dijkstra verification
  const post = dijkstraJS(nodes, remaining, entry, target);
  const isVerified = post.path.length === 0;

  // Budget status
  let budgetStatus = null;
  if (budget !== null && budget !== undefined && !isNaN(Number(budget))) {
    const allocated = Number(budget);
    const required = ek.maxFlow;
    const isFeasible = required <= allocated;
    const surplus = allocated - required;
    const utilization = allocated > 0 ? (required / allocated) * 100 : 0;
    budgetStatus = {
      allocated: Number(allocated.toFixed(2)),
      required: Number(required.toFixed(2)),
      feasible: isFeasible,
      surplus: Number(surplus.toFixed(2)),
      utilization_pct: Number(utilization.toFixed(1)),
    };
  }

  return {
    attack_path: pre.path,
    attack_difficulty: pre.distance,
    cut_edges: ek.cutEdges,
    cut_cost: ek.maxFlow,
    verified: isVerified,
    path_after_fix: post.path,
    edge_steps: pre.edgeSteps,
    source_partition: ek.sourcePartition,
    target_partition: ek.targetPartition,
    augmenting_paths: ek.augmentingPaths,
    augmenting_path_count: ek.augmentingPaths.length,
    budget_status: budgetStatus,
    metrics: {
      dijkstra_runtime_ms: pre.runtimeMs,
      edmonds_karp_runtime_ms: ek.runtimeMs,
      verification_runtime_ms: post.runtimeMs,
      total_nodes: nodes.length,
      total_edges: edges.length,
      cut_edge_count: ek.cutEdges.length,
      remaining_edges: remaining.length,
    },
  };
}

window.NetCutAlgorithms = {
  dijkstra: dijkstraJS,
  edmondsKarp: edmondsKarpJS,
  runChainedPipeline: chainedPipelineJS,
};
