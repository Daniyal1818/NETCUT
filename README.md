# NetCut: Attack-Path Analysis and Minimum-Cut Defense Planner

**Course:** Design and Analysis of Algorithms (DAA)  
**Team Members:** Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)  
**Instructor:** Ms. Tooba Sheikh  
**Submission Date:** 25 October 2026  

---

## 1. Abstract
**NetCut** is a cyber decision-support tool that models a computer network as a weighted directed graph and answers two fundamental security questions:
1. **What is the easiest route an attacker could take to reach a critical crown jewel asset?**
   - Solved with **Dijkstra's shortest path algorithm** using a min-heap priority queue ($O((V + E) \log V)$).
2. **What is the cheapest set of defensive changes (firewall rules, link severances, network segmentations) that completely blocks every route to that asset?**
   - Solved with the **Edmonds-Karp maximum flow algorithm** and the **Max-Flow Min-Cut Theorem** ($O(V \cdot E^2)$).

The two algorithms are chained in a decision-support pipeline:
$$\text{Dijkstra (Expose Weakness)} \longrightarrow \text{Edmonds-Karp (Compute Optimal Cut)} \longrightarrow \text{Dijkstra (Verify Target Isolation)}$$

Dijkstra exposes the current vulnerability, Edmonds-Karp computes the minimum-cost fix, and Dijkstra is run again on the residual network to mathematically verify that the target is $100\%$ isolated ($d[target] = \infty$).

---

## 2. Problem Statement
Organizations usually understand their network layout, but lack data-driven methods to identify which small set of links, firewall rules, or hosts to harden first. Blocking everything is operationally prohibitive, and blocking links at random leaves hidden attack vectors exposed. Attackers rarely strike the most heavily defended perimeter; they follow the path of least resistance from a compromised entry point toward high-value crown jewel databases and domain controllers.

**NetCut** solves this problem by determining the most likely attack path and computing the minimum-cost cut set that severs all paths from threat entry to crown jewel, while respecting operational defense budgets.

---

## 3. Algorithmic Architecture & Complexity

### A. Attack Vector Discovery: Dijkstra's Algorithm
- **Objective:** Find the directed path minimizing cumulative exploit difficulty $\sum_{(u, v) \in p} \mathcal{D}(u, v)$.
- **Data Structure:** Binary min-heap priority queue (`heapq`).
- **Time Complexity:** $\mathcal{O}((|V| + |E|) \log |V|)$
- **Space Complexity:** $\mathcal{O}(|V| + |E|)$
- **Output:** Path node sequence, cumulative resistance score, and individual step breakdown.

### B. Defense Optimization: Edmonds-Karp Max-Flow / Min-Cut
- **Objective:** Compute the minimum-capacity $s\text{-}t$ cut separating threat entry $s$ from critical asset $t$.
- **Theorem:** By the **Max-Flow Min-Cut Theorem**, the value of the maximum network flow equals the capacity of the minimum $s\text{-}t$ cut:
  $$|f^*| = c(S, T) = \sum_{u \in S, v \in T, (u, v) \in E} c(u, v)$$
- **Method:** Breadth-First Search (BFS) finds augmenting paths with the minimum number of edges in the residual graph $G_f$, guaranteeing at most $\mathcal{O}(|V| \cdot |E|)$ augmentations.
- **Time Complexity:** $\mathcal{O}(|V| \cdot |E|^2)$
- **Space Complexity:** $\mathcal{O}(|V| + |E|)$
- **Output:** Minimum defense cost, specific cut edges, and the $(S, T)$ graph partition ($S = \text{reachable from } s \text{ in } G_f$, $T = V \setminus S$).

### C. Chained Verification & Budget Feasibility
1. Compute pre-defense shortest path $P_{\text{pre}}$ and difficulty $D_{\text{pre}}$.
2. Compute min-cut $C = \{(u, v) \in E \mid u \in S, v \notin S\}$.
3. Form residual defense graph $G' = (V, E \setminus C)$.
4. Run Dijkstra on $G'$ from $s$ to $t$:
   - If path is empty and $d[t] = \infty \implies$ **VERIFIED SAFE**.
   - If path exists $\implies$ **WARNING: RESIDUAL PATH DETECTED**.
5. Compare total cut cost $\sum_{e \in C} c(e)$ against defense budget limit $B$.

---

## 4. Professional Operations Dashboard Features

- **Cyber Dark Theme:** Obsidian palette, glowing cyber cyan, neon crimson threat indicators, laser orange cut styling, and emerald verification badges.
- **No Roman Urdu / Informal Text:** Replaced all prototype strings with clean, industry-standard cybersecurity terminology.
- **Topology Studio:**
  - Dynamic host and connection manager.
  - Interactive edge click-to-edit on the Cytoscape canvas.
  - Threat entry, crown jewel target, and defense budget configuration.
- **Interactive Preset Scenarios:**
  - *Academic Benchmark Network* (DAA CCP 6-node topology)
  - *Corporate Enterprise DMZ* (Perimeter, Active Directory, HR Portal, Finance Vault)
  - *Cloud VPC & Kubernetes* (Ingress, AuthService, Redis Cache, Payment Gateway, PII DB)
  - *Critical Infrastructure SCADA/ICS* (Engineering Workstation, Historian, PLC, Safety System)
- **Cytoscape Visualizer with Multi-Layout Engine:**
  - Hierarchical Directed Tree (Breadthfirst)
  - Force-Directed Physics (CoSE)
  - Concentric Rings & Grid Layouts
  - Canvas Pan, Zoom, Center, and Fit controls
- **Export & Reporting:**
  - Export Topology Snapshot as high-resolution PNG.
  - Export Network Graph as JSON.
  - Generate and copy/download formatted Executive Security Audit Reports (.md).
- **Dual-Engine Architecture:**
  - Primary: Python REST API (`/api/analyze`).
  - Standalone Offline Fallback: Built-in JavaScript implementation of Dijkstra and Edmonds-Karp enables the frontend to run with zero server setup if opened directly in a browser.

---

## 5. Getting Started & Execution

### Option 1: Standalone Zero-Dependency Runner (Recommended)
NetCut includes a standalone server that uses Python's standard library. No `pip install` required:
```bash
python server.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in any modern web browser.

### Option 2: FastAPI & Uvicorn Runner
If you have FastAPI and Uvicorn installed:
```bash
uvicorn app.main:app --reload --port 8000
```

### Option 3: Direct Browser Launch (Offline)
Simply open `static/index.html` directly in Google Chrome, Microsoft Edge, or Firefox. The built-in client-side DAA engine will execute Dijkstra and Edmonds-Karp directly in the browser!

---

## 6. Running Unit Tests

Run the full algorithm test suite directly with Python:
```bash
python -c "import tests.test_algorithms as t; [getattr(t, n)() for n in dir(t) if n.startswith('test_')]; print('All tests passed!')"
```
Or with pytest if installed:
```bash
pytest
```

---

## 7. Project Structure
```
NETCUT/
├── app/
│   ├── algorithms/
│   │   ├── __init__.py
│   │   ├── dijkstra.py          # Min-heap shortest attack path O((V+E) log V)
│   │   └── edmonds_karp.py      # Max-flow min-cut algorithm O(V * E^2)
│   ├── __init__.py
│   └── main.py                  # FastAPI application & API endpoints
├── static/
│   ├── index.html               # Professional cyber operations dashboard
│   ├── style.css                # Obsidian cyber dark design system
│   ├── algorithms.js            # Standalone client-side DAA algorithm engine
│   └── app.js                   # Application controller & Cytoscape engine
├── tests/
│   └── test_algorithms.py       # Unit tests for Dijkstra, Edmonds-Karp & Chaining
├── server.py                    # Zero-dependency local server runner
├── requirements.txt             # Python dependencies (for FastAPI/Uvicorn)
└── README.md                    # DAA Complex Project Documentation
```

---

## 8. Attribution & Academic Information
- **Course:** Design and Analysis of Algorithms (DAA)
- **Institution:** Department of Computer Science & Information Technology
- **Team Lead:** Muhammad Ibrahim (CT-24144)
- **Team Member:** Muhammad Daniyal Akbar (CT-24145)
- **Course Instructor:** Ms. Tooba Sheikh
