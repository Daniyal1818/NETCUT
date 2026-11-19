/**
 * NetCut - Application Controller
 * Authors: Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)
 * Course: Design and Analysis of Algorithms (DAA)
 * Instructor: Ms. Tooba Sheikh
 */

(function () {
  'use strict';

  // --- Curated Preset Topologies ---
  const PRESETS = {
    benchmark: {
      name: "Academic Benchmark",
      nodes: ["Laptop", "Workstation", "Mail", "FileServer", "AppServer", "DB"],
      edges: [
        { src: "Laptop", dst: "Workstation", difficulty: 2, cost: 4, label: "SMB (Port 445)" },
        { src: "Laptop", dst: "Mail", difficulty: 1, cost: 3, label: "Phish / SMTP" },
        { src: "Workstation", dst: "FileServer", difficulty: 3, cost: 5, label: "NFS / RPC" },
        { src: "Mail", dst: "FileServer", difficulty: 4, cost: 2, label: "Internal Relay" },
        { src: "Mail", dst: "AppServer", difficulty: 5, cost: 3, label: "API Access" },
        { src: "FileServer", dst: "DB", difficulty: 2, cost: 6, label: "SQL Connect" },
        { src: "AppServer", dst: "DB", difficulty: 1, cost: 2, label: "Direct SQL Pool" }
      ],
      entry: "Laptop",
      target: "DB",
      budget: 10
    },
    enterprise: {
      name: "Enterprise Corporate DMZ",
      nodes: ["RemoteLaptop", "VPN_Gateway", "DMZ_Proxy", "ActiveDirectory", "InternalSwitch", "HR_Portal", "FinanceVault"],
      edges: [
        { src: "RemoteLaptop", dst: "VPN_Gateway", difficulty: 2, cost: 8, label: "Cred Stuffing" },
        { src: "RemoteLaptop", dst: "DMZ_Proxy", difficulty: 3, cost: 4, label: "Web Exploit" },
        { src: "VPN_Gateway", dst: "ActiveDirectory", difficulty: 4, cost: 7, label: "Kerberoast" },
        { src: "VPN_Gateway", dst: "InternalSwitch", difficulty: 2, cost: 5, label: "VLAN Hop" },
        { src: "DMZ_Proxy", dst: "HR_Portal", difficulty: 2, cost: 3, label: "SSRF" },
        { src: "InternalSwitch", dst: "ActiveDirectory", difficulty: 3, cost: 6, label: "LDAP Exploit" },
        { src: "InternalSwitch", dst: "HR_Portal", difficulty: 2, cost: 3, label: "Lateral SMB" },
        { src: "ActiveDirectory", dst: "FinanceVault", difficulty: 2, cost: 12, label: "Domain Admin" },
        { src: "HR_Portal", dst: "FinanceVault", difficulty: 6, cost: 4, label: "SQL Pivot" }
      ],
      entry: "RemoteLaptop",
      target: "FinanceVault",
      budget: 15
    },
    cloud: {
      name: "Cloud VPC & Kubernetes",
      nodes: ["InternetAttacker", "IngressController", "AuthService", "PaymentGateway", "RedisCache", "PII_Database"],
      edges: [
        { src: "InternetAttacker", dst: "IngressController", difficulty: 1, cost: 10, label: "HTTP RCE" },
        { src: "IngressController", dst: "AuthService", difficulty: 3, cost: 6, label: "JWT Bypass" },
        { src: "IngressController", dst: "PaymentGateway", difficulty: 5, cost: 8, label: "mTLS Tunnel" },
        { src: "AuthService", dst: "RedisCache", difficulty: 2, cost: 3, label: "Unauth Redis" },
        { src: "RedisCache", dst: "PaymentGateway", difficulty: 2, cost: 4, label: "Token Exfil" },
        { src: "AuthService", dst: "PII_Database", difficulty: 6, cost: 9, label: "Priv Escalation" },
        { src: "PaymentGateway", dst: "PII_Database", difficulty: 2, cost: 5, label: "JDBC" }
      ],
      entry: "InternetAttacker",
      target: "PII_Database",
      budget: 12
    },
    scada: {
      name: "Critical SCADA / ICS",
      nodes: ["ContractorUSB", "EngineeringWorkstation", "HistorianServer", "PLC_Gateway", "SafetySystem"],
      edges: [
        { src: "ContractorUSB", dst: "EngineeringWorkstation", difficulty: 1, cost: 6, label: "Airgap Jump" },
        { src: "ContractorUSB", dst: "HistorianServer", difficulty: 4, cost: 4, label: "Modbus Sniff" },
        { src: "EngineeringWorkstation", dst: "PLC_Gateway", difficulty: 2, cost: 5, label: "Firmware Flash" },
        { src: "HistorianServer", dst: "PLC_Gateway", difficulty: 3, cost: 3, label: "OPC-UA Pivot" },
        { src: "PLC_Gateway", dst: "SafetySystem", difficulty: 2, cost: 8, label: "Logic Override" }
      ],
      entry: "ContractorUSB",
      target: "SafetySystem",
      budget: 11
    }
  };

  // DOM Elements
  const $ = (id) => document.getElementById(id);
  const elements = {
    nodeName: $("nodeName"),
    nodeRole: $("nodeRole"),
    btnAddNode: $("btnAddNode"),
    edgeFrom: $("edgeFrom"),
    edgeTo: $("edgeTo"),
    diff: $("diff"),
    cost: $("cost"),
    edgeLabel: $("edgeLabel"),
    btnSaveEdge: $("btnSaveEdge"),
    btnDelete: $("btnDelete"),
    entry: $("entry"),
    target: $("target"),
    budget: $("budget"),
    presetSelect: $("presetSelect"),
    btnClear: $("btnClear"),
    btnRunAll: $("btnRunAll"),
    btnExportReport: $("btnExportReport"),
    btnExportPng: $("btnExportPng"),
    btnExportJson: $("btnExportJson"),
    statNodes: $("statNodes"),
    statEdges: $("statEdges"),
    statEngine: $("statEngine"),
    msgAlert: $("msgAlert"),
    layoutSelect: $("layoutSelect"),
    btnZoomIn: $("btnZoomIn"),
    btnZoomOut: $("btnZoomOut"),
    btnFit: $("btnFit"),
    btnCenter: $("btnCenter"),
    // Modals
    reportModal: $("reportModal"),
    reportContent: $("reportContent"),
    btnCloseReport: $("btnCloseReport"),
    btnCopyReport: $("btnCopyReport"),
    btnDownloadReport: $("btnDownloadReport"),
  };

  let analysisResult = null;
  let activeEngineMode = "Auto (Backend preferred)";

  // Cytoscape Instance
  const cy = cytoscape({
    container: $("cy"),
    elements: [],
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "background-color": "#1e293b",
          "border-color": "#38bdf8",
          "border-width": 2,
          color: "#f8fafc",
          "text-valign": "bottom",
          "text-margin-y": 8,
          "font-size": 11,
          "font-weight": 600,
          "font-family": "Inter, sans-serif",
          width: 38,
          height: 38,
          "overlay-opacity": 0,
          "transition-property": "background-color, border-color, border-width, width, height",
          "transition-duration": "0.25s"
        }
      },
      {
        selector: "node.entry",
        style: {
          "background-color": "rgba(244, 63, 94, 0.25)",
          "border-color": "#f43f5e",
          "border-width": 3,
          label: "data(displayLabel)",
          color: "#fca5a5",
          width: 44,
          height: 44
        }
      },
      {
        selector: "node.target",
        style: {
          "background-color": "rgba(245, 158, 11, 0.25)",
          "border-color": "#f59e0b",
          "border-width": 3,
          label: "data(displayLabel)",
          color: "#fde68a",
          width: 44,
          height: 44
        }
      },
      {
        selector: "node.partition-s",
        style: {
          "border-color": "#f43f5e",
          "border-style": "dashed"
        }
      },
      {
        selector: "node.partition-t",
        style: {
          "border-color": "#10b981",
          "border-style": "solid"
        }
      },
      {
        selector: "edge",
        style: {
          label: "data(labelText)",
          "font-size": 10,
          "font-family": "JetBrains Mono, monospace",
          width: 2,
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "line-color": "#475569",
          "target-arrow-color": "#475569",
          "text-background-color": "#0b1120",
          "text-background-opacity": 0.85,
          "text-background-padding": 3,
          "text-background-shape": "roundrectangle",
          color: "#94a3b8",
          "arrow-scale": 1.2
        }
      },
      {
        selector: ":selected",
        style: {
          "overlay-color": "#00f2fe",
          "overlay-opacity": 0.2,
          "overlay-padding": 5
        }
      },
      {
        selector: "edge.path",
        style: {
          "line-color": "#f43f5e",
          "target-arrow-color": "#f43f5e",
          width: 4.5,
          color: "#fda4af",
          "z-index": 10
        }
      },
      {
        selector: "edge.cut",
        style: {
          "line-color": "#f97316",
          "target-arrow-color": "#f97316",
          "line-style": "dashed",
          "line-dash-pattern": [6, 4],
          width: 4.5,
          color: "#fdba74",
          "z-index": 12
        }
      },
      {
        selector: "edge.removed",
        style: {
          opacity: 0.15,
          "line-style": "dotted",
          width: 1.5
        }
      }
    ]
  });

  // --- Alert Messenger ---
  function showAlert(text, type = "error") {
    if (!text) {
      elements.msgAlert.style.display = "none";
      elements.msgAlert.textContent = "";
      return;
    }
    elements.msgAlert.className = `alert alert-${type}`;
    elements.msgAlert.style.display = "flex";
    elements.msgAlert.textContent = text;
  }

  // --- Reset Highlight State ---
  function clearHighlights() {
    cy.elements().removeClass("path cut removed partition-s partition-t");
  }

  // --- Form & Select Management ---
  function fillSelect(sel, items, preferred) {
    const keep = preferred !== undefined ? preferred : sel.value;
    sel.innerHTML = "";
    items.forEach((item) => {
      const opt = document.createElement("option");
      opt.value = opt.textContent = item;
      sel.appendChild(opt);
    });
    if (items.includes(keep)) {
      sel.value = keep;
    }
  }

  function refreshEndpointSelects(entryPref, targetPref) {
    const nodeIds = cy.nodes().map((n) => n.id());
    fillSelect(elements.edgeFrom, nodeIds);
    fillSelect(elements.edgeTo, nodeIds);
    fillSelect(elements.entry, nodeIds, entryPref);
    fillSelect(elements.target, nodeIds, targetPref);

    // If selections are empty, default logically
    if (!elements.entry.value && nodeIds.length > 0) elements.entry.value = nodeIds[0];
    if (!elements.target.value && nodeIds.length > 1) elements.target.value = nodeIds[nodeIds.length - 1];

    updateNodeVisuals();
    updateHeaderStats();
  }

  function updateNodeVisuals() {
    const entryId = elements.entry.value;
    const targetId = elements.target.value;

    cy.nodes().forEach((n) => {
      const id = n.id();
      n.removeClass("entry target");
      if (id === entryId) {
        n.addClass("entry");
        n.data("displayLabel", `⚡ ENTRY: ${id}`);
      } else if (id === targetId) {
        n.addClass("target");
        n.data("displayLabel", `👑 TARGET: ${id}`);
      } else {
        n.data("displayLabel", id);
      }
    });
  }

  function updateHeaderStats() {
    elements.statNodes.textContent = cy.nodes().length;
    elements.statEdges.textContent = cy.edges().length;
  }

  function addOrUpdateEdge(src, dst, diff, cost, label) {
    const id = `${src}->${dst}`;
    const displayLabel = label ? `${label} (D:${diff} C:${cost})` : `D:${diff} | C:${cost}`;
    const ex = cy.getElementById(id);
    if (ex.length) {
      ex.data({
        difficulty: diff,
        cost: cost,
        customLabel: label || "",
        labelText: displayLabel
      });
    } else {
      cy.add({
        group: "edges",
        data: {
          id: id,
          source: src,
          target: dst,
          difficulty: diff,
          cost: cost,
          customLabel: label || "",
          labelText: displayLabel
        }
      });
    }
  }

  // --- Network Topology Importer ---
  function loadNetwork(data) {
    cy.elements().remove();
    analysisResult = null;
    clearHighlights();
    showAlert("");

    data.nodes.forEach((id) => {
      cy.add({
        group: "nodes",
        data: { id: id, label: id, displayLabel: id }
      });
    });

    data.edges.forEach((e) => {
      addOrUpdateEdge(e.src, e.dst, e.difficulty, e.cost, e.label);
    });

    if (data.budget !== undefined) {
      elements.budget.value = data.budget;
    }

    refreshEndpointSelects(data.entry, data.target);
    applyLayout(elements.layoutSelect.value);
  }

  // --- Cytoscape Layout Engine ---
  function applyLayout(layoutName = "breadthfirst") {
    let opts = { name: layoutName, animate: true, animationDuration: 400 };

    if (layoutName === "breadthfirst") {
      const entryNode = cy.getElementById(elements.entry.value);
      opts = {
        name: "breadthfirst",
        directed: true,
        roots: entryNode.length ? entryNode : undefined,
        padding: 40,
        spacingFactor: 1.25,
        animate: true
      };
    } else if (layoutName === "cose") {
      opts = {
        name: "cose",
        idealEdgeLength: 100,
        nodeOverlap: 20,
        refresh: 20,
        fit: true,
        padding: 30,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: 400000,
        edgeElasticity: 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
        animate: true
      };
    } else if (layoutName === "concentric") {
      const entryId = elements.entry.value;
      opts = {
        name: "concentric",
        concentric: (node) => (node.id() === entryId ? 10 : 2),
        levelWidth: () => 2,
        padding: 40,
        animate: true
      };
    } else if (layoutName === "circle") {
      opts = { name: "circle", padding: 40, animate: true };
    } else if (layoutName === "grid") {
      opts = { name: "grid", padding: 40, animate: true };
    }

    cy.layout(opts).run();
  }

  // --- Network State Extractor ---
  function getCurrentNetwork() {
    return {
      nodes: cy.nodes().map((n) => n.id()),
      edges: cy.edges().map((e) => ({
        src: e.data("source"),
        dst: e.data("target"),
        difficulty: Number(e.data("difficulty")) || 1.0,
        cost: Number(e.data("cost")) || 1.0,
        label: e.data("customLabel") || ""
      })),
      entry: elements.entry.value,
      target: elements.target.value,
      budget: elements.budget.value ? parseFloat(elements.budget.value) : null
    };
  }

  // --- Execution Engine (API + Offline Fallback) ---
  async function computeAnalysis() {
    showAlert("");
    const net = getCurrentNetwork();

    if (net.nodes.length < 2) {
      showAlert("Network topology requires at least 2 hosts.", "error");
      return null;
    }
    if (!net.entry || !net.target) {
      showAlert("Please designate both a Threat Entry Point and a Crown Jewel Target.", "error");
      return null;
    }
    if (net.entry === net.target) {
      showAlert("Threat Entry Point and Crown Jewel Target must be distinct nodes.", "error");
      return null;
    }

    // Attempt Backend API first
    try {
      const resp = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(net)
      });

      if (resp.ok) {
        const data = await resp.json();
        analysisResult = data;
        elements.statEngine.textContent = "Python Backend (FastAPI / Server)";
        return data;
      } else {
        const errData = await resp.json();
        throw new Error(errData.detail || "Backend computation error");
      }
    } catch (err) {
      // Fallback to client-side DAA algorithm engine
      console.warn("Backend unavailable or returned error, falling back to client-side engine:", err.message);
      if (window.NetCutAlgorithms) {
        const clientData = window.NetCutAlgorithms.runChainedPipeline(net);
        analysisResult = clientData;
        elements.statEngine.textContent = "Client-Side DAA Engine (Active)";
        return clientData;
      } else {
        showAlert(`Analysis failed: ${err.message}`, "error");
        return null;
      }
    }
  }

  // --- Tab UI Renderers ---
  function renderAttackPathTab(res) {
    const kpiDiff = $("kpiDiff");
    const kpiHops = $("kpiHops");
    const kpiFeasibility = $("kpiFeasibility");
    const attackTimeline = $("attackTimeline");
    const attackDetails = $("attackDetails");

    if (!res || !res.attack_path || res.attack_path.length === 0) {
      kpiDiff.textContent = "∞";
      kpiHops.textContent = "0";
      kpiFeasibility.textContent = "None";
      attackTimeline.innerHTML = `<div class="alert alert-info">No attack path exists from entry point to target asset.</div>`;
      attackDetails.textContent = "The target crown jewel is mathematically unreachable in the current topology.";
      return;
    }

    kpiDiff.textContent = res.attack_difficulty;
    kpiHops.textContent = res.attack_path.length - 1;

    // Qualitative assessment
    if (res.attack_difficulty <= 3) {
      kpiFeasibility.textContent = "Critical Risk";
      kpiFeasibility.className = "metric-value crimson";
    } else if (res.attack_difficulty <= 7) {
      kpiFeasibility.textContent = "High Risk";
      kpiFeasibility.className = "metric-value orange";
    } else {
      kpiFeasibility.textContent = "Moderate Resistance";
      kpiFeasibility.className = "metric-value cyan";
    }

    // Step sequence
    let html = "";
    for (let i = 0; i < res.attack_path.length - 1; i++) {
      const u = res.attack_path[i];
      const v = res.attack_path[i + 1];
      const edge = cy.getElementById(`${u}->${v}`);
      const diff = edge.length ? edge.data("difficulty") : "?";
      const cost = edge.length ? edge.data("cost") : "?";
      const label = edge.length ? edge.data("customLabel") : "";

      html += `
        <div class="timeline-step active-step">
          <div class="step-num">${i + 1}</div>
          <div class="step-info">
            <div class="step-path">${u} &rarr; ${v} ${label ? `<span class="badge badge-cut">${label}</span>` : ""}</div>
            <div class="step-meta">
              <span>Exploit Difficulty: <strong>${diff}</strong></span>
              <span>Remediation Cost: <strong>${cost}</strong></span>
            </div>
          </div>
        </div>
      `;
    }
    attackTimeline.innerHTML = html;

    attackDetails.textContent =
      `Dijkstra's Algorithm identified the easiest route: ${res.attack_path.join(" → ")} ` +
      `with cumulative difficulty ${res.attack_difficulty}. An attacker will prioritize this path over paths with higher resistance.`;
  }

  function renderMinCutTab(res) {
    const kpiCutCost = $("kpiCutCost");
    const kpiCutCount = $("kpiCutCount");
    const kpiBudgetFeasible = $("kpiBudgetFeasible");
    const cutTableBody = $("cutTableBody");
    const partitionS = $("partitionS");
    const partitionT = $("partitionT");
    const augmentingPathsList = $("augmentingPathsList");

    if (!res || !res.cut_edges || res.cut_edges.length === 0) {
      kpiCutCost.textContent = "0";
      kpiCutCount.textContent = "0";
      kpiBudgetFeasible.textContent = "N/A";
      cutTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No active attack vectors require mitigation.</td></tr>`;
      partitionS.textContent = "None";
      partitionT.textContent = "All nodes";
      augmentingPathsList.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">Zero flow saturation required.</div>`;
      return;
    }

    kpiCutCost.textContent = res.cut_cost;
    kpiCutCount.textContent = res.cut_edges.length;

    // Budget Feasibility
    if (res.budget_status) {
      const b = res.budget_status;
      if (b.feasible) {
        kpiBudgetFeasible.textContent = `Within Budget ($${b.allocated})`;
        kpiBudgetFeasible.className = "metric-value emerald";
      } else {
        kpiBudgetFeasible.textContent = `Over Budget ($${b.allocated})`;
        kpiBudgetFeasible.className = "metric-value crimson";
      }
    } else {
      kpiBudgetFeasible.textContent = "No Budget Limit Set";
      kpiBudgetFeasible.className = "metric-value cyan";
    }

    // Cut Edges Table
    let tableHtml = "";
    res.cut_edges.forEach((e, idx) => {
      tableHtml += `
        <tr>
          <td><strong>#${idx + 1}</strong></td>
          <td><span style="color:var(--orange); font-weight:600;">${e.src} &rarr; ${e.dst}</span></td>
          <td><span class="badge badge-cut">${e.cost}</span></td>
          <td style="font-size:11px; color:var(--text-sub);">
            ${e.label ? `${e.label}: Deploy firewall drop rule` : "Sever lateral trust / ACL rule"}
          </td>
        </tr>
      `;
    });
    cutTableBody.innerHTML = tableHtml;

    // Partitions
    partitionS.textContent = res.source_partition ? res.source_partition.join(", ") : "Entry Zone";
    partitionT.textContent = res.target_partition ? res.target_partition.join(", ") : "Target Enclave";

    // Augmenting Paths Breakdown
    if (res.augmenting_paths && res.augmenting_paths.length > 0) {
      let pathsHtml = "";
      res.augmenting_paths.forEach((p) => {
        pathsHtml += `
          <div style="padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-family:var(--font-mono); font-size:11px;">
            <span style="color:var(--cyan);">Path #${p.iteration}:</span> ${p.path.join(" → ")}
            <span style="float:right; color:var(--amber);">Bottleneck: ${p.bottleneck}</span>
          </div>
        `;
      });
      augmentingPathsList.innerHTML = pathsHtml;
    } else {
      augmentingPathsList.innerHTML = `<div style="color:var(--text-muted); font-size:11px;">Single-pass cut computation.</div>`;
    }
  }

  function renderVerificationTab(res) {
    const verifyBanner = $("verifyBanner");
    const preDiff = $("preDiff");
    const postDiff = $("postDiff");
    const prePathCount = $("prePathCount");
    const postPathCount = $("postPathCount");
    const verifyDetails = $("verifyDetails");

    if (!res) {
      verifyBanner.className = "alert alert-info";
      verifyBanner.innerHTML = "Click <strong>'Run Chained Defense Pipeline'</strong> to execute and verify defense planner.";
      return;
    }

    preDiff.textContent = res.attack_difficulty !== null ? res.attack_difficulty : "∞";
    postDiff.textContent = res.verified ? "∞ (Unreachable)" : (res.path_after_fix.length > 0 ? "Reachable" : "∞");

    prePathCount.textContent = res.attack_path && res.attack_path.length > 0 ? "1 (Active Vector)" : "0";
    postPathCount.textContent = res.verified ? "0 (All Routes Cut)" : "1+ Residual Routes";

    if (res.verified) {
      verifyBanner.className = "alert alert-success";
      verifyBanner.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
          <div>
            <strong>VERIFICATION CONFIRMED: Target 100% Isolated</strong><br>
            <span style="font-size:11px;">Re-running Dijkstra's algorithm on the residual topology confirms no path from entry point to crown jewel asset remains.</span>
          </div>
        </div>
      `;
      verifyDetails.textContent =
        `Theoretical Proof: The Edmonds-Karp min-cut removed all forward edges crossing from reachable set S to unreachable set T. ` +
        `Subsequent Dijkstra shortest-path evaluation yielded dist[target] = ∞.`;
    } else {
      verifyBanner.className = "alert alert-error";
      verifyBanner.innerHTML = `
        <div>
          <strong>WARNING: Target Still Reachable</strong><br>
          <span style="font-size:11px;">Residual path detected: ${res.path_after_fix.join(" → ")}</span>
        </div>
      `;
      verifyDetails.textContent = `A residual route still connects entry to target. Check edge capacities or network budget constraints.`;
    }
  }

  function renderInspectorTab(res) {
    const runtimeDijkstra = $("runtimeDijkstra");
    const runtimeEK = $("runtimeEK");
    const runtimeVerify = $("runtimeVerify");
    const complexityCard = $("complexityCard");

    if (res && res.metrics) {
      runtimeDijkstra.textContent = `${res.metrics.dijkstra_runtime_ms} ms`;
      runtimeEK.textContent = `${res.metrics.edmonds_karp_runtime_ms} ms`;
      runtimeVerify.textContent = `${res.metrics.verification_runtime_ms} ms`;
    }

    complexityCard.innerHTML = `
      <div style="font-family:var(--font-mono); font-size:11px; line-height:1.6; color:#cbd5e1;">
        <div><strong>Dijkstra's Algorithm:</strong> O((|V| + |E|) log |V|)</div>
        <div style="color:var(--text-sub); margin-bottom:8px;">- Uses Min-Heap Priority Queue to greedily expand the frontier of least difficulty.</div>
        <div><strong>Edmonds-Karp Max-Flow / Min-Cut:</strong> O(|V| · |E|²)</div>
        <div style="color:var(--text-sub); margin-bottom:8px;">- Uses BFS to find augmenting paths with the fewest edges; guaranteed O(|V| · |E|) augmentations.</div>
        <div><strong>Max-Flow Min-Cut Theorem:</strong></div>
        <div style="color:var(--text-sub);">- Proves that the maximum network flow equals the capacity of the minimum s-t cut separating threat entry from critical target.</div>
      </div>
    `;
  }

  // --- Canvas Highlighting Actions ---
  function highlightAttackPath(res) {
    clearHighlights();
    if (!res || !res.attack_path || res.attack_path.length === 0) return;

    for (let i = 0; i < res.attack_path.length - 1; i++) {
      const u = res.attack_path[i];
      const v = res.attack_path[i + 1];
      cy.getElementById(`${u}->${v}`).addClass("path");
    }
  }

  function highlightMinCut(res) {
    clearHighlights();
    if (!res || !res.cut_edges || res.cut_edges.length === 0) return;

    res.cut_edges.forEach((e) => {
      cy.getElementById(`${e.src}->${e.dst}`).addClass("cut");
    });

    if (res.source_partition) {
      res.source_partition.forEach((id) => cy.getElementById(id).addClass("partition-s"));
    }
    if (res.target_partition) {
      res.target_partition.forEach((id) => cy.getElementById(id).addClass("partition-t"));
    }
  }

  function highlightVerifiedDefense(res) {
    clearHighlights();
    if (!res || !res.cut_edges) return;

    res.cut_edges.forEach((e) => {
      cy.getElementById(`${e.src}->${e.dst}`).addClass("removed");
    });
  }

  // --- Chained Pipeline Execution ---
  async function runFullPipeline() {
    const res = await computeAnalysis();
    if (!res) return;

    renderAttackPathTab(res);
    renderMinCutTab(res);
    renderVerificationTab(res);
    renderInspectorTab(res);

    // Switch view highlight based on active tab
    const activeTab = document.querySelector(".tab-btn.active")?.getAttribute("data-tab");
    if (activeTab === "path") {
      highlightAttackPath(res);
    } else if (activeTab === "cut") {
      highlightMinCut(res);
    } else if (activeTab === "verify") {
      highlightVerifiedDefense(res);
    }
  }

  // --- Executive Report Generator ---
  function generateExecutiveReport() {
    if (!analysisResult) {
      showAlert("Please execute analysis pipeline before generating a report.", "warning");
      return;
    }

    const r = analysisResult;
    const net = getCurrentNetwork();
    const dateStr = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

    const md = `# NetCut Defense Planner - Executive Security Audit Report
**Project:** Attack-Path Analysis & Minimum-Cut Defense Optimization
**Course:** Design and Analysis of Algorithms (DAA)
**Team Members:** Muhammad Ibrahim (CT-24144), Muhammad Daniyal Akbar (CT-24145)
**Instructor:** Ms. Tooba Sheikh
**Date:** ${dateStr}

---

## 1. Executive Summary
NetCut modeled the enterprise network graph consisting of **${net.nodes.length} hosts** and **${net.edges.length} directed connections**.
- **Threat Actor Entry Point:** \`${net.entry}\`
- **Crown Jewel Asset:** \`${net.target}\`
- **Primary Attack Vector Difficulty:** **${r.attack_difficulty !== null ? r.attack_difficulty : "Unreachable"}**
- **Optimal Defensive Severance Cost:** **${r.cut_cost}**
- **Target Isolation Verification:** **${r.verified ? "VERIFIED (100% Isolated)" : "UNVERIFIED"}**
${r.budget_status ? `- **Budget Compliance:** ${r.budget_status.feasible ? `PASS (Spent $${r.budget_status.required} / Limit $${r.budget_status.allocated})` : `EXCEEDED (Deficit: $${Math.abs(r.budget_status.surplus)})`}` : ""}

---

## 2. Attack Vector Analysis (Dijkstra's Algorithm)
Attackers follow the path of least resistance. Dijkstra's shortest path identified the following exploit sequence:
${r.attack_path && r.attack_path.length > 0 ? r.attack_path.map((n, i) => `${i + 1}. **${n}**`).join("\n") : "*No viable attack route discovered.*"}

- **Total Exploit Resistance:** ${r.attack_difficulty}
- **Exploit Chain Hops:** ${r.attack_path ? r.attack_path.length - 1 : 0}

---

## 3. Minimum-Cut Defensive Remediation (Edmonds-Karp Max-Flow Min-Cut)
Applying the Max-Flow Min-Cut Theorem, NetCut computed the minimal set of links that completely disconnects the entry point from the critical asset at lowest budget cost:

| Step | Connection | Remediation Cost | Action Recommended |
|---|---|---|---|
${r.cut_edges.map((e, idx) => `| #${idx + 1} | \`${e.src} → ${e.dst}\` | ${e.cost} | Enforce strict ACL / Isolate Subnet |`).join("\n")}

**Total Defense Investment Required:** **${r.cut_cost}**

---

## 4. Chained Verification Audit
To ensure zero operational vulnerabilities remain, Dijkstra's algorithm was re-executed on the residual network:
- **Residual Path to Crown Jewel:** ${r.verified ? "NONE (Distance: ∞)" : r.path_after_fix.join(" → ")}
- **Defensive Integrity:** ${r.verified ? "100% Target Protection Guaranteed" : "Residual Vulnerability Detected"}

---
*Report generated automatically by NetCut Decision-Support Engine.*
`;

    elements.reportContent.textContent = md;
    elements.reportModal.classList.add("active");
  }

  // --- Event Bindings ---

  // Tabs Switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      const pane = $(`pane-${tabId}`);
      if (pane) pane.classList.add("active");

      // Visual updates on Cytoscape canvas
      if (analysisResult) {
        if (tabId === "path") highlightAttackPath(analysisResult);
        else if (tabId === "cut") highlightMinCut(analysisResult);
        else if (tabId === "verify") highlightVerifiedDefense(analysisResult);
        else clearHighlights();
      }
    });
  });

  // Editor Actions
  elements.btnAddNode.addEventListener("click", () => {
    const id = elements.nodeName.value.trim();
    if (!id) return showAlert("Please specify a host identifier.", "warning");
    if (cy.getElementById(id).length) return showAlert(`Host '${id}' already exists.`, "warning");

    cy.add({
      group: "nodes",
      data: { id: id, label: id, displayLabel: id },
      position: { x: 100 + Math.random() * 300, y: 80 + Math.random() * 250 }
    });

    elements.nodeName.value = "";
    analysisResult = null;
    clearHighlights();
    refreshEndpointSelects();
    showAlert("");
  });

  elements.btnSaveEdge.addEventListener("click", () => {
    const s = elements.edgeFrom.value;
    const t = elements.edgeTo.value;
    if (!s || !t) return showAlert("Please create at least two hosts before connecting.", "warning");
    if (s === t) return showAlert("Self-loops are not allowed.", "warning");

    const diff = parseFloat(elements.diff.value);
    const cost = parseFloat(elements.cost.value);
    const label = elements.edgeLabel.value.trim();

    if (isNaN(diff) || diff < 0) return showAlert("Difficulty must be a non-negative number.", "warning");
    if (isNaN(cost) || cost < 0) return showAlert("Cost must be a non-negative number.", "warning");

    addOrUpdateEdge(s, t, diff, cost, label);
    analysisResult = null;
    clearHighlights();
    updateHeaderStats();
    showAlert("");
  });

  elements.btnDelete.addEventListener("click", () => {
    const sel = cy.$(":selected");
    if (!sel.length) return showAlert("Select one or more elements to delete.", "info");
    sel.remove();
    analysisResult = null;
    clearHighlights();
    refreshEndpointSelects();
    showAlert("");
  });

  // Canvas Interactions
  cy.on("tap", "edge", (evt) => {
    const e = evt.target;
    elements.edgeFrom.value = e.data("source");
    elements.edgeTo.value = e.data("target");
    elements.diff.value = e.data("difficulty");
    elements.cost.value = e.data("cost");
    elements.edgeLabel.value = e.data("customLabel") || "";

    // Switch to topology tab for easy edit
    document.querySelector('.tab-btn[data-tab="topology"]').click();
  });

  elements.entry.addEventListener("change", () => {
    analysisResult = null;
    clearHighlights();
    updateNodeVisuals();
  });

  elements.target.addEventListener("change", () => {
    analysisResult = null;
    clearHighlights();
    updateNodeVisuals();
  });

  // Action Buttons
  elements.btnRunAll.addEventListener("click", () => runFullPipeline());

  // Individual Tab Trigger Buttons
  $("btnFindPath").addEventListener("click", async () => {
    await runFullPipeline();
    document.querySelector('.tab-btn[data-tab="path"]').click();
  });

  $("btnComputeCut").addEventListener("click", async () => {
    await runFullPipeline();
    document.querySelector('.tab-btn[data-tab="cut"]').click();
  });

  $("btnVerifyDefense").addEventListener("click", async () => {
    await runFullPipeline();
    document.querySelector('.tab-btn[data-tab="verify"]').click();
  });

  elements.btnClear.addEventListener("click", () => {
    cy.elements().remove();
    analysisResult = null;
    clearHighlights();
    refreshEndpointSelects();
    showAlert("");
  });

  elements.presetSelect.addEventListener("change", (e) => {
    const key = e.target.value;
    if (PRESETS[key]) {
      loadNetwork(PRESETS[key]);
      runFullPipeline();
    }
  });

  // Canvas Controls
  elements.layoutSelect.addEventListener("change", (e) => applyLayout(e.target.value));
  elements.btnZoomIn.addEventListener("click", () => cy.zoom(cy.zoom() * 1.25));
  elements.btnZoomOut.addEventListener("click", () => cy.zoom(cy.zoom() * 0.8));
  elements.btnFit.addEventListener("click", () => cy.fit(undefined, 35));
  elements.btnCenter.addEventListener("click", () => cy.center());

  // Export Buttons
  elements.btnExportReport.addEventListener("click", generateExecutiveReport);
  elements.btnCloseReport.addEventListener("click", () => elements.reportModal.classList.remove("active"));
  elements.btnCopyReport.addEventListener("click", () => {
    navigator.clipboard.writeText(elements.reportContent.textContent);
    alert("Report markdown copied to clipboard!");
  });
  elements.btnDownloadReport.addEventListener("click", () => {
    const blob = new Blob([elements.reportContent.textContent], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `NetCut_Defense_Report_${Date.now()}.md`;
    a.click();
  });

  elements.btnExportPng.addEventListener("click", () => {
    const png64 = cy.png({ full: true, scale: 2, bg: "#0a0e1a" });
    const a = document.createElement("a");
    a.href = png64;
    a.download = `NetCut_Topology_${Date.now()}.png`;
    a.click();
  });

  elements.btnExportJson.addEventListener("click", () => {
    const net = getCurrentNetwork();
    const blob = new Blob([JSON.stringify(net, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `NetCut_Network_${Date.now()}.json`;
    a.click();
  });

  // --- Initial Launch ---
  loadNetwork(PRESETS.benchmark);
  setTimeout(runFullPipeline, 400);

})();
