package main

import "net/http"

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CodeSpider — Review Operations Console</title>
<style>
  :root {
    --bg: #0d1117;
    --panel: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #3fb950;
    --warn: #d29922;
    --err: #f85149;
    --info: #58a6ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  :focus-visible { outline: 2px solid var(--info); outline-offset: 2px; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 20px 20px 48px; }
  header {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    gap: 12px; margin-bottom: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--border);
  }
  h1 { margin: 0; font-size: 1.35rem; letter-spacing: -0.01em; }
  .meta { color: var(--muted); font-size: 0.88rem; display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
  .tabs {
    display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px;
  }
  .tab-btn {
    background: var(--panel); color: var(--muted); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 12px; font-size: 0.85rem; cursor: pointer; font-weight: 600;
  }
  .tab-btn[aria-selected="true"] { background: #1f6feb; color: #ffffff; border-color: #388bfd; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px; margin-bottom: 20px;
  }
  .two-col {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
    gap: 16px; margin-bottom: 20px;
  }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .card .label { font-size: 0.76rem; text-transform: uppercase; color: var(--muted); letter-spacing: 0.04em; }
  .card .val { font-size: 1.55rem; font-weight: 600; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
  .panel-head {
    padding: 12px 16px; border-bottom: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;
  }
  .panel-head h2 { margin: 0; font-size: 1rem; }
  .panel-body { padding: 14px 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
  th, td { padding: 9px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 500; font-size: 0.76rem; text-transform: uppercase; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.74rem; font-weight: 600; }
  .badge.success { background: rgba(63,185,80,0.16); color: var(--accent); }
  .badge.failed { background: rgba(248,81,73,0.16); color: var(--err); }
  .badge.canceled { background: rgba(210,153,34,0.16); color: var(--warn); }
  .badge.info { background: rgba(88,166,255,0.16); color: var(--info); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.81rem; }
  .empty { padding: 22px; text-align: center; color: var(--muted); }
  .stream {
    max-height: 260px; overflow-y: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem; display: flex; flex-direction: column; gap: 6px;
  }
  .stream-item { padding: 6px 8px; background: rgba(255,255,255,0.03); border-radius: 4px; border-left: 3px solid var(--info); }
  .stream-item.secret_alert { border-left-color: var(--err); }
  .stream-item.blue_team { border-left-color: var(--accent); }
  form.row, .toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; align-items: center; }
  input, select, button {
    background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 7px 10px; font-size: 0.85rem;
  }
  button.primary { background: #238636; border-color: #2ea043; cursor: pointer; font-weight: 600; color: #fff; }
  button.primary:hover { background: #2ea043; }
  button.secondary { background: var(--panel); cursor: pointer; }
  pre.out {
    margin: 0; padding: 10px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; max-height: 240px; overflow: auto; font-size: 0.8rem; white-space: pre-wrap;
  }
  a { color: var(--info); text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>CodeSpider Operations Console</h1>
      <div class="meta">
        <span>Model: <strong id="meta-model">-</strong></span>
        <span>Workers: <strong id="meta-workers">-</strong></span>
        <span>Uptime: <strong id="meta-uptime">-</strong></span>
      </div>
    </div>
    <div class="meta">
      <label for="admin-token" class="sr-only">Admin token</label>
      <input id="admin-token" type="password" placeholder="Admin token (if enabled)" size="20" aria-label="Admin token" />
      <a href="/status">JSON Status</a>
      <a href="/metrics">Prometheus</a>
      <span id="last-refresh">Initializing...</span>
    </div>
  </header>

  <nav class="tabs" role="tablist" aria-label="Console sections">
    <button class="tab-btn" role="tab" aria-selected="true" data-tab="overview">Overview &amp; Queue</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="reviews">Reviews &amp; Evidence</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="intel">Languages &amp; Org Graph</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="memory">Policy &amp; Memory</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="benchmarks">Benchmarks</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="replay">Shadow Replay</button>
    <button class="tab-btn" role="tab" aria-selected="false" data-tab="audit">Audit Log</button>
  </nav>

  <section id="tab-overview" class="tab-panel active" role="tabpanel">
    <div class="grid">
      <div class="card"><div class="label">Active Jobs</div><div class="val" id="m-active">0</div></div>
      <div class="card"><div class="label">Queue Depth</div><div class="val" id="m-queue">0</div></div>
      <div class="card"><div class="label">Reviewed PRs</div><div class="val" id="m-reviewed">0</div></div>
      <div class="card"><div class="label">Runs (OK / Fail)</div><div class="val" id="m-runs">0 / 0</div></div>
      <div class="card"><div class="label">Inline Comments</div><div class="val" id="m-comments">0</div></div>
      <div class="card"><div class="label">Total Tokens</div><div class="val" id="m-tokens">0</div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Live Agent Activity (SSE)</h2><span class="meta" id="sse-status">Connecting...</span></div>
      <div class="panel-body"><div class="stream" id="event-stream"></div></div>
    </div>
  </section>

  <section id="tab-reviews" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head">
        <h2>Review History &amp; Evidence Explorer</h2>
        <div class="toolbar" style="margin-bottom:0">
          <input id="rev-repo-filter" placeholder="Filter repo (e.g. acme/api)" />
          <select id="rev-status-filter">
            <option value="">All statuses</option>
            <option value="success">success</option>
            <option value="failed">failed</option>
            <option value="canceled">canceled</option>
          </select>
          <button class="secondary" id="rev-refresh">Load</button>
        </div>
      </div>
      <div id="reviews-container"></div>
    </div>
  </section>

  <section id="tab-intel" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head"><h2>Polyglot Language Analyzers &amp; Capabilities</h2><button class="secondary" id="lang-refresh">Refresh</button></div>
      <div id="lang-container"></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Organization Dependency Graph (Verified vs. Inferred)</h2><button class="secondary" id="graph-refresh">Refresh</button></div>
      <div id="graph-container"></div>
    </div>
  </section>

  <section id="tab-memory" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head"><h2>Add Approved Policy Rule</h2><button class="secondary" id="mem-refresh">Refresh Memory</button></div>
      <div class="panel-body">
        <form class="row" id="rule-form">
          <input id="rule-id" placeholder="Rule ID (e.g. org-auth-01)" required />
          <input id="rule-repo" placeholder="Repo (* or owner/repo)" value="*" required />
          <input id="rule-instr" placeholder="Instruction" style="min-width:260px" required />
          <button type="submit" class="primary">Save Rule</button>
        </form>
        <pre class="out" id="mem-output">Click Refresh Memory to inspect stored feedback, rules, and incidents.</pre>
      </div>
    </div>
  </section>

  <section id="tab-benchmarks" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head"><h2>Split Benchmark Suite (95% Wilson CIs)</h2><button class="primary" id="bench-run">Run Offline Splits</button></div>
      <div id="bench-container"><div class="empty">Click "Run Offline Splits" to evaluate dev, validation, and holdout suites.</div></div>
    </div>
  </section>

  <section id="tab-replay" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head"><h2>Shadow Replay &amp; Dry-Run Playground</h2><span class="meta">Zero Gitea mutations</span></div>
      <div class="panel-body">
        <form class="row" id="dry-run-form">
          <input id="dr-repo" placeholder="owner/repo" required />
          <input id="dr-pr" type="number" placeholder="PR #" min="1" style="width:90px" required />
          <input id="dr-skills" placeholder="skills (optional)" />
          <label><input id="dr-offline" type="checkbox" checked /> Offline deterministic only</label>
          <button type="submit" class="primary">Run Shadow Replay</button>
        </form>
        <pre class="out" id="dr-output">Enter a repo and PR number to simulate a review without posting to Gitea.</pre>
      </div>
    </div>
  </section>

  <section id="tab-audit" class="tab-panel" role="tabpanel">
    <div class="panel">
      <div class="panel-head"><h2>Security &amp; Authorization Audit Log</h2><button class="secondary" id="audit-refresh">Refresh</button></div>
      <div id="audit-container"></div>
    </div>
  </section>
</div>

<script>
let csrfToken = "";
const tokenInput = document.getElementById("admin-token");
tokenInput.addEventListener("change", async () => {
  const tok = tokenInput.value.trim();
  if (tok) {
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: tok })
    });
    if (res.ok) {
      const data = await res.json();
      csrfToken = data.csrf_token || "";
    }
  }
  connectSSE();
  refresh();
});

async function ensureSession() {
  try {
    const res = await fetch("/api/session", { cache: "no-store" });
    if (res.ok) {
      const d = await res.json();
      if (d.csrf_token) csrfToken = d.csrf_token;
    }
  } catch (_) {}
}

function writeHeaders() {
  const h = { "Content-Type": "application/json" };
  if (csrfToken) h["X-CSRF-Token"] = csrfToken;
  return h;
}

const tabs = Array.from(document.querySelectorAll(".tab-btn"));
tabs.forEach((btn, idx) => {
  btn.addEventListener("click", () => selectTab(btn.dataset.tab));
  btn.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") { tabs[(idx + 1) % tabs.length].focus(); selectTab(tabs[(idx + 1) % tabs.length].dataset.tab); }
    if (e.key === "ArrowLeft") { tabs[(idx - 1 + tabs.length) % tabs.length].focus(); selectTab(tabs[(idx - 1 + tabs.length) % tabs.length].dataset.tab); }
  });
});

function selectTab(name) {
  tabs.forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "reviews") loadReviews();
  if (name === "intel") { loadLanguages(); loadOrgGraph(); }
  if (name === "audit") loadAudit();
}

function fmtDuration(ms) {
  if (!ms || ms < 0) return "-";
  if (ms < 1000) return ms + "ms";
  return (ms / 1000).toFixed(1) + "s";
}
function fmtUptime(sec) {
  if (sec < 60) return sec + "s";
  const m = Math.floor(sec / 60), h = Math.floor(m / 60);
  return h > 0 ? h + "h " + (m % 60) + "m" : m + "m " + (sec % 60) + "s";
}
function makeCell(text, cls) {
  const td = document.createElement("td");
  if (cls) td.className = cls;
  td.textContent = text;
  return td;
}

let eventSource = null;
function connectSSE() {
  if (eventSource) eventSource.close();
  eventSource = new EventSource("/events");
  const statusEl = document.getElementById("sse-status");
  const streamEl = document.getElementById("event-stream");
  eventSource.onopen = () => { statusEl.textContent = "Live"; };
  eventSource.onerror = () => { statusEl.textContent = "Reconnecting..."; };
  eventSource.onmessage = (e) => {
    try {
      const ev = JSON.parse(e.data);
      const row = document.createElement("div");
      row.className = "stream-item " + (ev.type || "");
      const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "";
      row.textContent = ts + (ev.pr_key ? " " + ev.pr_key : "") + " (" + (ev.type || "event") + ")" + (ev.tool ? " [" + ev.tool + "]" : "") + ": " + (ev.message || "");
      streamEl.prepend(row);
      while (streamEl.children.length > 40) streamEl.removeChild(streamEl.lastChild);
    } catch (_) {}
  };
}

async function refresh() {
  try {
    const res = await fetch("/status", { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    const m = data.metrics || {};
    document.getElementById("meta-model").textContent = data.model || "-";
    document.getElementById("meta-workers").textContent = String(data.workers || 0);
    document.getElementById("meta-uptime").textContent = fmtUptime(m.uptime_seconds || 0);
    document.getElementById("m-active").textContent = String(data.active_jobs || 0);
    document.getElementById("m-queue").textContent = String(data.queue_depth || 0);
    document.getElementById("m-reviewed").textContent = String(data.reviewed_prs || 0);
    document.getElementById("m-runs").textContent = (m.runs_success || 0) + " / " + (m.runs_failed || 0);
    document.getElementById("m-comments").textContent = String(m.total_inline_comments || 0);
    document.getElementById("m-tokens").textContent = String(m.total_tokens || 0);
    document.getElementById("last-refresh").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (err) {
    document.getElementById("last-refresh").textContent = "Auth required or error: " + err.message;
  }
}

async function loadReviews() {
  const repo = encodeURIComponent(document.getElementById("rev-repo-filter").value.trim());
  const st = encodeURIComponent(document.getElementById("rev-status-filter").value);
  const c = document.getElementById("reviews-container");
  try {
    const res = await fetch("/api/reviews?limit=30&repo=" + repo + "&status=" + st, { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const d = await res.json();
    const items = d.items || [];
    c.textContent = "";
    if (items.length === 0) { c.innerHTML = '<div class="empty">No matching reviews recorded.</div>'; return; }
    const tbl = document.createElement("table");
    tbl.innerHTML = "<thead><tr><th>PR</th><th>SHA</th><th>Status</th><th>Model</th><th>Verdict</th><th>Findings</th><th>Duration</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const r of items) {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(r.pr_key || "-", "mono"));
      tr.appendChild(makeCell((r.head_sha || "-").slice(0, 8), "mono"));
      tr.appendChild(makeCell(r.status || "-"));
      tr.appendChild(makeCell(r.model || "-"));
      tr.appendChild(makeCell(r.verdict || "-"));
      const fCount = Array.isArray(r.findings) ? r.findings.length : 0;
      const states = Array.isArray(r.findings) ? r.findings.map(f => f.state).join(", ") : "-";
      tr.appendChild(makeCell(fCount + " (" + states + ")"));
      tr.appendChild(makeCell(fmtDuration(r.duration_ms)));
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    c.appendChild(tbl);
  } catch (e) { c.textContent = "Failed to load reviews: " + e.message; }
}

async function loadLanguages() {
  const c = document.getElementById("lang-container");
  try {
    const res = await fetch("/api/languages", { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const list = await res.json();
    c.textContent = "";
    const tbl = document.createElement("table");
    tbl.innerHTML = "<thead><tr><th>Language</th><th>Adapter</th><th>Capabilities</th><th>Limitations</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const l of list) {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(l.language + " (" + l.version + ")"));
      tr.appendChild(makeCell(l.adapter, "mono"));
      tr.appendChild(makeCell((l.capabilities || []).join(", ")));
      tr.appendChild(makeCell(l.limitations || "-"));
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    c.appendChild(tbl);
  } catch (e) { c.textContent = "Failed: " + e.message; }
}

async function loadOrgGraph() {
  const c = document.getElementById("graph-container");
  try {
    const res = await fetch("/api/org-graph", { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const g = await res.json();
    const edges = g.edges || [];
    c.textContent = "";
    if (edges.length === 0) { c.innerHTML = '<div class="empty">No cross-repo edges indexed yet.</div>'; return; }
    const tbl = document.createElement("table");
    tbl.innerHTML = "<thead><tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const ed of edges.slice(0, 80)) {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(ed.from, "mono"));
      tr.appendChild(makeCell(ed.relation));
      tr.appendChild(makeCell(ed.to, "mono"));
      tr.appendChild(makeCell(ed.confidence));
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    c.appendChild(tbl);
  } catch (e) { c.textContent = "Failed: " + e.message; }
}

async function loadAudit() {
  const c = document.getElementById("audit-container");
  try {
    const res = await fetch("/api/audit?limit=100", { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const d = await res.json();
    const evs = d.events || [];
    c.textContent = "";
    if (evs.length === 0) { c.innerHTML = '<div class="empty">No audit events recorded yet.</div>'; return; }
    const tbl = document.createElement("table");
    tbl.innerHTML = "<thead><tr><th>Time</th><th>Actor</th><th>PR</th><th>Action</th><th>Decision</th><th>Reason</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const ev of evs) {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "-"));
      tr.appendChild(makeCell(ev.actor || "-"));
      tr.appendChild(makeCell(ev.pr_key || "-", "mono"));
      tr.appendChild(makeCell(ev.action || "-"));
      tr.appendChild(makeCell(ev.decision || "-"));
      tr.appendChild(makeCell(ev.reason || "-"));
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    c.appendChild(tbl);
  } catch (e) { c.textContent = "Failed: " + e.message; }
}

document.getElementById("rev-refresh").addEventListener("click", loadReviews);
document.getElementById("lang-refresh").addEventListener("click", loadLanguages);
document.getElementById("graph-refresh").addEventListener("click", loadOrgGraph);
document.getElementById("audit-refresh").addEventListener("click", loadAudit);

document.getElementById("mem-refresh").addEventListener("click", async () => {
  const out = document.getElementById("mem-output");
  const res = await fetch("/api/memory", { cache: "no-store" });
  out.textContent = res.ok ? JSON.stringify(await res.json(), null, 2) : "HTTP " + res.status;
});

document.getElementById("rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await fetch("/api/memory", {
    method: "POST",
    headers: writeHeaders(),
    body: JSON.stringify({
      kind: "rule",
      rule: {
        id: document.getElementById("rule-id").value.trim(),
        repo: document.getElementById("rule-repo").value.trim(),
        instruction: document.getElementById("rule-instr").value.trim(),
        scope: "repo"
      }
    })
  });
  document.getElementById("mem-output").textContent = res.ok ? "Saved rule." : "Failed: HTTP " + res.status;
});

document.getElementById("bench-run").addEventListener("click", async () => {
  const c = document.getElementById("bench-container");
  c.innerHTML = '<div class="empty">Running split benchmarks...</div>';
  const res = await fetch("/api/benchmarks", { cache: "no-store" });
  if (!res.ok) { c.textContent = "Failed: HTTP " + res.status; return; }
  const d = await res.json();
  const splits = d.splits || [];
  c.textContent = "";
  const tbl = document.createElement("table");
  tbl.innerHTML = "<thead><tr><th>Split</th><th>Cases</th><th>TP / FP / FN</th><th>Precision (95% CI)</th><th>Recall (95% CI)</th><th>FPR (95% CI)</th><th>FP/PR</th></tr></thead>";
  const tb = document.createElement("tbody");
  for (const s of splits) {
    const tr = document.createElement("tr");
    tr.appendChild(makeCell(s.split || s.dataset));
    tr.appendChild(makeCell(String(s.cases)));
    tr.appendChild(makeCell(s.true_positives + " / " + s.false_positives + " / " + s.false_negatives));
    tr.appendChild(makeCell(s.precision.toFixed(3) + " [" + s.precision_ci_95.lower.toFixed(3) + ".." + s.precision_ci_95.upper.toFixed(3) + "]"));
    tr.appendChild(makeCell(s.recall.toFixed(3) + " [" + s.recall_ci_95.lower.toFixed(3) + ".." + s.recall_ci_95.upper.toFixed(3) + "]"));
    tr.appendChild(makeCell(s.false_positive_rate.toFixed(3) + " [" + s.fp_rate_ci_95.lower.toFixed(3) + ".." + s.fp_rate_ci_95.upper.toFixed(3) + "]"));
    tr.appendChild(makeCell(s.false_positives_per_pr.toFixed(3)));
    tb.appendChild(tr);
  }
  tbl.appendChild(tb);
  c.appendChild(tbl);
});

document.getElementById("dry-run-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const outEl = document.getElementById("dr-output");
  outEl.textContent = "Running shadow replay...";
  const skillsRaw = document.getElementById("dr-skills").value.trim();
  const skills = skillsRaw ? skillsRaw.split(",").map(s => s.trim()).filter(Boolean) : [];
  try {
    const res = await fetch("/api/replay", {
      method: "POST",
      headers: writeHeaders(),
      body: JSON.stringify({
        repo: document.getElementById("dr-repo").value.trim(),
        pr_number: Number(document.getElementById("dr-pr").value),
        skills: skills,
        offline: document.getElementById("dr-offline").checked
      })
    });
    const text = await res.text();
    if (!res.ok) throw new Error(text || ("HTTP " + res.status));
    outEl.textContent = JSON.stringify(JSON.parse(text), null, 2);
  } catch (err) {
    outEl.textContent = "Replay failed: " + err.message;
  }
});

ensureSession().then(() => { connectSSE(); refresh(); });
setInterval(refresh, 5000);
</script>
</body>
</html>
`
