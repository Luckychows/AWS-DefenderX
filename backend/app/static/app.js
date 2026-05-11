const el = (id) => document.getElementById(id);

const state = {
  findings: [],
  activeId: null,
};

const cfg = window.CMS_CONFIG || {};
const API_BASE = (cfg.apiBaseUrl || "").replace(/\/+$/, "");
const API_TOKEN = cfg.apiToken || "";
const CLOUD_MODE = Boolean(API_BASE);

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmtDate(s) {
  try {
    return new Date(s).toLocaleString();
  } catch {
    return s;
  }
}

async function apiGet(path) {
  const url = API_BASE ? `${API_BASE}${path}` : path;
  const headers = {};
  if (API_TOKEN) headers["x-api-token"] = API_TOKEN;
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(await r.text());
  return await r.json();
}

async function apiPost(path) {
  const url = API_BASE ? `${API_BASE}${path}` : path;
  const headers = {};
  if (API_TOKEN) headers["x-api-token"] = API_TOKEN;
  const r = await fetch(url, { method: "POST", headers });
  if (!r.ok) throw new Error(await r.text());
  return await r.json();
}

function showError(message) {
  const detail = el("detail");
  if (!detail) return;
  const safe = escapeHtml(message || "Unknown error");
  const box = document.createElement("div");
  box.className = "box";
  box.style.borderColor = "rgba(239,68,68,0.55)";
  box.innerHTML = `<pre>Action failed:\n${safe}</pre>`;
  detail.prepend(box);
}

function renderStats() {
  const total = state.findings.length;
  const open = state.findings.filter((f) => f.status === "open").length;
  const rem = state.findings.filter((f) => f.status === "remediated").length;
  el("stats").textContent = `${total} total • ${open} open • ${rem} remediated`;
}

function rowHtml(f) {
  const sev = escapeHtml(f.severity);
  const title = escapeHtml(f.title);
  const desc = escapeHtml(f.description);
  const badge = escapeHtml(f.status);
  const active = f.finding_id === state.activeId ? "active" : "";
  return `
    <div class="row ${active}" data-id="${escapeHtml(f.finding_id)}">
      <div class="sev ${sev}"></div>
      <div class="main">
        <div class="t">${title}</div>
        <div class="d">${desc}</div>
      </div>
      <div class="badge">${badge}</div>
    </div>
  `;
}

function renderList() {
  el("findings").innerHTML = state.findings.map(rowHtml).join("") || `<div class="detail empty"><div class="hint">No findings yet. Click “Load sample findings”.</div></div>`;
  for (const node of document.querySelectorAll(".row")) {
    node.addEventListener("click", async () => {
      const id = node.getAttribute("data-id");
      state.activeId = id;
      renderList();
      await loadDetail(id);
    });
  }
}

function detailHtml(payload) {
  const f = payload.finding;
  const rems = payload.remediations || [];

  const ai = f.ai_summary
    ? `<div class="box"><pre>${escapeHtml(f.ai_summary)}</pre></div>`
    : `<div class="box"><pre>No AI summary yet.</pre></div>`;

  const remList =
    rems.length === 0
      ? `<div class="box"><pre>No remediation actions recorded.</pre></div>`
      : `<div class="box"><pre>${escapeHtml(JSON.stringify(rems, null, 2))}</pre></div>`;

  return `
    <div class="kvs">
      <div class="kvk">Finding ID</div><div class="kvv">${escapeHtml(f.finding_id)}</div>
      <div class="kvk">Status</div><div class="kvv">${escapeHtml(f.status)}</div>
      <div class="kvk">Severity</div><div class="kvv">${escapeHtml(f.severity)}</div>
      <div class="kvk">Resource</div><div class="kvv">${escapeHtml(f.resource_id)}</div>
      <div class="kvk">Region</div><div class="kvv">${escapeHtml(f.region)}</div>
      <div class="kvk">Account</div><div class="kvv">${escapeHtml(f.account_id)}</div>
      <div class="kvk">Created</div><div class="kvv">${escapeHtml(fmtDate(f.created_at))}</div>
    </div>

    <div class="actions" style="margin: 8px 0 2px; justify-content: flex-start;">
      <button id="aiBtn" class="btn primary">Generate AI summary</button>
      <button id="remBtn" class="btn">Record remediation</button>
    </div>

    <div class="sectionTitle">Risk</div>
    <div class="box"><pre>${escapeHtml(f.risk)}</pre></div>

    <div class="sectionTitle">Recommendation</div>
    <div class="box"><pre>${escapeHtml(f.recommendation)}</pre></div>

    <div class="sectionTitle">AI summary</div>
    ${ai}

    <div class="sectionTitle">Event</div>
    <div class="box"><pre>${escapeHtml(JSON.stringify(f.event, null, 2))}</pre></div>

    <div class="sectionTitle">Remediation actions</div>
    ${remList}
  `;
}

async function loadDetail(id) {
  el("detailMeta").textContent = `Loading ${id}...`;
  el("detail").classList.remove("empty");
  el("detail").innerHTML = `<div class="box"><pre>Loading…</pre></div>`;

  const payload = CLOUD_MODE
    ? await apiGet(`/findings/${encodeURIComponent(id)}`)
    : await apiGet(`/api/findings/${encodeURIComponent(id)}`);
  const normalized = CLOUD_MODE
    ? { finding: payload.finding, remediations: [] }
    : payload;
  el("detailMeta").textContent = normalized.finding.title;
  el("detail").innerHTML = detailHtml(normalized);

  el("aiBtn").addEventListener("click", async () => {
    el("aiBtn").disabled = true;
    try {
      await apiPost(`${CLOUD_MODE ? "" : "/api"}/findings/${encodeURIComponent(id)}/summarize`);
      await loadDetail(id);
    } catch (e) {
      showError(e?.message || String(e));
    } finally {
      el("aiBtn").disabled = false;
    }
  });

  el("remBtn").addEventListener("click", async () => {
    el("remBtn").disabled = true;
    try {
      await apiPost(`${CLOUD_MODE ? "" : "/api"}/findings/${encodeURIComponent(id)}/remediate`);
      await refresh();
      await loadDetail(id);
    } catch (e) {
      showError(e?.message || String(e));
    } finally {
      el("remBtn").disabled = false;
    }
  });
}

async function refresh() {
  const status = el("statusFilter").value;
  const limit = el("limitFilter").value;
  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  qs.set("limit", limit);
  const base = CLOUD_MODE ? "/findings" : "/api/findings";
  const data = await apiGet(`${base}?${qs.toString()}`);
  state.findings = data.findings || [];
  renderStats();
  renderList();
}

async function loadSample() {
  if (CLOUD_MODE) return;
  el("loadSampleBtn").disabled = true;
  try {
    await apiPost("/api/simulate/load-sample");
    await refresh();
  } finally {
    el("loadSampleBtn").disabled = false;
  }
}

function wireUi() {
  el("refreshBtn").addEventListener("click", refresh);
  if (CLOUD_MODE) {
    el("loadSampleBtn").disabled = true;
    el("loadSampleBtn").textContent = "Cloud mode enabled";
    el("loadSampleBtn").title = "Sample loader is local-only. Use AWS scanner/lambda triggers.";
  } else {
    el("loadSampleBtn").addEventListener("click", loadSample);
  }
  el("statusFilter").addEventListener("change", refresh);
  el("limitFilter").addEventListener("change", refresh);
}

wireUi();
refresh().catch((e) => {
  el("stats").textContent = "API error";
  const msg = CLOUD_MODE
    ? "Cloud API unreachable or token missing/invalid. Check CMS_CONFIG in index.html."
    : "Backend not running yet. Start it with <code>uvicorn app.main:app --reload</code>.";
  el("findings").innerHTML = `<div class="detail empty"><div class="hint">${msg}</div></div>`;
  console.error(e);
});

