// DNSentinel single-page app: tab navigation + shared auth state.
// Combines what used to be analyzer.js / dashboard.js / alerts.html / domains.html / investigation.html
// into one script so the whole product lives at one URL.

const API_BASE = "http://localhost:8000";

// ---------- Shared auth state ----------
let authToken = null;
let authUser = null;
let dashboardInterval = null;

function updateNavAuthStatus() {
  const el = document.getElementById("navAuthStatus");
  if (authUser) {
    el.innerHTML = `Signed in as <strong style="color:var(--accent)">${authUser.username}</strong> (${authUser.role}) &middot; <a href="#" id="navSignOut" style="color:var(--muted)">sign out</a>`;
    document.getElementById("navSignOut").addEventListener("click", (e) => {
      e.preventDefault();
      authToken = null;
      authUser = null;
      updateNavAuthStatus();
      renderAuthGatedSections();
    });
  } else {
    el.innerHTML = `<a href="#" id="navSignIn" style="color:var(--accent)">Sign in</a>`;
    document.getElementById("navSignIn").addEventListener("click", (e) => {
      e.preventDefault();
      openLoginModal();
    });
  }
}

function openLoginModal() {
  document.getElementById("loginOverlay").style.display = "flex";
  document.getElementById("loginModalStatus").textContent = "";
}
function closeLoginModal() {
  document.getElementById("loginOverlay").style.display = "none";
}

document.getElementById("loginModalCancel").addEventListener("click", closeLoginModal);

document.getElementById("loginModalSubmit").addEventListener("click", async () => {
  const username = document.getElementById("loginUsername").value;
  const password = document.getElementById("loginPassword").value;
  const statusEl = document.getElementById("loginModalStatus");
  statusEl.textContent = "Signing in...";
  try {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    });
    if (!res.ok) { statusEl.textContent = "Invalid credentials."; return; }
    const data = await res.json();
    authToken = data.access_token;
    authUser = { username, role: data.role };
    closeLoginModal();
    updateNavAuthStatus();
    renderAuthGatedSections();
  } catch (err) {
    statusEl.textContent = `Could not reach the API at ${API_BASE}.`;
  }
});

function renderAuthGatedSections() {
  const signedIn = !!authToken;
  document.getElementById("investSignedOutMsg").style.display = signedIn ? "none" : "block";
  document.getElementById("investAuthedPanels").style.display = signedIn ? "block" : "none";
  if (document.getElementById("tab-alerts").style.display !== "none") loadAlerts();
}

// ---------- Tab navigation ----------
const TAB_NAMES = ["analyzer", "dashboard", "alerts", "domains", "investigation"];

function switchTab(tabName) {
  TAB_NAMES.forEach((name) => {
    document.getElementById(`tab-${name}`).style.display = name === tabName ? "block" : "none";
    document.querySelector(`.tab-link[data-tab="${name}"]`).classList.toggle("active", name === tabName);
  });

  if (dashboardInterval) { clearInterval(dashboardInterval); dashboardInterval = null; }

  if (tabName === "dashboard") {
    refreshDashboard();
    dashboardInterval = setInterval(refreshDashboard, 10000);
  } else if (tabName === "alerts") {
    loadAlerts();
  } else if (tabName === "domains") {
    loadIndicators();
  }

  window.location.hash = tabName;
}

document.querySelectorAll(".tab-link").forEach((link) => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    switchTab(link.dataset.tab);
  });
});

// ---------- Analyzer tab ----------
function classificationClass(action) {
  return { ALLOW: "safe", MONITOR: "monitor", ALERT: "alert", BLOCK: "block" }[action] || "";
}

async function checkDomain(domain) {
  const resultBox = document.getElementById("resultBox");
  resultBox.classList.remove("show");
  resultBox.innerHTML = `<span style="color:var(--muted)">Checking...</span>`;
  resultBox.classList.add("show");

  try {
    const res = await fetch(`${API_BASE}/api/dns/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      resultBox.innerHTML = `<strong style="color:var(--block)">Error:</strong> ${err.detail || res.statusText}`;
      return;
    }
    const data = await res.json();
    const cls = classificationClass(data.action);
    resultBox.style.borderColor = `var(--${cls})`;
    resultBox.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
          <div style="font-size:1.1rem;font-weight:700;">${data.domain}</div>
          <div style="color:var(--muted);font-size:0.85rem;">Resolved: ${data.resolved_ip} &middot; ${data.latency_ms} ms</div>
        </div>
        <span class="badge ${data.action}" style="font-size:0.95rem;padding:6px 16px;">${data.action}</span>
      </div>
      <div style="margin-top:12px;">
        <strong>Risk score:</strong> ${data.risk_score} / 100 &nbsp; (${data.classification})
      </div>
      ${data.reasons.length ? `<ul class="reasons">${data.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>` : `<div class="reasons">No risk signals detected.</div>`}
    `;
  } catch (err) {
    resultBox.innerHTML = `<strong style="color:var(--block)">Could not reach the API.</strong> Is the backend running on ${API_BASE}?`;
  }
}

document.getElementById("checkForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const domain = document.getElementById("domainInput").value.trim();
  if (domain) checkDomain(domain);
});

document.querySelectorAll(".sample-domain").forEach((el) => {
  el.addEventListener("click", () => {
    document.getElementById("domainInput").value = el.textContent.trim();
    checkDomain(el.textContent.trim());
  });
});

// ---------- Dashboard tab ----------
async function fetchJSON(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, opts);
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return res.json();
}

let timelineChartInstance = null;
let donutChartInstance = null;

function actionBadge(action) {
  return `<span class="badge ${action}">${action}</span>`;
}

async function refreshDashboard() {
  try {
    const stats = await fetchJSON("/api/stats");
    document.getElementById("stat-total").textContent = stats.total_queries;
    document.getElementById("stat-blocked").textContent = stats.blocked;
    document.getElementById("stat-alerted").textContent = stats.alerted;
    document.getElementById("stat-monitored").textContent = stats.monitored;
    document.getElementById("stat-allowed").textContent = stats.allowed;
    document.getElementById("stat-indicators").textContent = stats.threat_indicators;
    document.getElementById("stat-latency").textContent = `${stats.avg_latency_ms} ms`;
    document.getElementById("stat-open-alerts").textContent = stats.open_alerts;

    if (donutChartInstance) donutChartInstance.destroy();
    donutChartInstance = new Chart(document.getElementById("actionDonut"), {
      type: "doughnut",
      data: {
        labels: ["Allowed", "Monitored", "Alerted", "Blocked"],
        datasets: [{
          data: [stats.allowed, stats.monitored, stats.alerted, stats.blocked],
          backgroundColor: ["#22c55e", "#eab308", "#f97316", "#ef4444"],
          borderWidth: 0,
        }],
      },
      options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "#e5e7eb" } } } },
    });

    const timeline = await fetchJSON("/api/stats/timeline?hours=24");
    document.getElementById("timelineEmpty").style.display = timeline.length === 0 ? "block" : "none";
    if (timeline.length > 0) {
      if (timelineChartInstance) timelineChartInstance.destroy();
      const labels = timeline.map((d) => d.time.split(" ")[1] || d.time);
      const colors = { ALLOW: "#22c55e", MONITOR: "#eab308", ALERT: "#f97316", BLOCK: "#ef4444" };
      const datasets = ["ALLOW", "MONITOR", "ALERT", "BLOCK"].map((action) => ({
        label: action,
        data: timeline.map((d) => d[action] || 0),
        borderColor: colors[action],
        backgroundColor: colors[action] + "33",
        tension: 0.3,
        fill: true,
      }));
      timelineChartInstance = new Chart(document.getElementById("timelineChart"), {
        type: "line",
        data: { labels, datasets },
        options: {
          responsive: true,
          plugins: { legend: { labels: { color: "#e5e7eb" } } },
          scales: {
            x: { ticks: { color: "#8b98a9" }, grid: { color: "#1f2937" } },
            y: { ticks: { color: "#8b98a9" }, grid: { color: "#1f2937" }, beginAtZero: true },
          },
        },
      });
    }

    const recent = await fetchJSON("/api/dns/history?limit=25");
    const recentBody = document.getElementById("recentQueriesBody");
    recentBody.innerHTML = recent.length === 0
      ? `<tr><td colspan="5" class="empty-state">No DNS queries yet. Try the analyzer tab.</td></tr>`
      : recent.map((r) => `
          <tr>
            <td>${new Date(r.timestamp).toLocaleTimeString()}</td>
            <td>${r.domain}</td>
            <td>${r.client_ip}</td>
            <td>${actionBadge(r.action)}</td>
            <td>${r.risk_score.toFixed(1)}</td>
          </tr>`).join("");

    const topDomains = await fetchJSON("/api/stats/top-domains?limit=8");
    const topBody = document.getElementById("topDomainsBody");
    topBody.innerHTML = topDomains.length === 0
      ? `<tr><td colspan="2" class="empty-state">No blocked domains yet.</td></tr>`
      : topDomains.map((r) => `<tr><td>${r.domain}</td><td>${r.block_count}</td></tr>`).join("");

    document.getElementById("dashApiWarning").style.display = "none";
  } catch (err) {
    document.getElementById("dashApiWarning").style.display = "block";
  }
}

// ---------- Alerts tab ----------
async function setAlertStatus(alertId, status) {
  await fetch(`${API_BASE}/api/alerts/${alertId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${authToken}` },
    body: JSON.stringify({ status }),
  });
  loadAlerts();
}
window.setAlertStatus = setAlertStatus;

async function loadAlerts() {
  const tbody = document.getElementById("alertsBody");
  if (!authToken) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Sign in above to load alerts.</td></tr>`;
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/alerts?limit=100`, { headers: { Authorization: `Bearer ${authToken}` } });
    if (res.status === 401) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Session expired — please sign in again.</td></tr>`;
      return;
    }
    const rows = await res.json();
    tbody.innerHTML = rows.length === 0
      ? `<tr><td colspan="7" class="empty-state">No alerts yet. Check a suspicious domain on the Analyzer tab.</td></tr>`
      : rows.map((r) => `
          <tr>
            <td>${r.domain}</td>
            <td>${r.client_ip}</td>
            <td>${r.severity}</td>
            <td>${r.alert_type}</td>
            <td>${r.status}</td>
            <td>${new Date(r.created_at).toLocaleString()}</td>
            <td>
              ${r.status === "open" || r.status === "investigating" ? `
                <button onclick="setAlertStatus(${r.id}, 'resolved')" style="background:var(--safe);border:none;color:#05161a;padding:4px 10px;border-radius:6px;font-size:0.78rem;cursor:pointer;margin-right:4px;">Confirm</button>
                <button onclick="setAlertStatus(${r.id}, 'false_positive')" style="background:transparent;border:1px solid var(--panel-border);color:var(--muted);padding:4px 10px;border-radius:6px;font-size:0.78rem;cursor:pointer;">False positive</button>
              ` : `<span style="color:var(--muted);font-size:0.8rem;">—</span>`}
            </td>
          </tr>`).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Could not reach the API at ${API_BASE}.</td></tr>`;
  }
}

// ---------- Domains tab ----------
async function loadIndicators() {
  const tbody = document.getElementById("indicatorsBody");
  try {
    const rows = await fetchJSON("/api/threat/indicators?limit=200");
    tbody.innerHTML = rows.length === 0
      ? `<tr><td colspan="6" class="empty-state">No indicators synced yet. Click "Sync CSV feeds now".</td></tr>`
      : rows.map((r) => `
          <tr>
            <td>${r.indicator}</td><td>${r.type}</td><td>${r.source}</td>
            <td>${r.confidence}</td><td>${r.severity}</td>
            <td>${new Date(r.last_seen).toLocaleString()}</td>
          </tr>`).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Could not reach the API at ${API_BASE}.</td></tr>`;
  }
}

document.getElementById("syncBtn").addEventListener("click", async () => {
  if (!authToken) { openLoginModal(); return; }
  await fetch(`${API_BASE}/api/threat/feeds/sync`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` } });
  loadIndicators();
});

// ---------- Investigation tab ----------
document.getElementById("stixSyncBtn").addEventListener("click", async () => {
  const resultEl = document.getElementById("stixResult");
  resultEl.textContent = "Syncing...";
  try {
    const res = await fetch(`${API_BASE}/api/threat/feeds/sync-stix`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` } });
    const data = await res.json();
    if (!res.ok) { resultEl.innerHTML = `<span style="color:var(--block)">${data.detail}</span>`; return; }
    resultEl.innerHTML = `<span style="color:var(--safe)">Ingested ${data.ingested_indicators} indicators from bundle ${data.bundle_id}</span>`;
  } catch (err) {
    resultEl.innerHTML = `<span style="color:var(--block)">Request failed.</span>`;
  }
});

document.getElementById("uploadBtn").addEventListener("click", async () => {
  const fileInput = document.getElementById("pcapFile");
  const resultEl = document.getElementById("pcapResult");
  if (!fileInput.files.length) {
    resultEl.innerHTML = `<span style="color:var(--monitor)">Choose a .log file first (or use data/sample_zeek_dns.log).</span>`;
    return;
  }
  resultEl.textContent = "Analyzing...";
  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  try {
    const res = await fetch(`${API_BASE}/api/pcap/upload`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` }, body: formData });
    const data = await res.json();
    if (!res.ok) { resultEl.innerHTML = `<span style="color:var(--block)">${data.detail}</span>`; return; }
    const suspected = data.results.filter((r) => r.is_tunnel_suspected);
    resultEl.innerHTML = `
      <div class="panel" style="margin-bottom:0;">
        <div><strong>${data.total_dns_records}</strong> DNS records &middot; <strong>${data.sessions_analyzed}</strong> sessions analyzed</div>
        <div style="margin-top:6px;color:${suspected.length ? "var(--block)" : "var(--safe)"};font-weight:700;">${suspected.length} tunnel-suspected session(s)</div>
        ${suspected.map((s) => `
          <div style="margin-top:12px;padding:10px;border:1px solid var(--panel-border);border-radius:8px;">
            <strong>${s.client_ip}</strong> → ${s.base_domain}
            <div style="font-size:0.85rem;color:var(--muted);">Anomaly probability: ${s.anomaly_probability}</div>
            <ul class="reasons">${s.rule_flags.map((f) => `<li>${f}</li>`).join("")}</ul>
          </div>`).join("")}
      </div>`;
  } catch (err) {
    resultEl.innerHTML = `<span style="color:var(--block)">Upload failed.</span>`;
  }
});

// ---------- Init ----------
document.addEventListener("DOMContentLoaded", () => {
  updateNavAuthStatus();
  renderAuthGatedSections();
  const initialTab = window.location.hash.replace("#", "") || "analyzer";
  switchTab(TAB_NAMES.includes(initialTab) ? initialTab : "analyzer");
});
