// Dashboard page logic: pulls live stats from the DNSentinel API and
// renders the SOC-style overview (cards, charts, recent queries table).

const API_BASE = "http://localhost:8000";

async function fetchJSON(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return res.json();
}

function actionBadge(action) {
  return `<span class="badge ${action}">${action}</span>`;
}

async function loadOverview() {
  const stats = await fetchJSON("/api/stats");

  document.getElementById("stat-total").textContent = stats.total_queries;
  document.getElementById("stat-blocked").textContent = stats.blocked;
  document.getElementById("stat-alerted").textContent = stats.alerted;
  document.getElementById("stat-monitored").textContent = stats.monitored;
  document.getElementById("stat-allowed").textContent = stats.allowed;
  document.getElementById("stat-indicators").textContent = stats.threat_indicators;
  document.getElementById("stat-latency").textContent = `${stats.avg_latency_ms} ms`;
  document.getElementById("stat-open-alerts").textContent = stats.open_alerts;

  renderActionDonut("actionDonut", stats);
}

async function loadTimeline() {
  const timeline = await fetchJSON("/api/stats/timeline?hours=24");
  if (timeline.length === 0) {
    document.getElementById("timelineEmpty").style.display = "block";
    return;
  }
  renderTimelineChart("timelineChart", timeline);
}

async function loadRecentQueries() {
  const rows = await fetchJSON("/api/dns/history?limit=25");
  const tbody = document.getElementById("recentQueriesBody");
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No DNS queries yet. Try the analyzer above or run scripts/seed_database.py.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(
      (r) => `
      <tr>
        <td>${new Date(r.timestamp).toLocaleTimeString()}</td>
        <td>${r.domain}</td>
        <td>${r.client_ip}</td>
        <td>${actionBadge(r.action)}</td>
        <td>${r.risk_score.toFixed(1)}</td>
      </tr>`
    )
    .join("");
}

async function loadTopDomains() {
  const rows = await fetchJSON("/api/stats/top-domains?limit=8");
  const tbody = document.getElementById("topDomainsBody");
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty-state">No blocked domains yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map((r) => `<tr><td>${r.domain}</td><td>${r.block_count}</td></tr>`)
    .join("");
}

async function refreshAll() {
  try {
    await Promise.all([loadOverview(), loadTimeline(), loadRecentQueries(), loadTopDomains()]);
  } catch (err) {
    console.error("Dashboard refresh failed:", err);
    document.getElementById("apiWarning").style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshAll();
  setInterval(refreshAll, 10000); // auto-refresh every 10s for the live demo
});
