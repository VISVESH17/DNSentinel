// Shared Chart.js helpers for the DNSentinel dashboard.
// Loaded on pages that render charts (dashboard.html).

const CHART_COLORS = {
  ALLOW: "#22c55e",
  MONITOR: "#eab308",
  ALERT: "#f97316",
  BLOCK: "#ef4444",
};

function renderTimelineChart(canvasId, timelineData) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  const labels = timelineData.map((d) => d.time.split(" ")[1] || d.time);
  const datasets = ["ALLOW", "MONITOR", "ALERT", "BLOCK"].map((action) => ({
    label: action,
    data: timelineData.map((d) => d[action] || 0),
    borderColor: CHART_COLORS[action],
    backgroundColor: CHART_COLORS[action] + "33",
    tension: 0.3,
    fill: true,
  }));

  new Chart(ctx, {
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

function renderActionDonut(canvasId, stats) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Allowed", "Monitored", "Alerted", "Blocked"],
      datasets: [{
        data: [stats.allowed, stats.monitored, stats.alerted, stats.blocked],
        backgroundColor: [
          CHART_COLORS.ALLOW, CHART_COLORS.MONITOR, CHART_COLORS.ALERT, CHART_COLORS.BLOCK,
        ],
        borderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom", labels: { color: "#e5e7eb" } } },
    },
  });
}
