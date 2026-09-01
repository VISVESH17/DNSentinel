// Powers the "Check a domain" form on index.html -- calls POST /api/dns/check
// and renders the risk decision live. This is the core demo interaction.

const API_BASE = "http://localhost:8000";

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
      ${
        data.reasons.length
          ? `<ul class="reasons">${data.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>`
          : `<div class="reasons">No risk signals detected.</div>`
      }
    `;
  } catch (err) {
    resultBox.innerHTML = `<strong style="color:var(--block)">Could not reach the API.</strong> Is the backend running on ${API_BASE}?`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("checkForm");
  if (!form) return;

  form.addEventListener("submit", (e) => {
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
});
