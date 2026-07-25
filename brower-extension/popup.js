const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

function badgeClass(score) {
  if (score >= 55) return "risky";
  if (score >= 20) return "suspicious";
  return "safe";
}

function badgeLabel(score) {
  if (score >= 55) return "HIGH RISK";
  if (score >= 20) return "SUSPICIOUS";
  return "SAFE";
}

function render(results) {
  resultsEl.innerHTML = "";
  if (!results.length) {
    resultsEl.innerHTML = '<div class="empty">No inbox messages found.</div>';
    return;
  }
  for (const r of results) {
    const li = document.createElement("li");
    li.className = "email";
    const fromLabel = r.from?.display_name
      ? `${r.from.display_name} <${r.from.address}>`
      : (r.from?.address || "unknown sender");

    li.innerHTML = `
      <div class="row-top">
        <div class="subject" title="${escapeHtml(r.subject || "(no subject)")}">${escapeHtml(r.subject || "(no subject)")}</div>
        <span class="badge ${badgeClass(r.score)}">${badgeLabel(r.score)} ${r.score}</span>
      </div>
      <div class="from" title="${escapeHtml(fromLabel)}">${escapeHtml(fromLabel)}</div>
      ${r.reasons.length ? `<ul class="reasons">${r.reasons.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
    `;
    resultsEl.appendChild(li);
  }
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

scanBtn.addEventListener("click", () => {
  scanBtn.disabled = true;
  statusEl.textContent = "Scanning your inbox... this may take a moment.";
  resultsEl.innerHTML = "";

  chrome.runtime.sendMessage({ type: "SCAN_INBOX", maxResults: 15 }, (response) => {
    scanBtn.disabled = false;
    if (!response) {
      statusEl.textContent = "No response from background worker.";
      return;
    }
    if (!response.ok) {
      statusEl.textContent = "Error: " + response.error;
      return;
    }
    statusEl.textContent = `Scanned ${response.results.length} emails.`;
    render(response.results);
  });
});