/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – core.js
   Global constants, state, API helpers, formatters, chart utilities.
   ═══════════════════════════════════════════════════════════════════════════ */

const API = '';  // same origin

// ── Shared mutable state ──────────────────────────────────────────────────

let liveInterval = null;
let livePaused = false;
let liveCursorHttp = null;
let liveCursorWs = null;
let charts = {};

let _authToken = sessionStorage.getItem('llmproxy_token') || '';
let _isAdmin = false;
let _authRequired = false;
let _myTenantId = null;
let _myName = null;
let _activePage = 'overview';

// ── Auth header helper ────────────────────────────────────────────────────

function _authHeaders() {
    const h = {};
    if (_authToken) h['Authorization'] = 'Bearer ' + _authToken;
    return h;
}

// ── Tenant helpers ────────────────────────────────────────────────────────

function getSelectedTenant() {
    if (_authRequired && !_isAdmin) return '';
    return document.getElementById('tenant-select')?.value || '';
}

function _appendTenant(path) {
    const tid = getSelectedTenant();
    if (!tid) return path;
    const sep = path.includes('?') ? '&' : '?';
    return path + sep + 'tenant_id=' + encodeURIComponent(tid);
}

// ── API helpers ───────────────────────────────────────────────────────────

async function api(path) {
    const res = await fetch(API + _appendTenant(path), { headers: _authHeaders() });
    if (res.status === 401) { doLogout(); throw new Error('Unauthorized'); }
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
}

async function apiPost(path, body) {
    const res = await fetch(API + _appendTenant(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ..._authHeaders() },
        body: JSON.stringify(body),
    });
    if (res.status === 401) { doLogout(); throw new Error('Unauthorized'); }
    return res.json();
}

async function apiDelete(path) {
    const res = await fetch(API + _appendTenant(path), { method: 'DELETE', headers: _authHeaders() });
    if (res.status === 401) { doLogout(); throw new Error('Unauthorized'); }
    return res.json();
}

// ── Formatters ────────────────────────────────────────────────────────────

function esc(s) {
    if (s == null) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function formatBytes(b) {
    if (!b || b === 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
    return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}

function formatDuration(ms) {
    if (ms == null) return '-';
    if (ms < 1000) return Math.round(ms) + ' ms';
    return (ms / 1000).toFixed(2) + ' s';
}

function formatTime(ts) {
    if (!ts) return '-';
    return new Date(ts).toLocaleTimeString();
}

function formatDateTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

// ── Badge helpers ─────────────────────────────────────────────────────────

function statusClass(code) {
    if (!code) return '';
    if (code < 300) return 's2xx';
    if (code < 400) return 's3xx';
    if (code < 500) return 's4xx';
    return 's5xx';
}

function methodBadge(m) {
    return `<span class="badge badge-method ${esc(m)}">${esc(m)}</span>`;
}

function statusBadge(s) {
    if (!s) return '-';
    return `<span class="badge badge-status ${statusClass(s)}">${s}</span>`;
}

function severityBadge(sev) {
    return `<span class="badge badge-severity ${esc(sev)}">${esc(sev)}</span>`;
}

function statCard(label, value, changeClass) {
    return `<div class="stat-card">
        <div class="stat-label">${esc(label)}</div>
        <div class="stat-value${changeClass ? ' stat-change ' + changeClass : ''}">${esc(String(value))}</div>
    </div>`;
}

function emptyState(msg) {
    return `<div class="empty-state"><div class="icon"><i class="fa-solid fa-inbox"></i></div><p>${esc(msg)}</p></div>`;
}

function formatAction(action) {
    if (action == null) return '-';
    if (typeof action === 'string') return esc(action);
    const parts = [];
    if (action.status) parts.push(`<strong>${action.status}</strong>`);
    if (action.body) parts.push(`<span style="color:var(--text-secondary)">${esc(String(action.body).substring(0, 80))}</span>`);
    if (parts.length > 0) return parts.join(' &mdash; ');
    return `<pre class="body-preview" style="margin:0;padding:4px 8px;max-height:100px;font-size:11px">${esc(JSON.stringify(action, null, 2))}</pre>`;
}

function tryPrettyJson(s) {
    if (!s) return '';
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch(_) { return s; }
}

// ── Chart helpers ─────────────────────────────────────────────────────────

const chartColors = [
    '#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff',
    '#f778ba', '#39d2c0', '#e3b341', '#79c0ff', '#56d364',
];

function destroyChart(id) {
    if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

function makeChart(canvasId, config) {
    destroyChart(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    config.options = config.options || {};
    config.options.responsive = true;
    config.options.maintainAspectRatio = false;
    config.options.plugins = config.options.plugins || {};
    config.options.plugins.legend = config.options.plugins.legend || { labels: { color: '#8b949e', font: { size: 11 } } };
    if (config.options.scales) {
        for (const axis of Object.values(config.options.scales)) {
            axis.ticks = axis.ticks || {};
            axis.ticks.color = axis.ticks.color || '#6e7681';
            axis.grid = axis.grid || {};
            axis.grid.color = axis.grid.color || 'rgba(48,54,61,0.5)';
        }
    }
    charts[canvasId] = new Chart(ctx, config);
    return charts[canvasId];
}
