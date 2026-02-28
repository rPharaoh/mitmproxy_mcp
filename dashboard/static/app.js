/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – app.js
   ═══════════════════════════════════════════════════════════════════════════ */

const API = '';  // same origin
let liveInterval = null;
let livePaused = false;
let liveCursorHttp = null;
let liveCursorWs = null;
let charts = {};

// ─── Auth state ──────────────────────────────────────────────────────────

let _authToken = sessionStorage.getItem('llmproxy_token') || '';
let _isAdmin = false;
let _authRequired = false;
let _myTenantId = null;
let _myName = null;

function _authHeaders() {
    const h = {};
    if (_authToken) h['Authorization'] = 'Bearer ' + _authToken;
    return h;
}

async function checkAuth() {
    try {
        const res = await fetch(API + '/api/auth/check');
        const data = await res.json();
        _authRequired = data.auth_required;
    } catch (_) {
        _authRequired = false;
    }

    if (!_authRequired) {
        _isAdmin = true;
        showApp();
        return;
    }

    // Auth required – check stored token
    if (_authToken) {
        const ok = await validateToken(_authToken);
        if (ok) { showApp(); return; }
        // Token invalid, clear it
        _authToken = '';
        sessionStorage.removeItem('llmproxy_token');
    }

    showLogin();
}

async function validateToken(token) {
    try {
        const res = await fetch(API + '/api/auth/me', {
            headers: { 'Authorization': 'Bearer ' + token },
        });
        if (!res.ok) return false;
        const data = await res.json();
        _isAdmin = data.is_admin;
        _myTenantId = data.tenant_id || null;
        _myName = data.name || null;
        return true;
    } catch (_) {
        return false;
    }
}

function showLogin() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-error').style.display = 'none';
    document.getElementById('login-token').value = '';
    setTimeout(() => document.getElementById('login-token')?.focus(), 100);
}

function showApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-container').style.display = 'flex';
    updateAuthUI();
    loadTenants();
    loadOverview();
}

function updateAuthUI() {
    const selector = document.querySelector('.tenant-selector');
    const badgeEl = document.getElementById('user-badge');

    if (_authRequired) {
        // Show user badge
        if (badgeEl) {
            if (_isAdmin) {
                badgeEl.innerHTML = '<span class="user-badge admin"><i class="fa-solid fa-crown"></i> ' + esc(_myName || 'Admin') + ' <button class="logout-btn" onclick="doLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button></span>';
            } else {
                badgeEl.innerHTML = '<span class="user-badge"><i class="fa-solid fa-user"></i> ' + esc(_myName || 'User') + ' <button class="logout-btn" onclick="doLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button></span>';
            }
            badgeEl.style.display = 'block';
        }

        // Tenant selector: only for admins
        if (selector) {
            selector.style.display = _isAdmin ? 'block' : 'none';
        }
    } else {
        // No auth – show tenant selector, hide badge
        if (selector) selector.style.display = 'block';
        if (badgeEl) badgeEl.style.display = 'none';
    }
}

async function doLogin() {
    const input = document.getElementById('login-token');
    const errorEl = document.getElementById('login-error');
    const token = input.value.trim();

    if (!token) {
        errorEl.textContent = 'Please enter a token';
        errorEl.style.display = 'block';
        return;
    }

    const ok = await validateToken(token);
    if (!ok) {
        errorEl.textContent = 'Invalid or revoked token';
        errorEl.style.display = 'block';
        return;
    }

    _authToken = token;
    sessionStorage.setItem('llmproxy_token', token);
    showApp();
}

function doLogout() {
    _authToken = '';
    _isAdmin = false;
    _myTenantId = null;
    sessionStorage.removeItem('llmproxy_token');
    showLogin();
}

// Allow Enter key to submit login
document.getElementById('login-token')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
});

// ─── Tenant selector ──────────────────────────────────────────────────────

function getSelectedTenant() {
    // Non-admin users are always scoped server-side, no override
    if (_authRequired && !_isAdmin) return '';
    return document.getElementById('tenant-select')?.value || '';
}

function _appendTenant(path) {
    const tid = getSelectedTenant();
    if (!tid) return path;
    const sep = path.includes('?') ? '&' : '?';
    return path + sep + 'tenant_id=' + encodeURIComponent(tid);
}

async function loadTenants() {
    if (_authRequired && !_isAdmin) return; // non-admins don't see tenant picker
    try {
        const res = await fetch(API + _appendTenant('/api/tenants'), { headers: _authHeaders() });
        const tenants = await res.json();
        const select = document.getElementById('tenant-select');
        if (!select) return;
        const current = select.value;
        select.innerHTML = '<option value="">All tenants</option>';
        (tenants || []).forEach(t => {
            const opt = document.createElement('option');
            opt.value = t.tenant_id;
            opt.textContent = t.name || t.tenant_id;
            select.appendChild(opt);
        });
        if (current) select.value = current;
    } catch (_) { /* tenants not available */ }
}

document.getElementById('tenant-select')?.addEventListener('change', () => {
    const activePage = document.querySelector('.nav-item.active')?.dataset.page;
    if (activePage) navigateTo(activePage);
});

// ─── Helpers ───────────────────────────────────────────────────────────────

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
    const d = new Date(ts);
    return d.toLocaleTimeString();
}

function formatDateTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

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

// ─── Chart helpers ─────────────────────────────────────────────────────────

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

// ─── Navigation ────────────────────────────────────────────────────────────

const navItems = document.querySelectorAll('.nav-item[data-page]');
const pageSections = document.querySelectorAll('.page-section');

function navigateTo(page) {
    _activePage = page;
    navItems.forEach(n => n.classList.toggle('active', n.dataset.page === page));
    pageSections.forEach(p => p.classList.toggle('active', p.id === 'page-' + page));

    // Close side panels when leaving their pages
    if (page !== 'requests') closeSidePanel();
    if (page !== 'live') closeLiveSidePanel();

    // Stop live feed when leaving that page
    if (page !== 'live') stopLive();

    // Load data for the page
    const loaders = {
        'overview': loadOverview,
        'live': startLive,
        'requests': loadRequests,
        'domains': loadDomains,
        'errors': loadErrors,
        'websocket': loadWebSocket,
        'performance': loadPerformance,
        'security': loadSecurity,
        'privacy': loadPrivacy,
        'api-map': loadApiMap,
        'blocked': loadBlocked,
        'rules': loadRules,
        'tokens': loadTokens,
        'export': loadExport,
        'clear-data': loadClearData,
    };
    if (loaders[page]) loaders[page]();
}

navItems.forEach(item => {
    item.addEventListener('click', () => navigateTo(item.dataset.page));
});

// ─── Tab system ────────────────────────────────────────────────────────────

document.querySelectorAll('.tabs').forEach(tabBar => {
    tabBar.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            tabBar.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            // Trigger content update
            const section = tabBar.id.replace('-tabs', '');
            if (section === 'perf') renderPerfTab(tab.dataset.tab);
            if (section === 'security') renderSecurityTab(tab.dataset.tab);
            if (section === 'privacy') renderPrivacyTab(tab.dataset.tab);
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Overview
// ═══════════════════════════════════════════════════════════════════════════

async function loadOverview() {
    try {
        const [stats, summary, domains, requests] = await Promise.all([
            api('/api/stats'),
            api('/api/summary?hours=' + (document.getElementById('summary-hours')?.value || 24)),
            api('/api/domains?limit=10'),
            api('/api/requests?limit=10'),
        ]);

        // Stat cards
        document.getElementById('stats-grid').innerHTML = [
            statCard('Total Requests', stats.total_requests || 0),
            statCard('Unique Hosts', stats.unique_hosts || 0),
            statCard('Avg Latency', formatDuration(stats.avg_duration_ms)),
            statCard('Total Data', formatBytes(stats.total_bytes || 0)),
            statCard('Errors', stats.errors || 0, stats.errors > 0 ? 'negative' : ''),
            statCard('Success', stats.success || 0, 'positive'),
        ].join('');

        // Timeline chart
        if (summary.hourly_breakdown && summary.hourly_breakdown.length > 0) {
            makeChart('chart-timeline', {
                type: 'bar',
                data: {
                    labels: summary.hourly_breakdown.map(h => h.hour?.substring(11, 16) || ''),
                    datasets: [{
                        label: 'Requests',
                        data: summary.hourly_breakdown.map(h => h.requests || 0),
                        backgroundColor: 'rgba(88,166,255,0.4)',
                        borderColor: '#58a6ff',
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: { scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } }
            });
        }

        // Hosts chart
        if (domains.length > 0) {
            makeChart('chart-hosts', {
                type: 'doughnut',
                data: {
                    labels: domains.map(d => d.host),
                    datasets: [{
                        data: domains.map(d => d.total_requests),
                        backgroundColor: chartColors,
                        borderWidth: 0,
                    }]
                },
                options: {
                    cutout: '60%',
                    plugins: { legend: { position: 'right', labels: { boxWidth: 12, padding: 8 } } },
                }
            });
        }

        // Recent table
        document.getElementById('overview-recent-table').innerHTML = requestsTable(requests);

    } catch (e) {
        console.error('Overview load error:', e);
    }
}

function statCard(label, value, changeClass) {
    return `<div class="stat-card">
        <div class="stat-label">${esc(label)}</div>
        <div class="stat-value${changeClass ? ' stat-change ' + changeClass : ''}">${esc(String(value))}</div>
    </div>`;
}

document.getElementById('summary-hours')?.addEventListener('change', loadOverview);

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Live Feed (SSE with polling fallback)
// ═══════════════════════════════════════════════════════════════════════════

let _liveEventSource = null;
let _liveDomainFilter = '';
let _liveSearch = '';

function startLive() {
    livePaused = false;
    document.getElementById('live-toggle').innerHTML = '<i class="fa-solid fa-pause"></i> Pause';
    document.getElementById('live-feed-list').innerHTML = '';

    // Load domains for the filter dropdown
    _loadLiveDomains();

    // Clean up any existing connections
    stopLive();

    // Try SSE first, fall back to polling
    _startSSE();
}

async function _loadLiveDomains() {
    try {
        const data = await api('/api/domains?limit=100');
        const sel = document.getElementById('live-domain-filter');
        const current = sel.value;
        sel.innerHTML = '<option value="">All Domains</option>';
        (data || []).forEach(d => {
            sel.innerHTML += `<option value="${esc(d.host)}">${esc(d.host)}</option>`;
        });
        sel.value = current || '';
    } catch(e) {}
}

async function _loadReqDomains() {
    try {
        const data = await api('/api/domains?limit=100');
        const sel = document.getElementById('req-domain');
        if (!sel) return;
        const current = sel.value;
        sel.innerHTML = '<option value="">All Domains</option>';
        (data || []).forEach(d => {
            sel.innerHTML += `<option value="${esc(d.host)}">${esc(d.host)}</option>`;
        });
        sel.value = current || '';
    } catch(e) {}
}

document.getElementById('live-domain-filter')?.addEventListener('change', () => {
    _liveDomainFilter = document.getElementById('live-domain-filter').value;
    // Restart the stream with the new filter
    document.getElementById('live-feed-list').innerHTML = '';
    stopLive();
    _startSSE();
});

let _liveSearchDebounce = null;
document.getElementById('live-search')?.addEventListener('input', () => {
    clearTimeout(_liveSearchDebounce);
    _liveSearchDebounce = setTimeout(() => {
        _liveSearch = document.getElementById('live-search').value.trim();
        document.getElementById('live-feed-list').innerHTML = '';
        stopLive();
        _startSSE();
    }, 400);
});

function _startSSE() {
    try {
        let url = '/api/live/stream';
        const params = [];
        if (_authToken) params.push('token=' + encodeURIComponent(_authToken));
        if (_liveDomainFilter) params.push('host=' + encodeURIComponent(_liveDomainFilter));
        if (_liveSearch) params.push('search=' + encodeURIComponent(_liveSearch));
        if (params.length) url += '?' + params.join('&');

        _liveEventSource = new EventSource(url);

        _liveEventSource.onmessage = (event) => {
            if (livePaused) return;
            try {
                const data = JSON.parse(event.data);
                _renderLiveItems(data.http || [], data.ws || []);
            } catch (e) {
                console.error('SSE parse error:', e);
            }
        };

        _liveEventSource.onerror = () => {
            // SSE failed, fall back to polling
            console.warn('SSE connection lost, falling back to polling');
            _liveEventSource.close();
            _liveEventSource = null;
            _startPolling();
        };

    } catch (e) {
        _startPolling();
    }
}

function _startPolling() {
    liveCursorHttp = null;
    liveCursorWs = null;
    if (liveInterval) clearInterval(liveInterval);
    pollLive();
    liveInterval = setInterval(pollLive, 2000);
}

function stopLive() {
    if (_liveEventSource) {
        _liveEventSource.close();
        _liveEventSource = null;
    }
    if (liveInterval) { clearInterval(liveInterval); liveInterval = null; }
}

document.getElementById('live-toggle')?.addEventListener('click', () => {
    livePaused = !livePaused;
    document.getElementById('live-toggle').innerHTML = livePaused ? '<i class="fa-solid fa-play"></i> Resume' : '<i class="fa-solid fa-pause"></i> Pause';
});

function _renderLiveItems(httpReqs, wsMsgs) {
    const list = document.getElementById('live-feed-list');
    const items = [];

    httpReqs.forEach(r => {
        items.push(`<div class="live-feed-item clickable" data-id="${esc(r.id)}" onclick="showRequestDetail('${esc(r.id)}')">
            <span class="time">${formatTime(r.timestamp)}</span>
            ${methodBadge(r.method)}
            ${statusBadge(r.status_code)}
            <span class="url">${esc(r.url)}</span>
            <span class="duration">${formatDuration(r.duration_ms)}</span>
        </div>`);
    });

    wsMsgs.forEach(m => {
        items.push(`<div class="live-feed-item">
            <span class="time">${formatTime(m.timestamp)}</span>
            <span class="badge badge-method">${esc(m.direction)}</span>
            <span class="url">WS: ${esc(m.host)} ${esc(m.content?.substring(0, 120) || '')}</span>
        </div>`);
    });

    if (items.length > 0) {
        list.insertAdjacentHTML('afterbegin', items.join(''));
        while (list.children.length > 500) list.removeChild(list.lastChild);
    }

    document.getElementById('live-count').textContent = `${list.children.length} items captured`;
}

async function pollLive() {
    if (livePaused) return;
    try {
        let url = '/api/live?limit=50';
        if (liveCursorHttp) url += '&after_id=' + encodeURIComponent(liveCursorHttp);
        if (liveCursorWs) url += '&after_ws_id=' + encodeURIComponent(liveCursorWs);
        if (_liveDomainFilter) url += '&host=' + encodeURIComponent(_liveDomainFilter);
        if (_liveSearch) url += '&search=' + encodeURIComponent(_liveSearch);
        const data = await api(url);

        if (data.http?.cursor) liveCursorHttp = data.http.cursor;
        if (data.ws?.cursor) liveCursorWs = data.ws.cursor;

        _renderLiveItems(data.http?.requests || [], data.ws?.messages || []);

    } catch (e) {
        console.error('Live poll error:', e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Requests
// ═══════════════════════════════════════════════════════════════════════════

async function loadRequests() {
    // Load domains for the filter dropdown
    _loadReqDomains();
    try {
        const search = document.getElementById('req-search')?.value || '';
        const method = document.getElementById('req-method')?.value || '';
        const domain = document.getElementById('req-domain')?.value || '';
        const limit = document.getElementById('req-limit')?.value || '50';

        let url = `/api/requests?limit=${limit}`;
        if (method) url += `&method=${method}`;
        if (domain) url += `&host=${encodeURIComponent(domain)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const data = await api(url);
        document.getElementById('requests-table').innerHTML = requestsTable(data);
    } catch (e) {
        document.getElementById('requests-table').innerHTML = `<div class="empty-state"><p>Error loading requests</p></div>`;
    }
}

document.getElementById('req-search')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') loadRequests();
});

function requestsTable(rows) {
    if (!rows || rows.length === 0) {
        return `<div class="empty-state"><div class="icon"><i class="fa-solid fa-inbox"></i></div><p>No requests captured yet</p></div>`;
    }
    return `<table>
        <thead><tr>
            <th>Time</th><th>Method</th><th>Status</th><th>Host</th><th>Path</th><th>Duration</th><th>Size</th>
        </tr></thead>
        <tbody>${rows.map(r => `<tr class="clickable" data-id="${esc(r.id)}" onclick="showRequestDetail('${esc(r.id)}')">
            <td>${formatTime(r.timestamp)}</td>
            <td>${methodBadge(r.method)}</td>
            <td>${statusBadge(r.status_code)}</td>
            <td>${esc(r.host)}</td>
            <td title="${esc(r.path)}">${esc(r.path?.substring(0, 60))}</td>
            <td>${formatDuration(r.duration_ms)}</td>
            <td>${formatBytes(r.content_length)}</td>
        </tr>`).join('')}</tbody>
    </table>`;
}

// ─── Request Detail Modal & Side Panel ─────────────────────────────────────

let _activePage = 'overview';
let _viewMode = localStorage.getItem('llmproxy_view_mode') || 'panel'; // 'panel' or 'modal'

function toggleViewMode() {
    _viewMode = _viewMode === 'panel' ? 'modal' : 'panel';
    localStorage.setItem('llmproxy_view_mode', _viewMode);
    _updateViewToggleButtons();
    // Close any open panels when switching to modal mode
    if (_viewMode === 'modal') {
        closeSidePanel();
        closeLiveSidePanel();
    }
}

function _updateViewToggleButtons() {
    const icon = _viewMode === 'panel' ? 'fa-table-columns' : 'fa-expand';
    const tip = _viewMode === 'panel' ? 'Using side panel (click for modal)' : 'Using modal (click for side panel)';
    document.querySelectorAll('.view-toggle').forEach(btn => {
        btn.innerHTML = `<i class="fa-solid ${icon}"></i>`;
        btn.title = tip;
        btn.classList.toggle('active', _viewMode === 'panel');
    });
}

// Initialize toggle buttons on load
document.addEventListener('DOMContentLoaded', _updateViewToggleButtons);

function _renderDetailContent(r, curlCmd) {
    return `
        <div class="detail-row"><div class="detail-label">URL</div><div class="detail-value">${esc(r.url)}</div></div>
        <div class="detail-row"><div class="detail-label">Method</div><div class="detail-value">${methodBadge(r.method)}</div></div>
        <div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">${statusBadge(r.status_code)}</div></div>
        <div class="detail-row"><div class="detail-label">Host</div><div class="detail-value">${esc(r.host)}</div></div>
        <div class="detail-row"><div class="detail-label">Path</div><div class="detail-value">${esc(r.path)}</div></div>
        <div class="detail-row"><div class="detail-label">Scheme</div><div class="detail-value">${esc(r.scheme)}</div></div>
        <div class="detail-row"><div class="detail-label">Duration</div><div class="detail-value">${formatDuration(r.duration_ms)}</div></div>
        <div class="detail-row"><div class="detail-label">Content Type</div><div class="detail-value">${esc(r.content_type)}</div></div>
        <div class="detail-row"><div class="detail-label">Content Length</div><div class="detail-value">${formatBytes(r.content_length)}</div></div>
        <div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-value">${formatDateTime(r.timestamp)}</div></div>
        ${r.tenant_id ? `<div class="detail-row"><div class="detail-label">Tenant</div><div class="detail-value">${esc(r.tenant_id)}</div></div>` : ''}

        <h3 style="margin-top:20px;font-size:14px;color:var(--text-secondary);">Request Headers</h3>
        <pre class="body-preview">${esc(typeof r.request_headers === 'object' ? JSON.stringify(r.request_headers, null, 2) : r.request_headers)}</pre>

        ${r.request_body ? `<h3 style="margin-top:16px;font-size:14px;color:var(--text-secondary);">Request Body</h3>
        <pre class="body-preview">${esc(tryPrettyJson(r.request_body))}</pre>` : ''}

        <h3 style="margin-top:16px;font-size:14px;color:var(--text-secondary);">Response Headers</h3>
        <pre class="body-preview">${esc(typeof r.response_headers === 'object' ? JSON.stringify(r.response_headers, null, 2) : r.response_headers)}</pre>

        ${r.response_body ? `<h3 style="margin-top:16px;font-size:14px;color:var(--text-secondary);">Response Body</h3>
        <pre class="body-preview">${esc(tryPrettyJson(r.response_body))}</pre>` : ''}

        ${curlCmd ? `<h3 style="margin-top:16px;font-size:14px;color:var(--text-secondary);">cURL Command</h3>
        <pre class="body-preview" style="user-select:all;">${esc(curlCmd)}</pre>` : ''}
    `;
}

async function _fetchDetailData(id) {
    const r = await api(`/api/requests/${id}`);
    let curlCmd = '';
    try {
        const c = await api(`/api/curl/${id}`);
        curlCmd = c.curl || '';
    } catch(_) {}
    return { r, curlCmd };
}

async function showRequestDetail(id) {
    if (_viewMode === 'panel' && _activePage === 'requests') {
        showInSidePanel(id);
    } else if (_viewMode === 'panel' && _activePage === 'live') {
        showInLiveSidePanel(id);
    } else {
        showInModal(id);
    }
}

async function showInModal(id) {
    const modal = document.getElementById('request-modal');
    const body = document.getElementById('request-modal-body');
    body.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';
    modal.classList.add('open');
    try {
        const { r, curlCmd } = await _fetchDetailData(id);
        body.innerHTML = _renderDetailContent(r, curlCmd);
    } catch (e) {
        body.innerHTML = `<div class="empty-state"><p>Error loading request detail</p></div>`;
    }
}

async function showInSidePanel(id) {
    const splitView = document.querySelector('#page-requests .split-view');
    const panelBody = document.getElementById('side-panel-body');
    if (!splitView || !panelBody) { showInModal(id); return; }

    splitView.classList.add('panel-open');
    panelBody.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

    // Highlight selected row
    splitView.querySelectorAll('tr.selected').forEach(tr => tr.classList.remove('selected'));
    const clickedRow = splitView.querySelector(`tr[data-id="${id}"]`);
    if (clickedRow) clickedRow.classList.add('selected');

    try {
        const { r, curlCmd } = await _fetchDetailData(id);
        panelBody.innerHTML = _renderDetailContent(r, curlCmd);
    } catch (e) {
        panelBody.innerHTML = `<div class="empty-state"><p>Error loading request detail</p></div>`;
    }
}

function closeSidePanel() {
    const splitView = document.querySelector('#page-requests .split-view');
    if (splitView) splitView.classList.remove('panel-open');
    const panelBody = document.getElementById('side-panel-body');
    if (panelBody) panelBody.innerHTML = '<div class="empty-state"><div class="icon"><i class="fa-solid fa-arrow-pointer"></i></div><p>Click a request to view details</p></div>';
    document.querySelectorAll('#page-requests tr.selected').forEach(tr => tr.classList.remove('selected'));
}

async function showInLiveSidePanel(id) {
    const splitView = document.getElementById('live-split-view');
    const panelBody = document.getElementById('live-side-panel-body');
    if (!splitView || !panelBody) { showInModal(id); return; }

    splitView.classList.add('panel-open');
    panelBody.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

    // Highlight selected live feed item
    splitView.querySelectorAll('.live-feed-item.selected').forEach(el => el.classList.remove('selected'));
    const clickedItem = splitView.querySelector(`.live-feed-item[data-id="${id}"]`);
    if (clickedItem) clickedItem.classList.add('selected');

    try {
        const { r, curlCmd } = await _fetchDetailData(id);
        panelBody.innerHTML = _renderDetailContent(r, curlCmd);
    } catch (e) {
        panelBody.innerHTML = `<div class="empty-state"><p>Error loading request detail</p></div>`;
    }
}

function closeLiveSidePanel() {
    const splitView = document.getElementById('live-split-view');
    if (splitView) splitView.classList.remove('panel-open');
    const panelBody = document.getElementById('live-side-panel-body');
    if (panelBody) panelBody.innerHTML = '<div class="empty-state"><div class="icon"><i class="fa-solid fa-arrow-pointer"></i></div><p>Click a request to view details</p></div>';
    document.querySelectorAll('#page-live .live-feed-item.selected').forEach(el => el.classList.remove('selected'));
}

function tryPrettyJson(s) {
    if (!s) return '';
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch(_) { return s; }
}

function closeModal() {
    document.getElementById('request-modal').classList.remove('open');
}

document.getElementById('request-modal')?.addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) closeModal();
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
});

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Domains
// ═══════════════════════════════════════════════════════════════════════════

async function loadDomains() {
    try {
        const data = await api('/api/domains?limit=20');
        if (!data || data.length === 0) {
            document.getElementById('domains-table').innerHTML = `<div class="empty-state"><div class="icon"><i class="fa-solid fa-server"></i></div><p>No domains captured yet</p></div>`;
            return;
        }

        const top10 = data.slice(0, 10);

        makeChart('chart-domains', {
            type: 'bar',
            data: {
                labels: top10.map(d => d.host),
                datasets: [{
                    data: top10.map(d => d.total_requests),
                    backgroundColor: chartColors,
                    borderWidth: 0,
                    borderRadius: 3,
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true } },
            }
        });

        makeChart('chart-domain-latency', {
            type: 'bar',
            data: {
                labels: top10.map(d => d.host),
                datasets: [{
                    data: top10.map(d => d.avg_duration_ms || 0),
                    backgroundColor: 'rgba(210,153,34,0.4)',
                    borderColor: '#d29922',
                    borderWidth: 1,
                    borderRadius: 3,
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true } },
            }
        });

        document.getElementById('domains-table').innerHTML = `<table>
            <thead><tr><th>Host</th><th>Requests</th><th>Methods</th><th>Avg Latency</th><th>Total Data</th><th>First Seen</th><th>Last Seen</th></tr></thead>
            <tbody>${data.map(d => `<tr>
                <td><strong>${esc(d.host)}</strong></td>
                <td>${d.total_requests}</td>
                <td>${(Array.isArray(d.methods) ? d.methods : (d.methods || '').split(',')).filter(Boolean).map(m => methodBadge(m)).join(' ')}</td>
                <td>${formatDuration(d.avg_duration_ms)}</td>
                <td>${formatBytes(d.total_bytes)}</td>
                <td>${formatDateTime(d.first_seen)}</td>
                <td>${formatDateTime(d.last_seen)}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (e) {
        console.error('Domains error:', e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Errors
// ═══════════════════════════════════════════════════════════════════════════

async function loadErrors() {
    try {
        const data = await api('/api/errors?limit=100');
        document.getElementById('errors-table').innerHTML = requestsTable(data);
    } catch (e) {
        document.getElementById('errors-table').innerHTML = `<div class="empty-state"><p>Error loading data</p></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: WebSocket
// ═══════════════════════════════════════════════════════════════════════════

async function loadWebSocket() {
    try {
        const [stats, conns] = await Promise.all([
            api('/api/websocket/stats'),
            api('/api/websocket/connections?limit=50'),
        ]);

        document.getElementById('ws-stats-grid').innerHTML = [
            statCard('Total Messages', stats.total_messages || 0),
            statCard('Connections', stats.total_connections || 0),
            statCard('Unique Hosts', stats.unique_hosts || 0),
            statCard('Total Data', formatBytes(stats.total_bytes || 0)),
            statCard('Sent', stats.sent || 0),
            statCard('Received', stats.received || 0),
        ].join('');

        if (!conns || conns.length === 0) {
            document.getElementById('ws-connections-table').innerHTML = `<div class="empty-state"><div class="icon"><i class="fa-solid fa-plug"></i></div><p>No WebSocket connections captured</p></div>`;
            return;
        }

        document.getElementById('ws-connections-table').innerHTML = `<table>
            <thead><tr><th>Host</th><th>URL</th><th>Messages</th><th>Sent</th><th>Received</th><th>Data</th><th>First</th><th>Last</th></tr></thead>
            <tbody>${conns.map(c => `<tr>
                <td>${esc(c.host)}</td>
                <td title="${esc(c.url)}">${esc(c.url?.substring(0, 60))}</td>
                <td>${c.total_messages}</td>
                <td>${c.sent}</td>
                <td>${c.received}</td>
                <td>${formatBytes(c.total_bytes)}</td>
                <td>${formatDateTime(c.first_message)}</td>
                <td>${formatDateTime(c.last_message)}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (e) {
        console.error('WebSocket error:', e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Performance
// ═══════════════════════════════════════════════════════════════════════════

let perfData = null;
let bandwidthData = null;
let anomalyData = null;

async function loadPerformance() {
    try {
        [perfData, bandwidthData, anomalyData] = await Promise.all([
            api('/api/performance'),
            api('/api/bandwidth'),
            api('/api/anomalies'),
        ]);
        renderPerfTab('perf-slow');
    } catch (e) {
        document.getElementById('perf-content').innerHTML = `<div class="empty-state"><p>Error loading performance data</p></div>`;
    }
}

function renderPerfTab(tab) {
    const el = document.getElementById('perf-content');
    if (tab === 'perf-slow') {
        const items = perfData?.slow_endpoints || [];
        el.innerHTML = items.length === 0 ? emptyState('No slow endpoints detected') : `<div class="card"><table>
            <thead><tr><th>Host</th><th>Path</th><th>Method</th><th>Hits</th><th>Avg (ms)</th><th>Max (ms)</th><th>P95 (ms)</th></tr></thead>
            <tbody>${items.map(i => `<tr>
                <td>${esc(i.host)}</td><td>${esc(i.path)}</td><td>${methodBadge(i.method)}</td>
                <td>${i.hits}</td><td>${Math.round(i.avg_ms || 0)}</td><td>${Math.round(i.max_ms || 0)}</td><td>${Math.round(i.p95_ms || 0)}</td>
            </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'perf-large') {
        const items = perfData?.large_payloads || [];
        el.innerHTML = items.length === 0 ? emptyState('No large payloads') : `<div class="card"><table>
            <thead><tr><th>URL</th><th>Size</th><th>Content Type</th><th>Status</th></tr></thead>
            <tbody>${items.map(i => `<tr>
                <td title="${esc(i.url)}">${esc(i.url?.substring(0, 80))}</td>
                <td>${formatBytes(i.content_length)}</td><td>${esc(i.content_type)}</td><td>${statusBadge(i.status_code)}</td>
            </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'perf-redundant') {
        const items = perfData?.redundant_requests || [];
        el.innerHTML = items.length === 0 ? emptyState('No redundant requests') : `<div class="card"><table>
            <thead><tr><th>URL</th><th>Method</th><th>Hits</th></tr></thead>
            <tbody>${items.map(i => `<tr>
                <td title="${esc(i.url)}">${esc(i.url?.substring(0, 100))}</td>
                <td>${methodBadge(i.method)}</td><td>${i.hits}</td>
            </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'perf-bandwidth') {
        if (!bandwidthData) { el.innerHTML = emptyState('No data'); return; }
        const hosts = bandwidthData.by_host || [];
        el.innerHTML = `
            <div class="stats-grid">
                ${statCard('Total Bandwidth', formatBytes(bandwidthData.total_bytes || 0))}
            </div>
            <div class="card"><div class="card-header"><span class="card-title">Bandwidth by Host</span></div><table>
            <thead><tr><th>Host</th><th>Total</th><th>Requests</th><th>Avg/Request</th></tr></thead>
            <tbody>${hosts.map(h => `<tr>
                <td>${esc(h.host)}</td><td>${formatBytes(h.total_bytes)}</td>
                <td>${h.requests}</td><td>${formatBytes(h.avg_bytes)}</td>
            </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'perf-anomalies') {
        if (!anomalyData) { el.innerHTML = emptyState('No data'); return; }
        let html = '';
        const outliers = anomalyData.timing_outliers?.outliers || [];
        if (outliers.length > 0) {
            html += `<div class="card"><div class="card-header"><span class="card-title">Timing Outliers</span>
                <span class="card-subtitle">Threshold: ${formatDuration(anomalyData.timing_outliers?.threshold_ms)}</span></div><table>
                <thead><tr><th>URL</th><th>Duration</th><th>Status</th></tr></thead>
                <tbody>${outliers.map(o => `<tr>
                    <td title="${esc(o.url)}">${esc(o.url?.substring(0, 80))}</td>
                    <td>${formatDuration(o.duration_ms)}</td><td>${statusBadge(o.status_code)}</td>
                </tr>`).join('')}</tbody></table></div>`;
        }
        const rare = anomalyData.rare_hosts || [];
        if (rare.length > 0) {
            html += `<div class="card"><div class="card-header"><span class="card-title">Rare Hosts</span></div><table>
                <thead><tr><th>Host</th><th>Hits</th></tr></thead>
                <tbody>${rare.map(r => `<tr><td>${esc(r.host)}</td><td>${r.hits}</td></tr>`).join('')}</tbody></table></div>`;
        }
        const bursts = anomalyData.error_bursts || [];
        if (bursts.length > 0) {
            html += `<div class="card"><div class="card-header"><span class="card-title">Error Bursts</span></div><table>
                <thead><tr><th>Minute</th><th>Errors</th></tr></thead>
                <tbody>${bursts.map(b => `<tr><td>${esc(b.minute)}</td><td>${b.errors}</td></tr>`).join('')}</tbody></table></div>`;
        }
        el.innerHTML = html || emptyState('No anomalies detected');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Security
// ═══════════════════════════════════════════════════════════════════════════

let vulnData = null, piiData = null, sessionData = null, sessionIssueData = null, c2Data = null;

async function loadSecurity() {
    try {
        [vulnData, piiData, sessionData, sessionIssueData, c2Data] = await Promise.all([
            api('/api/security/vulnerabilities'),
            api('/api/security/pii'),
            api('/api/security/sessions'),
            api('/api/security/session-issues'),
            api('/api/security/c2'),
        ]);
        renderSecurityTab('sec-vulns');
    } catch (e) {
        document.getElementById('security-content').innerHTML = `<div class="empty-state"><p>Error loading security data</p></div>`;
    }
}

function renderSecurityTab(tab) {
    const el = document.getElementById('security-content');
    if (tab === 'sec-vulns') {
        if (!vulnData || !vulnData.findings?.length) { el.innerHTML = emptyState('No vulnerabilities found'); return; }
        el.innerHTML = `
            <div class="stats-grid">
                ${statCard('Total Scanned', vulnData.total_scanned)}
                ${statCard('Findings', vulnData.findings_count, vulnData.findings_count > 0 ? 'negative' : '')}
                ${statCard('Critical', vulnData.by_severity?.critical || 0, (vulnData.by_severity?.critical || 0) > 0 ? 'negative' : '')}
                ${statCard('High', vulnData.by_severity?.high || 0)}
                ${statCard('Medium', vulnData.by_severity?.medium || 0)}
                ${statCard('Low', vulnData.by_severity?.low || 0)}
            </div>
            <div class="card">${vulnData.findings.map(f => `<div class="finding-item">
                <div class="finding-header">${severityBadge(f.severity)} <span class="finding-type">${esc(f.type)}</span></div>
                <div class="finding-detail">${esc(f.detail)}</div>
                <div class="finding-url">${esc(f.url)}</div>
            </div>`).join('')}</div>`;
    } else if (tab === 'sec-pii') {
        if (!piiData || !piiData.findings?.length) { el.innerHTML = emptyState('No PII detected'); return; }
        el.innerHTML = `
            <div class="stats-grid">
                ${statCard('Scanned', piiData.total_scanned)}
                ${statCard('Findings', piiData.findings_count, piiData.findings_count > 0 ? 'negative' : '')}
            </div>
            <div class="card"><table>
                <thead><tr><th>Type</th><th>Location</th><th>URL</th><th>Count</th><th>Samples</th></tr></thead>
                <tbody>${piiData.findings.map(f => `<tr>
                    <td><strong>${esc(f.type)}</strong></td><td>${esc(f.location)}</td>
                    <td title="${esc(f.url)}">${esc(f.url?.substring(0, 60))}</td>
                    <td>${f.count}</td><td style="font-size:11px">${esc((f.samples || []).join(', ').substring(0, 80))}</td>
                </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'sec-sessions') {
        if (!sessionData || !sessionData.tokens?.length) { el.innerHTML = emptyState('No session tokens found'); return; }
        el.innerHTML = `
            <div class="stats-grid">
                ${statCard('Scanned', sessionData.total_scanned)}
                ${statCard('Tokens Found', sessionData.tokens_found)}
            </div>
            <div class="card"><table>
                <thead><tr><th>Type</th><th>Header/Name</th><th>Host</th><th>Value</th></tr></thead>
                <tbody>${sessionData.tokens.map(t => `<tr>
                    <td><span class="badge badge-method">${esc(t.type)}</span></td>
                    <td>${esc(t.header || t.name)}</td>
                    <td>${esc(t.host)}</td>
                    <td style="font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis">${esc(t.value?.substring(0, 60))}</td>
                </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'sec-issues') {
        if (!sessionIssueData || !sessionIssueData.issues?.length) { el.innerHTML = emptyState('No session issues detected'); return; }
        el.innerHTML = `<div class="card">${sessionIssueData.issues.map(i => `<div class="finding-item">
            <div class="finding-header"><span class="finding-type">${esc(i.type)}</span></div>
            <div class="finding-detail">${esc(i.detail || JSON.stringify(i))}</div>
        </div>`).join('')}</div>`;
    } else if (tab === 'sec-c2') {
        if (!c2Data || !c2Data.findings?.length) { el.innerHTML = emptyState('No C2 patterns detected'); return; }
        el.innerHTML = `<div class="card">${c2Data.findings.map(f => `<div class="finding-item">
            <div class="finding-header"><span class="finding-type">${esc(f.type)}</span></div>
            <div class="finding-detail">${esc(f.detail || JSON.stringify(f))}</div>
        </div>`).join('')}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Privacy
// ═══════════════════════════════════════════════════════════════════════════

let thirdPartyData = null, cookieData = null;

async function loadPrivacy() {
    try {
        [thirdPartyData, cookieData] = await Promise.all([
            api('/api/privacy/third-parties'),
            api('/api/privacy/cookies'),
        ]);
        renderPrivacyTab('priv-third');
    } catch (e) {
        document.getElementById('privacy-content').innerHTML = `<div class="empty-state"><p>Error loading privacy data</p></div>`;
    }
}

function renderPrivacyTab(tab) {
    const el = document.getElementById('privacy-content');
    if (tab === 'priv-third') {
        const domains = thirdPartyData?.domains || [];
        if (domains.length === 0) { el.innerHTML = emptyState('No third-party domains'); return; }
        el.innerHTML = `
            <div class="stats-grid">${statCard('Third-Party Domains', thirdPartyData.total_domains || 0)}</div>
            <div class="card"><table>
            <thead><tr><th>Host</th><th>Category</th><th>Requests</th><th>Data</th><th>Methods</th><th>Errors</th></tr></thead>
            <tbody>${domains.map(d => `<tr>
                <td><strong>${esc(d.host)}</strong></td>
                <td><span class="badge badge-method">${esc(d.category)}</span></td>
                <td>${d.total_requests}</td><td>${formatBytes(d.total_bytes)}</td>
                <td>${(Array.isArray(d.methods) ? d.methods : (d.methods || '').split(',')).filter(Boolean).map(m => methodBadge(m)).join(' ')}</td>
                <td>${d.errors || 0}</td>
            </tr>`).join('')}</tbody></table></div>`;
    } else if (tab === 'priv-cookies') {
        const cookies = cookieData?.cookies || [];
        if (cookies.length === 0) { el.innerHTML = emptyState('No cookies detected'); return; }
        el.innerHTML = `
            <div class="stats-grid">${statCard('Total Cookies', cookieData.total_cookies || 0)}</div>
            <div class="card"><table>
            <thead><tr><th>Name</th><th>Host</th><th>Category</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Seen</th></tr></thead>
            <tbody>${cookies.map(c => `<tr>
                <td><strong>${esc(c.name)}</strong></td><td>${esc(c.host)}</td>
                <td><span class="badge badge-method">${esc(c.category)}</span></td>
                <td>${c.secure ? '<i class="fa-solid fa-circle-check" style="color:var(--green)"></i>' : '<i class="fa-solid fa-circle-xmark" style="color:var(--red)"></i>'}</td>
                <td>${c.httponly ? '<i class="fa-solid fa-circle-check" style="color:var(--green)"></i>' : '<i class="fa-solid fa-circle-xmark" style="color:var(--red)"></i>'}</td>
                <td>${esc(c.samesite || 'None')}</td>
                <td>${c.seen_count}</td>
            </tr>`).join('')}</tbody></table></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: API Map
// ═══════════════════════════════════════════════════════════════════════════

async function populateApiMapDomains() {
    const select = document.getElementById('apimap-host');
    const current = select.value;
    try {
        const domains = await api('/api/domains?limit=100');
        // Keep the first placeholder option, remove the rest
        select.innerHTML = '<option value="">Select a domain...</option>';
        (domains || []).forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.host;
            opt.textContent = `${d.host}  (${d.total_requests} reqs)`;
            select.appendChild(opt);
        });
        // Restore previous selection if still present
        if (current) select.value = current;
    } catch (_) { /* domains not available yet */ }
}

// Auto-load endpoints when domain changes
document.getElementById('apimap-host')?.addEventListener('change', function() {
    const btn = document.getElementById('btn-openapi');
    if (this.value) {
        btn.removeAttribute('disabled');
        loadApiMap();
    } else {
        btn.setAttribute('disabled', '');
        document.getElementById('apimap-table').innerHTML = emptyState('Select a domain to view its API map');
    }
});

async function loadApiMap() {
    // Populate dropdown if first visit
    await populateApiMapDomains();

    const host = document.getElementById('apimap-host')?.value || '';
    if (!host) {
        document.getElementById('apimap-table').innerHTML = emptyState('Select a domain to view its API map');
        return;
    }

    document.getElementById('apimap-table').innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';
    try {
        const data = await api('/api/map?limit=100&host=' + encodeURIComponent(host));

        if (!data || data.length === 0) {
            document.getElementById('apimap-table').innerHTML = emptyState('No API endpoints discovered for ' + host);
            return;
        }

        document.getElementById('apimap-table').innerHTML = `<table>
            <thead><tr><th>Endpoint</th><th>Methods</th><th>Status Codes</th><th>Hits</th><th>Avg Latency</th></tr></thead>
            <tbody>${data.map(e => `<tr>
                <td>${esc(e.endpoint)}</td>
                <td>${(e.methods || []).map(m => methodBadge(m)).join(' ')}</td>
                <td>${(e.status_codes || []).map(s => statusBadge(s)).join(' ')}</td>
                <td>${e.total_hits}</td>
                <td>${formatDuration(e.avg_duration_ms)}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (e) {
        document.getElementById('apimap-table').innerHTML = `<div class="empty-state"><p>Error loading API map</p></div>`;
    }
}

async function downloadOpenApi() {
    const host = document.getElementById('apimap-host')?.value || '';
    if (!host) return alert('Select a domain first');
    try {
        const data = await api('/api/openapi?host=' + encodeURIComponent(host));
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = host.replace(/[^a-zA-Z0-9.-]/g, '_') + '-openapi.json';
        a.click();
    } catch (e) {
        alert('Error generating OpenAPI spec: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Blocked Domains
// ═══════════════════════════════════════════════════════════════════════════

async function loadBlocked() {
    try {
        const data = await api('/api/blocked');
        if (!data || data.length === 0) {
            document.getElementById('blocked-table').innerHTML = emptyState('No blocked domains');
            return;
        }
        document.getElementById('blocked-table').innerHTML = `<table>
            <thead><tr><th>Domain</th><th>Reason</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>${data.map(d => `<tr>
                <td><strong>${esc(d.domain)}</strong></td>
                <td>${esc(d.reason || '-')}</td>
                <td>${formatDateTime(d.created_at)}</td>
                <td><button class="btn btn-sm btn-danger" onclick="unblockDomain('${esc(d.domain)}')">Unblock</button></td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (e) {
        document.getElementById('blocked-table').innerHTML = `<div class="empty-state"><p>Error loading blocked domains</p></div>`;
    }
}

async function blockDomain() {
    const domain = document.getElementById('block-domain')?.value?.trim();
    const reason = document.getElementById('block-reason')?.value?.trim();
    if (!domain) return alert('Enter a domain to block');
    await apiPost('/api/blocked', { domain, reason: reason || undefined });
    document.getElementById('block-domain').value = '';
    document.getElementById('block-reason').value = '';
    loadBlocked();
}

async function unblockDomain(domain) {
    if (!confirm(`Unblock ${domain}?`)) return;
    await apiDelete(`/api/blocked/${domain}`);
    loadBlocked();
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Rules
// ═══════════════════════════════════════════════════════════════════════════

async function loadRules() {
    try {
        const data = await api('/api/rules');
        if (!data || data.length === 0) {
            document.getElementById('rules-table').innerHTML = emptyState('No traffic rules configured');
            return;
        }
        document.getElementById('rules-table').innerHTML = `<table>
            <thead><tr><th>Type</th><th>Action</th><th>Host</th><th>Path</th><th>Description</th><th>Enabled</th></tr></thead>
            <tbody>${data.map(r => `<tr>
                <td><span class="badge badge-method">${esc(r.rule_type)}</span></td>
                <td>${formatAction(r.action)}</td>
                <td>${esc(r.match_host || '*')}</td>
                <td>${esc(r.match_path || '*')}</td>
                <td>${esc(r.description || '-')}</td>
                <td>${r.enabled ? '<i class="fa-solid fa-circle-check" style="color:var(--green)"></i>' : '<i class="fa-solid fa-circle-xmark" style="color:var(--red)"></i>'}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (e) {
        document.getElementById('rules-table').innerHTML = `<div class="empty-state"><p>Error loading rules</p></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Tokens
// ═══════════════════════════════════════════════════════════════════════════

async function loadTokens() {
    const el = document.getElementById('tokens-list');
    if (!el) return;
    // Hide any previous create result
    const resEl = document.getElementById('token-create-result');
    if (resEl) resEl.style.display = 'none';
    try {
        const tokens = await api('/api/tokens');
        if (!tokens || !tokens.length) {
            el.innerHTML = '<div class="empty-state"><div class="icon"><i class="fa-solid fa-key"></i></div><p>No tokens found</p></div>';
            return;
        }
        el.innerHTML = `<table>
            <thead><tr><th>Name</th><th>Tenant ID</th><th>Token</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>${tokens.map(t => {
                const status = t.active !== false
                    ? '<span style="color:var(--green);"><i class="fa-solid fa-circle-check"></i> Active</span>'
                    : '<span style="color:var(--text-muted);"><i class="fa-solid fa-circle-xmark"></i> Revoked</span>';
                const created = t.created_at ? new Date(t.created_at).toLocaleString() : '—';
                const revokeBtn = t.active !== false
                    ? `<button class="btn btn-sm btn-danger" onclick="revokeToken('${esc(t.id)}')"><i class="fa-solid fa-ban"></i> Revoke</button>`
                    : '';
                return `<tr>
                    <td><strong>${esc(t.name || '—')}</strong></td>
                    <td><code style="font-size:11px;">${esc(t.tenant_id || '—')}</code></td>
                    <td><code style="font-size:11px;">${esc(t.token || '—')}</code></td>
                    <td>${status}</td>
                    <td>${created}</td>
                    <td>${revokeBtn}</td>
                </tr>`;
            }).join('')}</tbody>
        </table>`;
    } catch (e) {
        el.innerHTML = '<div class="empty-state"><p>Error loading tokens</p></div>';
    }
}

async function createToken() {
    const nameInput = document.getElementById('token-name');
    const name = (nameInput?.value || '').trim();
    if (!name) { alert('Please enter a name for the token'); return; }

    const resEl = document.getElementById('token-create-result');
    try {
        const result = await apiPost('/api/tokens', { name });
        if (result.error) {
            resEl.innerHTML = `<div class="card" style="border-color:var(--red);"><div style="padding:12px;">
                <strong style="color:var(--red);"><i class="fa-solid fa-circle-xmark"></i> Error:</strong> ${esc(result.error)}
            </div></div>`;
        } else {
            resEl.innerHTML = `<div class="card" style="border-color:var(--green);"><div style="padding:12px;">
                <strong style="color:var(--green);"><i class="fa-solid fa-circle-check"></i> Token Created</strong>
                <p style="margin:8px 0 4px;font-size:13px;color:var(--text-muted);">Copy this token now — it won't be shown again.</p>
                <div style="display:flex;align-items:center;gap:8px;margin-top:8px;">
                    <input type="text" id="new-token-value" value="${esc(result.token)}" readonly style="flex:1;font-family:monospace;font-size:13px;">
                    <button class="btn btn-sm" onclick="copyNewToken()"><i class="fa-solid fa-copy"></i> Copy</button>
                </div>
                <p style="margin-top:6px;font-size:12px;color:var(--text-muted);">Name: <strong>${esc(result.name)}</strong> · Tenant: <code>${esc(result.tenant_id)}</code></p>
            </div></div>`;
        }
        resEl.style.display = 'block';
        nameInput.value = '';
        // Refresh the token list
        loadTokens();
    } catch (e) {
        resEl.innerHTML = `<div class="card" style="border-color:var(--red);"><div style="padding:12px;">
            <strong style="color:var(--red);"><i class="fa-solid fa-circle-xmark"></i> Failed to create token</strong>
        </div></div>`;
        resEl.style.display = 'block';
    }
}

function copyNewToken() {
    const input = document.getElementById('new-token-value');
    if (input) {
        input.select();
        navigator.clipboard.writeText(input.value).then(() => {
            input.style.borderColor = 'var(--green)';
            setTimeout(() => { input.style.borderColor = ''; }, 1500);
        });
    }
}

async function revokeToken(docId) {
    if (!confirm('Revoke this token? This action cannot be undone.')) return;
    try {
        const result = await apiPost('/api/tokens/revoke', { id: docId });
        if (result.error) {
            alert('Error: ' + result.error);
        }
        loadTokens();
    } catch (e) {
        alert('Failed to revoke token');
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Clear Data
// ═══════════════════════════════════════════════════════════════════════════

async function loadClearData() {
    const sel = document.getElementById('clear-tenant-select');
    if (!sel) return;
    // Populate tenant dropdown
    try {
        const tenants = await api('/api/tenants');
        sel.innerHTML = '<option value="">Select a tenant...</option>' +
            tenants.map(t => `<option value="${esc(t.tenant_id)}">${esc(t.name || t.tenant_id)}</option>`).join('');
    } catch (_) {
        sel.innerHTML = '<option value="">No tenants available</option>';
    }
    document.getElementById('clear-data-result').style.display = 'none';
}

function showClearResult(data) {
    const el = document.getElementById('clear-data-result');
    if (!el) return;
    const results = data.results || {};
    const rows = Object.entries(results).map(([idx, count]) => {
        const name = idx.replace('llmproxy-', '');
        const val = typeof count === 'number' ? `${count} deleted` : count;
        return `<tr><td>${esc(name)}</td><td>${esc(String(val))}</td></tr>`;
    }).join('');
    el.innerHTML = `<div class="card" style="border-color:var(--green);">
        <div style="padding:12px;">
            <strong><i class="fa-solid fa-circle-check" style="color:var(--green)"></i> Cleared: ${esc(String(data.cleared))}</strong>
            <table style="margin-top:8px;"><thead><tr><th>Index</th><th>Result</th></tr></thead>
            <tbody>${rows}</tbody></table>
        </div>
    </div>`;
    el.style.display = 'block';
}

async function clearTenantData() {
    const sel = document.getElementById('clear-tenant-select');
    const tenantId = sel?.value;
    if (!tenantId) { alert('Please select a tenant.'); return; }
    const name = sel.options[sel.selectedIndex]?.text || tenantId;
    if (!confirm(`Clear all data for tenant "${name}"? This cannot be undone.`)) return;
    try {
        const data = await apiPost('/api/clear', { tenant_id: tenantId });
        showClearResult(data);
    } catch (e) {
        alert('Error clearing tenant data: ' + e.message);
    }
}

async function clearAllData() {
    if (!confirm('Delete ALL captured data across ALL tenants? This cannot be undone.')) return;
    if (!confirm('Are you absolutely sure? This will delete every request, WebSocket message, tag, rule, and blocked domain.')) return;
    try {
        const data = await apiPost('/api/clear', { all: true });
        showClearResult(data);
    } catch (e) {
        alert('Error clearing data: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGE: Export Data
// ═══════════════════════════════════════════════════════════════════════════

function loadExport() {
    document.getElementById('export-status').style.display = 'none';
    // Populate domain dropdown
    const sel = document.getElementById('export-domain');
    if (sel) {
        api('/api/domains?limit=100').then(domains => {
            sel.innerHTML = '<option value="">All domains</option>' +
                (domains || []).map(d => `<option value="${esc(d.host)}">${esc(d.host)} (${d.count})</option>`).join('');
        }).catch(() => {});
    }
}

function _downloadJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function _showExportStatus(msg, isError) {
    const el = document.getElementById('export-status');
    if (!el) return;
    el.innerHTML = `<div class="card" style="border-color:var(${isError ? '--red' : '--green'});">
        <div style="padding:12px;">
            <i class="fa-solid ${isError ? 'fa-circle-xmark' : 'fa-circle-check'}" style="color:var(${isError ? '--red' : '--green'})"></i> ${msg}
        </div>
    </div>`;
    el.style.display = 'block';
}

async function exportRequests() {
    const btn = document.getElementById('btn-export-req');
    const limit = parseInt(document.getElementById('export-limit').value) || 0;
    const host = document.getElementById('export-domain')?.value || '';
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Exporting...';
    _showExportStatus('Fetching data from server...', false);
    try {
        const tenant = getSelectedTenant();
        let url = `/api/export/requests?limit=${limit}`;
        if (host) url += '&host=' + encodeURIComponent(host);
        if (tenant) url += '&tenant_id=' + encodeURIComponent(tenant);
        const data = await api(url);
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const suffix = host ? `-${host}` : '';
        _downloadJson(data, `llmproxy-requests${suffix}-${ts}.json`);
        _showExportStatus(`Downloaded ${data.length} requests${host ? ' for ' + host : ''}`, false);
    } catch (e) {
        _showExportStatus('Export failed: ' + e.message, true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-download"></i> Download Requests';
    }
}

async function exportWebSocket() {
    const btn = document.getElementById('btn-export-ws');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Exporting...';
    _showExportStatus('Fetching WebSocket data...', false);
    try {
        const tenant = getSelectedTenant();
        let url = '/api/export/websocket?limit=0';
        if (tenant) url += '&tenant_id=' + encodeURIComponent(tenant);
        const data = await api(url);
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        _downloadJson(data, `llmproxy-websocket-${ts}.json`);
        _showExportStatus(`Downloaded ${data.length} WebSocket messages`, false);
    } catch (e) {
        _showExportStatus('Export failed: ' + e.message, true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-download"></i> Download WebSocket';
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

function emptyState(msg) {
    return `<div class="empty-state"><div class="icon"><i class="fa-solid fa-inbox"></i></div><p>${esc(msg)}</p></div>`;
}

function formatAction(action) {
    if (action == null) return '-';
    if (typeof action === 'string') return esc(action);
    // Object actions (e.g. mock_response with status, headers, body)
    const parts = [];
    if (action.status) parts.push(`<strong>${action.status}</strong>`);
    if (action.body) parts.push(`<span style="color:var(--text-secondary)">${esc(String(action.body).substring(0, 80))}</span>`);
    if (parts.length > 0) return parts.join(' &mdash; ');
    return `<pre class="body-preview" style="margin:0;padding:4px 8px;max-height:100px;font-size:11px">${esc(JSON.stringify(action, null, 2))}</pre>`;
}

// ─── Initial load ──────────────────────────────────────────────────────────
checkAuth();
