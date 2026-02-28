/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – pages.js
   All secondary pages: Domains, Errors, WebSocket, Performance, Security,
   Privacy, API Map, Blocked Domains, Rules, Tokens, Export, Clear Data.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

// ═══════════════════════════════════════════════════════════════════════════
// Domains
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
// Errors
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
// WebSocket
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
// Performance
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
// Security
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
// Privacy
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
// API Map
// ═══════════════════════════════════════════════════════════════════════════

async function populateApiMapDomains() {
    const select = document.getElementById('apimap-host');
    const current = select.value;
    try {
        const domains = await api('/api/domains?limit=100');
        select.innerHTML = '<option value="">Select a domain...</option>';
        (domains || []).forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.host;
            opt.textContent = `${d.host}  (${d.total_requests} reqs)`;
            select.appendChild(opt);
        });
        if (current) select.value = current;
    } catch (_) {}
}

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
// Blocked Domains
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
// Rules
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
// Tokens
// ═══════════════════════════════════════════════════════════════════════════

async function loadTokens() {
    const el = document.getElementById('tokens-list');
    if (!el) return;
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
// Clear Data
// ═══════════════════════════════════════════════════════════════════════════

async function loadClearData() {
    const sel = document.getElementById('clear-tenant-select');
    if (!sel) return;
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
// Export Data
// ═══════════════════════════════════════════════════════════════════════════

function loadExport() {
    document.getElementById('export-status').style.display = 'none';
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
