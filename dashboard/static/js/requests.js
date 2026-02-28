/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – requests.js
   Requests page – filters, pagination, table rendering.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

let _reqPage = 0;

// ── Domain dropdown ───────────────────────────────────────────────────────

async function _loadReqDomains() {
    try {
        const data = await api('/api/domains?limit=100');
        const sel = document.getElementById('req-domain');
        if (!sel) return;
        const current = sel.value;
        sel.innerHTML = '<option value="">All</option>';
        (data || []).forEach(d => {
            sel.innerHTML += `<option value="${esc(d.host)}">${esc(d.host)}</option>`;
        });
        sel.value = current || '';
    } catch(e) {}
}

// ── Load requests ─────────────────────────────────────────────────────────

async function loadRequests(page) {
    _loadReqDomains();
    if (typeof page === 'number') _reqPage = page;
    else _reqPage = 0;
    try {
        const search = document.getElementById('req-search')?.value || '';
        const method = document.getElementById('req-method')?.value || '';
        const domain = document.getElementById('req-domain')?.value || '';
        const statusClass = document.getElementById('req-status')?.value || '';
        const mimeType = document.getElementById('req-mime')?.value || '';
        const limit = parseInt(document.getElementById('req-limit')?.value || '50', 10);
        const offset = _reqPage * limit;

        let url = `/api/requests?limit=${limit}&offset=${offset}`;
        if (method) url += `&method=${method}`;
        if (domain) url += `&host=${encodeURIComponent(domain)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (statusClass) url += `&status_class=${encodeURIComponent(statusClass)}`;
        if (mimeType) url += `&mime_type=${encodeURIComponent(mimeType)}`;

        const data = await api(url);
        document.getElementById('requests-table').innerHTML = requestsTable(data.requests || data);
        _renderReqPagination(data.total || 0, limit, _reqPage);
    } catch (e) {
        document.getElementById('requests-table').innerHTML = `<div class="empty-state"><p>Error loading requests</p></div>`;
        document.getElementById('requests-pagination').style.display = 'none';
    }
}

// ── Pagination ────────────────────────────────────────────────────────────

function _renderReqPagination(total, limit, currentPage) {
    const el = document.getElementById('requests-pagination');
    if (!el || total <= limit) { if (el) el.style.display = 'none'; return; }
    const totalPages = Math.ceil(total / limit);
    const maxButtons = 7;
    let startPage = Math.max(0, currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons);
    if (endPage - startPage < maxButtons) startPage = Math.max(0, endPage - maxButtons);

    let html = `<div class="pagination-info">${total.toLocaleString()} results · page ${currentPage + 1} of ${totalPages}</div><div class="pagination-buttons">`;
    html += `<button class="btn btn-sm" ${currentPage === 0 ? 'disabled' : ''} onclick="loadRequests(0)" title="First"><i class="fa-solid fa-angles-left"></i></button>`;
    html += `<button class="btn btn-sm" ${currentPage === 0 ? 'disabled' : ''} onclick="loadRequests(${currentPage - 1})" title="Previous"><i class="fa-solid fa-angle-left"></i></button>`;
    for (let i = startPage; i < endPage; i++) {
        html += `<button class="btn btn-sm${i === currentPage ? ' btn-primary' : ''}" onclick="loadRequests(${i})">${i + 1}</button>`;
    }
    html += `<button class="btn btn-sm" ${currentPage >= totalPages - 1 ? 'disabled' : ''} onclick="loadRequests(${currentPage + 1})" title="Next"><i class="fa-solid fa-angle-right"></i></button>`;
    html += `<button class="btn btn-sm" ${currentPage >= totalPages - 1 ? 'disabled' : ''} onclick="loadRequests(${totalPages - 1})" title="Last"><i class="fa-solid fa-angles-right"></i></button>`;
    html += '</div>';
    el.innerHTML = html;
    el.style.display = 'flex';
}

// ── Filter clear & search shortcut ────────────────────────────────────────

document.getElementById('req-search')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') loadRequests();
});

function clearReqFilters() {
    document.getElementById('req-search').value = '';
    document.getElementById('req-domain').value = '';
    document.getElementById('req-method').value = '';
    document.getElementById('req-status').value = '';
    document.getElementById('req-mime').value = '';
    document.getElementById('req-limit').value = '50';
    loadRequests();
}

// ── Table renderer (shared with Overview) ─────────────────────────────────

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
