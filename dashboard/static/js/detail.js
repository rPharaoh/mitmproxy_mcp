/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – detail.js
   Request detail modal, side panels, view mode toggle.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

let _viewMode = localStorage.getItem('llmproxy_view_mode') || 'panel';

// ── View mode toggle ──────────────────────────────────────────────────────

function toggleViewMode() {
    _viewMode = _viewMode === 'panel' ? 'modal' : 'panel';
    localStorage.setItem('llmproxy_view_mode', _viewMode);
    _updateViewToggleButtons();
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

document.addEventListener('DOMContentLoaded', _updateViewToggleButtons);

// ── Detail content renderer ───────────────────────────────────────────────

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

// ── Route to panel or modal ───────────────────────────────────────────────

async function showRequestDetail(id) {
    if (_viewMode === 'panel' && _activePage === 'requests') {
        showInSidePanel(id);
    } else if (_viewMode === 'panel' && _activePage === 'live') {
        showInLiveSidePanel(id);
    } else {
        showInModal(id);
    }
}

// ── Modal ─────────────────────────────────────────────────────────────────

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

function closeModal() {
    document.getElementById('request-modal').classList.remove('open');
}

document.getElementById('request-modal')?.addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) closeModal();
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
});

// ── Requests side panel ───────────────────────────────────────────────────

async function showInSidePanel(id) {
    const splitView = document.querySelector('#page-requests .split-view');
    const panelBody = document.getElementById('side-panel-body');
    if (!splitView || !panelBody) { showInModal(id); return; }

    splitView.classList.add('panel-open');
    panelBody.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

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

// ── Live feed side panel ──────────────────────────────────────────────────

async function showInLiveSidePanel(id) {
    const splitView = document.getElementById('live-split-view');
    const panelBody = document.getElementById('live-side-panel-body');
    if (!splitView || !panelBody) { showInModal(id); return; }

    splitView.classList.add('panel-open');
    panelBody.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

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
