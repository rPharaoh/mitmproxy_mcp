/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – live.js
   Live Feed page – SSE streaming with polling fallback, filters.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

let _liveEventSource = null;
let _liveDomainFilter = '';
let _liveSearch = '';
let _liveMethod = '';
let _liveStatusClass = '';
let _liveMimeType = '';

// ── Start / Stop ──────────────────────────────────────────────────────────

function startLive() {
    livePaused = false;
    document.getElementById('live-toggle').innerHTML = '<i class="fa-solid fa-pause"></i> Pause';
    document.getElementById('live-feed-list').innerHTML = '';

    _loadLiveDomains();
    stopLive();
    _startSSE();
}

function stopLive() {
    if (_liveEventSource) {
        _liveEventSource.close();
        _liveEventSource = null;
    }
    if (liveInterval) { clearInterval(liveInterval); liveInterval = null; }
}

// ── Domain dropdown ───────────────────────────────────────────────────────

async function _loadLiveDomains() {
    try {
        const data = await api('/api/domains?limit=100');
        const sel = document.getElementById('live-domain-filter');
        const current = sel.value;
        sel.innerHTML = '<option value="">All</option>';
        (data || []).forEach(d => {
            sel.innerHTML += `<option value="${esc(d.host)}">${esc(d.host)}</option>`;
        });
        sel.value = current || '';
    } catch(e) {}
}

// ── Filter change handlers ────────────────────────────────────────────────

function _restartLiveStream() {
    document.getElementById('live-feed-list').innerHTML = '';
    stopLive();
    _startSSE();
}

document.getElementById('live-domain-filter')?.addEventListener('change', () => {
    _liveDomainFilter = document.getElementById('live-domain-filter').value;
    _restartLiveStream();
});

document.getElementById('live-method-filter')?.addEventListener('change', () => {
    _liveMethod = document.getElementById('live-method-filter').value;
    _restartLiveStream();
});

document.getElementById('live-status-filter')?.addEventListener('change', () => {
    _liveStatusClass = document.getElementById('live-status-filter').value;
    _restartLiveStream();
});

document.getElementById('live-mime-filter')?.addEventListener('change', () => {
    _liveMimeType = document.getElementById('live-mime-filter').value;
    _restartLiveStream();
});

let _liveSearchDebounce = null;
document.getElementById('live-search')?.addEventListener('input', () => {
    clearTimeout(_liveSearchDebounce);
    _liveSearchDebounce = setTimeout(() => {
        _liveSearch = document.getElementById('live-search').value.trim();
        _restartLiveStream();
    }, 400);
});

function clearLiveFilters() {
    document.getElementById('live-search').value = '';
    document.getElementById('live-domain-filter').value = '';
    document.getElementById('live-method-filter').value = '';
    document.getElementById('live-status-filter').value = '';
    document.getElementById('live-mime-filter').value = '';
    _liveSearch = ''; _liveDomainFilter = ''; _liveMethod = ''; _liveStatusClass = ''; _liveMimeType = '';
    _restartLiveStream();
}

// ── Pause / Resume ────────────────────────────────────────────────────────

document.getElementById('live-toggle')?.addEventListener('click', () => {
    livePaused = !livePaused;
    document.getElementById('live-toggle').innerHTML = livePaused
        ? '<i class="fa-solid fa-play"></i> Resume'
        : '<i class="fa-solid fa-pause"></i> Pause';
});

// ── SSE streaming ─────────────────────────────────────────────────────────

function _buildLiveParams() {
    const params = [];
    if (_authToken) params.push('token=' + encodeURIComponent(_authToken));
    if (_liveDomainFilter) params.push('host=' + encodeURIComponent(_liveDomainFilter));
    if (_liveSearch) params.push('search=' + encodeURIComponent(_liveSearch));
    if (_liveMethod) params.push('method=' + encodeURIComponent(_liveMethod));
    if (_liveStatusClass) params.push('status_class=' + encodeURIComponent(_liveStatusClass));
    if (_liveMimeType) params.push('mime_type=' + encodeURIComponent(_liveMimeType));
    return params;
}

function _startSSE() {
    try {
        let url = '/api/live/stream';
        const params = _buildLiveParams();
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
            console.warn('SSE connection lost, falling back to polling');
            _liveEventSource.close();
            _liveEventSource = null;
            _startPolling();
        };

    } catch (e) {
        _startPolling();
    }
}

// ── Polling fallback ──────────────────────────────────────────────────────

function _startPolling() {
    liveCursorHttp = null;
    liveCursorWs = null;
    if (liveInterval) clearInterval(liveInterval);
    pollLive();
    liveInterval = setInterval(pollLive, 2000);
}

async function pollLive() {
    if (livePaused) return;
    try {
        let url = '/api/live?limit=50';
        if (liveCursorHttp) url += '&after_id=' + encodeURIComponent(liveCursorHttp);
        if (liveCursorWs) url += '&after_ws_id=' + encodeURIComponent(liveCursorWs);
        if (_liveDomainFilter) url += '&host=' + encodeURIComponent(_liveDomainFilter);
        if (_liveSearch) url += '&search=' + encodeURIComponent(_liveSearch);
        if (_liveMethod) url += '&method=' + encodeURIComponent(_liveMethod);
        if (_liveStatusClass) url += '&status_class=' + encodeURIComponent(_liveStatusClass);
        if (_liveMimeType) url += '&mime_type=' + encodeURIComponent(_liveMimeType);
        const data = await api(url);

        if (data.http?.cursor) liveCursorHttp = data.http.cursor;
        if (data.ws?.cursor) liveCursorWs = data.ws.cursor;

        _renderLiveItems(data.http?.requests || [], data.ws?.messages || []);
    } catch (e) {
        console.error('Live poll error:', e);
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

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
