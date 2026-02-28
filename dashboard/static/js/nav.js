/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – nav.js
   Navigation, auto-refresh timer, tab system.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Navigation ────────────────────────────────────────────────────────────

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

    // Reset auto-refresh timer for new page
    _restartAutoRefresh();

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

// ── Auto-refresh ──────────────────────────────────────────────────────────

let _autoRefreshTimer = null;
let _autoRefreshEnabled = localStorage.getItem('llmproxy_autorefresh') === '1';
let _autoRefreshInterval = parseInt(localStorage.getItem('llmproxy_autorefresh_interval') || '10', 10);

const _noAutoRefreshPages = new Set(['live', 'tokens', 'export', 'clear-data']);

const _pageLoaders = {
    'overview': () => loadOverview(),
    'requests': () => loadRequests(_reqPage),
    'domains': () => loadDomains(),
    'errors': () => loadErrors(),
    'websocket': () => loadWebSocket(),
    'performance': () => loadPerformance(),
    'security': () => loadSecurity(),
    'privacy': () => loadPrivacy(),
    'api-map': () => loadApiMap(),
    'blocked': () => loadBlocked(),
    'rules': () => loadRules(),
};

function _restartAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
    if (!_autoRefreshEnabled) return;
    if (_noAutoRefreshPages.has(_activePage)) return;
    const loader = _pageLoaders[_activePage];
    if (!loader) return;
    _autoRefreshTimer = setInterval(loader, _autoRefreshInterval * 1000);
}

function _stopAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
}

(function initAutoRefresh() {
    const chk = document.getElementById('auto-refresh-check');
    const sel = document.getElementById('auto-refresh-interval');
    if (chk) chk.checked = _autoRefreshEnabled;
    if (sel) sel.value = String(_autoRefreshInterval);

    chk?.addEventListener('change', () => {
        _autoRefreshEnabled = chk.checked;
        localStorage.setItem('llmproxy_autorefresh', _autoRefreshEnabled ? '1' : '0');
        if (_autoRefreshEnabled) _restartAutoRefresh();
        else _stopAutoRefresh();
    });
    sel?.addEventListener('change', () => {
        _autoRefreshInterval = parseInt(sel.value, 10) || 10;
        localStorage.setItem('llmproxy_autorefresh_interval', String(_autoRefreshInterval));
        if (_autoRefreshEnabled) _restartAutoRefresh();
    });
})();

// ── Tab system ────────────────────────────────────────────────────────────

document.querySelectorAll('.tabs').forEach(tabBar => {
    tabBar.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            tabBar.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const section = tabBar.id.replace('-tabs', '');
            if (section === 'perf') renderPerfTab(tab.dataset.tab);
            if (section === 'security') renderSecurityTab(tab.dataset.tab);
            if (section === 'privacy') renderPrivacyTab(tab.dataset.tab);
        });
    });
});
