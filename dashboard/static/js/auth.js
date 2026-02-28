/* ═══════════════════════════════════════════════════════════════════════════
   LLMProxy Dashboard – auth.js
   Login / logout, token validation, tenant management.
   Depends on: core.js
   ═══════════════════════════════════════════════════════════════════════════ */

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

    if (_authToken) {
        const ok = await validateToken(_authToken);
        if (ok) { showApp(); return; }
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
    navigateTo('overview');
}

function updateAuthUI() {
    const selector = document.querySelector('.tenant-selector');
    const badgeEl = document.getElementById('user-badge');

    if (_authRequired) {
        if (badgeEl) {
            if (_isAdmin) {
                badgeEl.innerHTML = '<span class="user-badge admin"><i class="fa-solid fa-crown"></i> ' + esc(_myName || 'Admin') + ' <button class="logout-btn" onclick="doLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button></span>';
            } else {
                badgeEl.innerHTML = '<span class="user-badge"><i class="fa-solid fa-user"></i> ' + esc(_myName || 'User') + ' <button class="logout-btn" onclick="doLogout()"><i class="fa-solid fa-right-from-bracket"></i> Logout</button></span>';
            }
            badgeEl.style.display = 'block';
        }
        if (selector) selector.style.display = _isAdmin ? 'block' : 'none';
    } else {
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

document.getElementById('login-token')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
});

// ── Tenant selector ───────────────────────────────────────────────────────

async function loadTenants() {
    if (_authRequired && !_isAdmin) return;
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
    } catch (_) {}
}

document.getElementById('tenant-select')?.addEventListener('change', () => {
    const activePage = document.querySelector('.nav-item.active')?.dataset.page;
    if (activePage) navigateTo(activePage);
});
