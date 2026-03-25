// ==================== Init ====================

let _renderIconsTimer = null;
let _responsiveModeTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    syncResponsiveMode();
    window.addEventListener('resize', queueResponsiveModeSync);
    window.addEventListener('orientationchange', queueResponsiveModeSync);
    renderIcons();
    checkSession();
});

function queueResponsiveModeSync() {
    if (_responsiveModeTimer) clearTimeout(_responsiveModeTimer);
    _responsiveModeTimer = setTimeout(() => {
        _responsiveModeTimer = null;
        syncResponsiveMode();
    }, 120);
}

function isMobileAdaptiveMode() {
    const narrowViewport = window.matchMedia('(max-width: 900px)').matches;
    const coarsePointer = window.matchMedia('(pointer: coarse)').matches;
    const noHover = window.matchMedia('(hover: none)').matches;
    return narrowViewport || coarsePointer || noHover;
}

function syncResponsiveMode() {
    document.body.classList.toggle('mobile-adaptive', isMobileAdaptiveMode());
}

function renderIcons() {
    if (typeof lucide === 'undefined') return;
    // Debounce: collapse rapid calls into one
    if (_renderIconsTimer) clearTimeout(_renderIconsTimer);
    _renderIconsTimer = setTimeout(() => {
        _renderIconsTimer = null;
        lucide.createIcons();
    }, 16);
}

// ==================== Auth Gate ====================

async function checkSession() {
    // Validate session via API call — the HttpOnly cookie is sent automatically
    try {
        const res = await fetch(`${API_URL}/admin/tenant`, { credentials: 'include' });
        if (res.ok) {
            showApp();
        } else {
            window.location.href = '/login';
        }
    } catch {
        window.location.href = '/login';
    }
}

function showLogin() {
    window.location.href = '/login';
}

function showApp() {
    syncResponsiveMode();
    document.getElementById('appContainer').classList.remove('hidden');
    setupNavigation();
    setupMobileSidebar();
    setupModals();
    setupForms();
    checkApiHealth();
    loadDashboard();
    startAutoRefresh();

    // Show tenant name in sidebar
    var tenantName = sessionStorage.getItem('tenant_name');
    if (tenantName) {
        var el = document.querySelector('.brand .version');
        if (el) el.textContent = tenantName;
    }

    renderIcons();
}

async function adminLogout() {
    try {
        await fetch(`${API_URL}/admin/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: '{}'
        });
    } catch { /* ignore */ }
    sessionStorage.removeItem('tenant_id');
    sessionStorage.removeItem('tenant_name');
    window.location.href = '/login';
}

// ==================== Mobile Sidebar ====================

function setupMobileSidebar() {
    var hamburgerBtn  = document.getElementById('hamburgerBtn');
    var sidebarCloseBtn = document.getElementById('sidebarCloseBtn');
    var overlay       = document.getElementById('sidebarOverlay');
    var sidebar       = document.getElementById('sidebarEl');

    function openSidebar() {
        sidebar.classList.add('open');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeSidebar() {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    if (hamburgerBtn)    hamburgerBtn.addEventListener('click', openSidebar);
    if (sidebarCloseBtn) sidebarCloseBtn.addEventListener('click', closeSidebar);
    if (overlay)         overlay.addEventListener('click', closeSidebar);

    // Auto-close sidebar when a nav item is tapped on mobile
    document.querySelectorAll('.sidebar .nav-item').forEach(function(item) {
        item.addEventListener('click', function() {
            if (isMobileAdaptiveMode()) closeSidebar();
        });
    });
}

// ==================== Navigation ====================

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(item.dataset.page);
        });
    });
}

function navigateTo(page) {
    if (currentPage === page) return; // Already on this page
    
    const currentPageEl = document.getElementById(`${currentPage}Page`);
    const newPageEl = document.getElementById(`${page}Page`);
    
    // Update nav immediately for instant feedback
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Smooth page transition
    if (currentPageEl && newPageEl) {
        currentPageEl.classList.add('transitioning-out');
        
        // Show skeleton loading immediately on new page
        showPageSkeleton(page);
        
        setTimeout(() => {
            currentPageEl.classList.remove('active', 'transitioning-out');
            newPageEl.classList.add('active');
            currentPage = page;
            
            // Clear bulk selection when leaving users page
            if (page !== 'users') clearBulkSelection();
            
            refreshCurrentPage();
            startAutoRefresh();
        }, 100); // Quick transition
    } else {
        currentPage = page;
        document.querySelectorAll('.page').forEach(p => {
            p.classList.toggle('active', p.id === `${page}Page`);
        });
        
        // Clear bulk selection when leaving users page
        if (page !== 'users') clearBulkSelection();
        
        refreshCurrentPage();
        startAutoRefresh();
    }
}

// Show skeleton loading for pages
function showPageSkeleton(page) {
    if (page === 'apps') {
        const tbody = document.getElementById('appsTableBody');
        if (tbody) tbody.innerHTML = generateTableSkeleton(5, 7);
    } else if (page === 'users') {
        const tbody = document.getElementById('usersTableBody');
        if (tbody) tbody.innerHTML = generateTableSkeleton(5, 6);
    } else if (page === 'activity') {
        const sessionsTbody = document.getElementById('adminSessionsTableBody');
        const historyTbody = document.getElementById('adminHistoryTableBody');
        if (sessionsTbody) sessionsTbody.innerHTML = generateTableSkeleton(4, 6);
        if (historyTbody) historyTbody.innerHTML = generateTableSkeleton(6, 4);
    } else if (page === 'settings') {
        const summary = document.getElementById('settingsPasskeySummary');
        const list = document.getElementById('settingsPasskeyList');
        const chip = document.getElementById('settingsMfaStatusChip');
        const otpBlock = document.getElementById('settingsMfaOtpBlock');
        const otpInput = document.getElementById('settingsMfaOtp');
        if (summary) summary.textContent = 'Loading passkey status...';
        if (list) list.innerHTML = '<div class="settings-passkey-empty">Loading settings...</div>';
        if (chip) {
            chip.className = 'settings-chip disabled';
            chip.textContent = 'Loading MFA...';
        }
        if (otpBlock) otpBlock.style.display = 'none';
        if (otpInput) otpInput.value = '';
        clearSettingsMessage();
    }
}

// Generate skeleton loading rows for tables
function generateTableSkeleton(rows, cols) {
    let html = '';
    for (let i = 0; i < rows; i++) {
        html += '<tr class="skeleton-row">';
        for (let j = 0; j < cols; j++) {
            const width = ['sm', 'md', 'lg', 'xl'][Math.floor(Math.random() * 4)];
            html += `<td><div class="skeleton skeleton-cell ${width}"></div></td>`;
        }
        html += '</tr>';
    }
    return html;
}

function refreshCurrentPage() {
    switch (currentPage) {
        case 'dashboard': loadDashboard(); break;
        case 'apps':      loadApps();      break;
        case 'users':     loadAppFilterOptions().then(() => loadUsers()); break;
        case 'activity':  loadMyAuthActivity(); break;
        case 'settings':  loadAdminSettings(); break;
    }
}

function startAutoRefresh() {
    // Auto-refresh disabled - use manual refresh button instead
    stopAutoRefresh();
}

function stopAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
}

// ==================== Settings ====================

function showSettingsMessage(message, type = 'success') {
    const box = document.getElementById('settingsMsg');
    if (!box) return;
    box.className = `settings-msg show ${type === 'error' ? 'error' : 'success'}`;
    box.textContent = message;
}

function clearSettingsMessage() {
    const box = document.getElementById('settingsMsg');
    if (!box) return;
    box.className = 'settings-msg';
    box.textContent = '';
}

function setSettingsButtonLoading(buttonId, loading, loadingLabel = 'Working...') {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    if (!btn.dataset.defaultLabel) {
        btn.dataset.defaultLabel = btn.textContent.trim();
    }

    if (loading) {
        btn.disabled = true;
        btn.innerHTML = `<span class="btn-inline-spinner" aria-hidden="true"></span>${escapeHtml(loadingLabel)}`;
        return;
    }

    btn.disabled = false;
    btn.textContent = btn.dataset.defaultLabel || 'Submit';
}

async function adminSettingsApiRequest(path, options = {}) {
    const cfg = {
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options
    };
    const res = await fetch(`${API_URL}${path}`, cfg);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        throw new Error(data.detail || data.message || 'Request failed');
    }
    return data;
}

function renderAdminSettingsProfile() {
    if (!adminSettingsProfile) return;
    const emailInput = document.getElementById('settingsProfileEmail');
    const tenantInput = document.getElementById('settingsTenantName');
    if (emailInput) emailInput.value = adminSettingsProfile.email || '';
    if (tenantInput) tenantInput.value = adminSettingsProfile.tenant_name || '';
}

function renderAdminSettingsSecurity() {
    if (!adminSettingsSecurity) return;

    const chip = document.getElementById('settingsMfaStatusChip');
    const toggleBtn = document.getElementById('settingsToggleMfaBtn');
    const otpBlock = document.getElementById('settingsMfaOtpBlock');
    const otpInput = document.getElementById('settingsMfaOtp');
    const mfaEnabled = !!adminSettingsSecurity.mfa_enabled;

    if (chip) {
        chip.className = `settings-chip ${mfaEnabled ? 'enabled' : 'disabled'}`;
        chip.textContent = mfaEnabled ? 'MFA Enabled' : 'MFA Disabled';
    }

    adminSettingsPendingMfaAction = mfaEnabled ? 'disable' : 'enable';
    if (toggleBtn) {
        const nextLabel = mfaEnabled ? 'Disable MFA' : 'Enable MFA';
        toggleBtn.textContent = nextLabel;
        toggleBtn.dataset.defaultLabel = nextLabel;
    }

    if (otpBlock) otpBlock.style.display = 'none';
    if (otpInput) otpInput.value = '';

    const passkeyCount = Number(adminSettingsSecurity.passkey_count || 0);
    const summary = document.getElementById('settingsPasskeySummary');
    if (summary) {
        summary.textContent = passkeyCount > 0
            ? `${passkeyCount} passkey${passkeyCount === 1 ? '' : 's'} registered`
            : 'No passkeys registered yet.';
    }

    const list = document.getElementById('settingsPasskeyList');
    if (!list) return;

    const passkeys = Array.isArray(adminSettingsSecurity.passkeys) ? adminSettingsSecurity.passkeys : [];
    if (!passkeys.length) {
        list.innerHTML = '<div class="settings-passkey-empty">Register one passkey to unlock passkey sign-in on /login.</div>';
        return;
    }

    list.innerHTML = passkeys.map((item) => {
        const passkeyId = Number(item.id);
        const createdAt = formatDateTime(item.created_at);
        const lastUsed = item.last_used_at ? formatDateTime(item.last_used_at) : 'Never';
        return `
            <div class="settings-passkey-item">
                <div class="settings-passkey-meta">
                    <strong>${escapeHtml(item.device_name || 'Admin Device')}</strong><br>
                    Created: ${escapeHtml(createdAt)}<br>
                    Last used: ${escapeHtml(lastUsed)}
                </div>
                <button type="button" class="btn btn-danger-outline btn-sm" onclick="removeAdminSettingsPasskey(${passkeyId})">Remove</button>
            </div>
        `;
    }).join('');
}

async function loadAdminSettings() {
    clearSettingsMessage();
    try {
        const [profile, security] = await Promise.all([
            adminSettingsApiRequest('/admin/settings/profile'),
            adminSettingsApiRequest('/admin/settings/security')
        ]);
        adminSettingsProfile = profile;
        adminSettingsSecurity = security;
        renderAdminSettingsProfile();
        renderAdminSettingsSecurity();
    } catch (error) {
        console.error('Error loading admin settings:', error);
        showSettingsMessage(error.message || 'Failed to load settings.', 'error');
    }
}

async function saveAdminSettingsProfile() {
    clearSettingsMessage();
    const emailInput = document.getElementById('settingsProfileEmail');
    const email = emailInput ? emailInput.value.trim().toLowerCase() : '';
    if (!email) {
        showSettingsMessage('Email is required.', 'error');
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showSettingsMessage('Please enter a valid email address.', 'error');
        return;
    }

    setSettingsButtonLoading('settingsSaveProfileBtn', true, 'Saving...');
    try {
        const data = await adminSettingsApiRequest('/admin/settings/profile', {
            method: 'PUT',
            body: JSON.stringify({ email })
        });
        adminSettingsProfile = { ...(adminSettingsProfile || {}), ...data };
        if (adminSettingsSecurity && typeof data.mfa_enabled === 'boolean') {
            adminSettingsSecurity = { ...adminSettingsSecurity, mfa_enabled: !!data.mfa_enabled };
            renderAdminSettingsSecurity();
        }
        renderAdminSettingsProfile();
        showSettingsMessage(data.message || 'Profile updated successfully.', 'success');
    } catch (error) {
        showSettingsMessage(error.message || 'Failed to save profile.', 'error');
    } finally {
        setSettingsButtonLoading('settingsSaveProfileBtn', false);
    }
}

async function requestAdminSettingsMfaOtp() {
    clearSettingsMessage();
    setSettingsButtonLoading(
        'settingsToggleMfaBtn',
        true,
        adminSettingsPendingMfaAction === 'enable' ? 'Sending code...' : 'Requesting code...'
    );

    try {
        const data = await adminSettingsApiRequest('/admin/settings/mfa/request-otp', {
            method: 'POST',
            body: JSON.stringify({ action: adminSettingsPendingMfaAction })
        });
        if (data.action === 'enable' || data.action === 'disable') {
            adminSettingsPendingMfaAction = data.action;
        }

        const otpBlock = document.getElementById('settingsMfaOtpBlock');
        const otpInput = document.getElementById('settingsMfaOtp');
        if (otpBlock) otpBlock.style.display = 'block';
        if (otpInput) {
            otpInput.value = '';
            otpInput.focus();
        }
        showSettingsMessage(data.message || 'Verification code sent to your email.', 'success');
    } catch (error) {
        showSettingsMessage(error.message || 'Failed to send verification code.', 'error');
    } finally {
        setSettingsButtonLoading('settingsToggleMfaBtn', false);
    }
}

async function verifyAdminSettingsMfaOtp() {
    clearSettingsMessage();
    const otpInput = document.getElementById('settingsMfaOtp');
    const otp = otpInput ? otpInput.value.trim() : '';
    if (!/^\d{6}$/.test(otp)) {
        showSettingsMessage('Please enter the 6-digit verification code.', 'error');
        return;
    }

    setSettingsButtonLoading('settingsVerifyMfaBtn', true, 'Verifying...');
    try {
        const data = await adminSettingsApiRequest('/admin/settings/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({ otp })
        });

        if (!adminSettingsSecurity) adminSettingsSecurity = {};
        adminSettingsSecurity.mfa_enabled = !!data.mfa_enabled;
        if (adminSettingsProfile) adminSettingsProfile.mfa_enabled = !!data.mfa_enabled;

        const otpBlock = document.getElementById('settingsMfaOtpBlock');
        if (otpBlock) otpBlock.style.display = 'none';
        if (otpInput) otpInput.value = '';

        renderAdminSettingsSecurity();
        showSettingsMessage(data.message || 'MFA updated successfully.', 'success');
    } catch (error) {
        showSettingsMessage(error.message || 'Failed to verify code.', 'error');
    } finally {
        setSettingsButtonLoading('settingsVerifyMfaBtn', false);
    }
}

function base64urlToBuffer(base64url) {
    const clean = String(base64url || '').replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (clean.length % 4)) % 4);
    const base64 = clean + padding;
    const raw = atob(base64);
    const buffer = new ArrayBuffer(raw.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i);
    return buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizeCreationOptions(options) {
    const normalized = { ...(options || {}) };
    if (!normalized.challenge || !normalized.user || !normalized.user.id) {
        throw new Error('Invalid passkey registration options received from server.');
    }
    normalized.challenge = base64urlToBuffer(normalized.challenge);
    normalized.user = { ...normalized.user, id: base64urlToBuffer(normalized.user.id) };

    if (Array.isArray(normalized.excludeCredentials)) {
        normalized.excludeCredentials = normalized.excludeCredentials.map((cred) => ({
            ...cred,
            id: base64urlToBuffer(cred.id)
        }));
    }
    return normalized;
}

function getAdminSettingsDefaultDeviceName() {
    const platform = navigator.userAgentData?.platform || navigator.platform || 'Device';
    return `Admin ${String(platform).trim() || 'Device'}`;
}

async function setupAdminSettingsPasskey() {
    clearSettingsMessage();

    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
        showSettingsMessage('Passkeys are not supported on this browser/device.', 'error');
        return;
    }

    setSettingsButtonLoading('settingsSetupPasskeyBtn', true, 'Preparing...');
    try {
        const begin = await adminSettingsApiRequest('/admin/settings/passkeys/register/begin', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const publicKey = normalizeCreationOptions(begin.options || {});
        const credential = await navigator.credentials.create({ publicKey });
        if (!credential || !credential.response || !credential.response.clientDataJSON || !credential.response.attestationObject) {
            throw new Error('No passkey credential returned by the browser.');
        }

        await adminSettingsApiRequest('/admin/settings/passkeys/register/complete', {
            method: 'POST',
            body: JSON.stringify({
                credential: {
                    id: credential.id,
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64url(credential.response.attestationObject),
                    deviceName: getAdminSettingsDefaultDeviceName()
                }
            })
        });

        await loadAdminSettings();
        showSettingsMessage('Passkey setup complete. You can now use passkey sign-in.', 'success');
    } catch (error) {
        const name = error && error.name ? String(error.name) : '';
        const msg = String(error.message || '');
        if (name === 'NotAllowedError' || msg.includes('NotAllowedError')) {
            showSettingsMessage('Passkey setup was cancelled.', 'error');
        } else {
            showSettingsMessage(msg || 'Failed to set up passkey.', 'error');
        }
    } finally {
        setSettingsButtonLoading('settingsSetupPasskeyBtn', false);
    }
}

async function removeAdminSettingsPasskey(passkeyId) {
    if (!Number.isFinite(Number(passkeyId))) return;
    clearSettingsMessage();

    if (!window.confirm('Remove this passkey?')) {
        return;
    }

    try {
        await adminSettingsApiRequest(`/admin/settings/passkeys/${Number(passkeyId)}`, {
            method: 'DELETE'
        });
        await loadAdminSettings();
        showSettingsMessage('Passkey removed successfully.', 'success');
    } catch (error) {
        showSettingsMessage(error.message || 'Failed to remove passkey.', 'error');
    }
}
