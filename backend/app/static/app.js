const API_URL = window.location.origin;

// ==================== Auth Interceptor ====================
// Automatically attaches admin JWT to all /admin/ API requests
// and redirects to login on 401 responses.
(function () {
    const _fetch = window.fetch;
    window.fetch = function (url, opts) {
        opts = opts || {};
        const tk = localStorage.getItem('admin_token');
        if (tk && typeof url === 'string' && url.includes('/admin')) {
            opts.headers = Object.assign({}, opts.headers || {}, { 'Authorization': 'Bearer ' + tk });
        }
        return _fetch.call(this, url, opts).then(function (res) {
            if (res.status === 401 && typeof url === 'string' && url.includes('/admin')) {
                localStorage.removeItem('admin_token');
                localStorage.removeItem('tenant_id');
                localStorage.removeItem('tenant_name');
                document.cookie = 'admin_token=; path=/; max-age=0';
                window.location.href = '/login';
            }
            return res;
        });
    };
})();

// State
let currentPage = 'dashboard';
let apps = [];
let users = [];
let editingAppId = null;
let editingUserId = null;
let deleteCallback = null;
let selectedAppFilter = '';
let selectedUserIds = new Set();
let _autoRefreshTimer = null;

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

function checkSession() {
    var tk = localStorage.getItem('admin_token');
    if (tk) {
        // Sync cookie so middleware stays happy
        document.cookie = 'admin_token=' + tk + '; path=/; SameSite=Lax; max-age=86400';
        showApp();
    } else {
        // Clear any stale cookie too
        document.cookie = 'admin_token=; path=/; max-age=0';
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
    var tenantName = localStorage.getItem('tenant_name');
    if (tenantName) {
        var el = document.querySelector('.brand .version');
        if (el) el.textContent = tenantName;
    }

    renderIcons();
}

function adminLogout() {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('tenant_id');
    localStorage.removeItem('tenant_name');
    document.cookie = 'admin_token=; path=/; max-age=0';
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
        if (tbody) tbody.innerHTML = generateTableSkeleton(5, 9);
    } else if (page === 'users') {
        const tbody = document.getElementById('usersTableBody');
        if (tbody) tbody.innerHTML = generateTableSkeleton(5, 6);
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
    }
}

function startAutoRefresh() {
    // Auto-refresh disabled - use manual refresh button instead
    stopAutoRefresh();
}

function stopAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
}

// ==================== Dashboard ====================

async function loadDashboard() {
    try {
        const response = await fetch(`${API_URL}/admin/stats`);
        if (response.ok) {
            const stats = await response.json();
            animateValue('totalApps', stats.total_apps || 0);
            animateValue('totalUsers', stats.total_users || 0);
            animateValue('activeUsers', stats.active_users || 0);
            animateValue('onlineUsers', stats.online_users || 0);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function animateValue(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    const current = parseInt(el.textContent) || 0;
    if (current === target) { el.textContent = target; return; }
    
    // Add visual update pulse
    el.classList.add('updating');

    const duration = 350; // Faster for snappier feel
    const start = performance.now();

    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        // Smoother easing function
        const eased = progress < 0.5
            ? 4 * progress * progress * progress
            : 1 - Math.pow(-2 * progress + 2, 3) / 2;
        el.textContent = Math.round(current + (target - current) * eased);
        if (progress < 1) {
            requestAnimationFrame(tick);
        } else {
            el.classList.remove('updating');
        }
    }

    requestAnimationFrame(tick);
}

// ==================== Apps Management ====================

async function loadApps() {
    const tbody = document.getElementById('appsTableBody');
    const container = tbody.closest('.table-container');
    
    // Show skeleton loading (instant visual feedback)
    tbody.innerHTML = generateTableSkeleton(5, 9);
    if (container) container.classList.add('refreshing');

    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        apps = await response.json();
        
        if (container) container.classList.remove('refreshing');

        if (apps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="loading">No applications yet. Create your first app.</td></tr>';
            return;
        }

        tbody.innerHTML = apps.map(app => {
            const safeAppId = escapeAttr(app.app_id);
            const safeName = escapeAttr(app.name || 'Unnamed');
            return `
            <tr class="new-row">
                <td data-label="Name" class="app-name-cell">${escapeHtml(app.name || 'Unnamed')}</td>
                <td data-label="App ID"><code>${app.app_id}</code></td>
                <td data-label="OTP"><span class="status-badge ${app.otp_enabled ? 'active' : 'inactive'}">${app.otp_enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td data-label="Passkey"><span class="status-badge ${app.passkey_enabled ? 'active' : 'inactive'}">${app.passkey_enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td data-label="Notification"><span class="status-badge ${app.login_notification_enabled ? 'active' : 'inactive'}">${app.login_notification_enabled ? 'On' : 'Off'}</span></td>
                <td>${app.access_token_expiry_minutes}m / ${app.refresh_token_expiry_days}d</td>
                <td class="redirect-uris">${app.redirect_uris ? escapeHtml(app.redirect_uris) : '<span style="color:#94a3b8">Not set</span>'}</td>
                <td>${formatDate(app.created_at)}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" data-action="credentials" data-app-id="${safeAppId}" title="View Credentials">
                            <i data-lucide="key-round"></i>
                        </button>
                        <button class="btn-icon" data-action="edit-app" data-app-id="${safeAppId}" title="Edit">
                            <i data-lucide="pencil"></i>
                        </button>
                        <button class="btn-icon danger" data-action="delete-app" data-app-id="${safeAppId}" data-app-name="${safeName}" title="Delete">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        // Attach event listeners via delegation
        tbody.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = btn.dataset.action;
                const appId = btn.dataset.appId;
                if (action === 'credentials') showCredentials(appId);
                else if (action === 'edit-app') editApp(appId);
                else if (action === 'delete-app') confirmDeleteApp(appId, btn.dataset.appName);
            });
        });
        renderIcons();
    } catch (error) {
        console.error('Error loading apps:', error);
        tbody.innerHTML = '<tr><td colspan="9" class="loading">Failed to load applications</td></tr>';
    }
}

function showCreateAppModal() {
    editingAppId = null;
    document.getElementById('appModalTitle').textContent = 'Create Application';
    document.getElementById('appFormSubmit').textContent = 'Create App';
    document.getElementById('appForm').reset();
    document.getElementById('appOtpEnabled').checked = true;
    document.getElementById('appPasskeyEnabled').checked = false;
    document.getElementById('appLoginNotification').checked = false;
    document.getElementById('appForceLogoutNotification').checked = false;
    document.getElementById('appAccessTokenExpiry').value = 30;
    document.getElementById('appRefreshTokenExpiry').value = 7;
    document.getElementById('appRedirectUris').value = '';
    openModal('appModal');
}

function editApp(appId) {
    const app = apps.find(a => a.app_id === appId);
    if (!app) return;

    editingAppId = appId;
    document.getElementById('appModalTitle').textContent = 'Edit Application';
    document.getElementById('appFormSubmit').textContent = 'Save Changes';
    document.getElementById('appName').value = app.name || '';
    document.getElementById('appDescription').value = app.description || '';
    document.getElementById('appOtpEnabled').checked = !!app.otp_enabled;
    document.getElementById('appPasskeyEnabled').checked = !!app.passkey_enabled;
    document.getElementById('appLoginNotification').checked = !!app.login_notification_enabled;
    document.getElementById('appForceLogoutNotification').checked = !!app.force_logout_notification_enabled;
    document.getElementById('appAccessTokenExpiry').value = app.access_token_expiry_minutes || 30;
    document.getElementById('appRefreshTokenExpiry').value = app.refresh_token_expiry_days || 7;
    document.getElementById('appRedirectUris').value = app.redirect_uris || '';
    openModal('appModal');
}

async function saveApp() {
    const name = document.getElementById('appName').value.trim();
    const description = document.getElementById('appDescription').value.trim();
    const otp_enabled = document.getElementById('appOtpEnabled').checked;
    const passkey_enabled = document.getElementById('appPasskeyEnabled').checked;
    const login_notification_enabled = document.getElementById('appLoginNotification').checked;
    const force_logout_notification_enabled = document.getElementById('appForceLogoutNotification').checked;
    const access_token_expiry_minutes = parseInt(document.getElementById('appAccessTokenExpiry').value) || 30;
    const refresh_token_expiry_days = parseInt(document.getElementById('appRefreshTokenExpiry').value) || 7;
    const redirect_uris = document.getElementById('appRedirectUris').value.trim();

    if (!name) { showToast('Please enter an app name', 'error'); return; }

    try {
        const body = { name, description, otp_enabled, passkey_enabled, login_notification_enabled, force_logout_notification_enabled, access_token_expiry_minutes, refresh_token_expiry_days };
        if (redirect_uris) body.redirect_uris = redirect_uris;

        let response;
        if (editingAppId) {
            response = await fetch(`${API_URL}/admin/apps/${editingAppId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        } else {
            response = await fetch(`${API_URL}/admin/apps`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        }

        const data = await response.json();

        if (response.ok) {
            closeModal('appModal');

            if (!editingAppId && data.app_id && data.app_secret) {
                document.getElementById('credAppId').textContent = data.app_id;
                document.getElementById('credAppSecret').textContent = data.app_secret;
                openModal('credentialsModal');
            }

            loadApps();
            loadDashboard();
            showToast(editingAppId ? 'Application updated' : 'Application created', 'success');
        } else {
            showToast(data.detail || 'Operation failed', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showToast('Failed to save application', 'error');
    }
}

async function showCredentials(appId) {
    try {
        const response = await fetch(`${API_URL}/admin/apps/${appId}/credentials`);
        if (response.ok) {
            const data = await response.json();
            document.getElementById('credAppId').textContent = data.app_id;
            document.getElementById('credAppSecret').textContent = data.app_secret;
            openModal('credentialsModal');
        } else {
            showToast('Failed to load credentials', 'error');
        }
    } catch (error) {
        showToast('Failed to load credentials', 'error');
    }
}

function confirmDeleteApp(appId, appName) {
    document.getElementById('deleteTargetName').textContent = appName;
    deleteCallback = async () => {
        try {
            const response = await fetch(`${API_URL}/admin/apps/${appId}`, { method: 'DELETE' });
            if (response.ok) {
                closeModal('deleteModal');
                loadApps();
                loadDashboard();
                // Refresh user list since users were cascade-deleted
                if (currentPage === 'users' || selectedAppFilter === appId) {
                    selectedAppFilter = '';
                    loadAppFilterOptions().then(() => loadUsers());
                }
                showToast('Application and its users deleted', 'success');
            } else {
                showToast('Failed to delete application', 'error');
            }
        } catch { showToast('Failed to delete application', 'error'); }
    };
    document.getElementById('deleteConfirmBtn').onclick = deleteCallback;
    openModal('deleteModal');
}

// ==================== Users Management ====================

async function loadUsers() {
    const tbody = document.getElementById('usersTableBody');
    const container = tbody.closest('.table-container');
    
    // Show skeleton loading (instant visual feedback)
    tbody.innerHTML = generateTableSkeleton(5, 6);
    if (container) container.classList.add('refreshing');

    try {
        let url = `${API_URL}/admin/users`;
        const params = [];
        if (selectedAppFilter) params.push(`app_id=${encodeURIComponent(selectedAppFilter)}`);
        if (params.length) url += '?' + params.join('&');

        const response = await fetch(url);
        const data = await response.json();
        users = Array.isArray(data) ? data : (data.users || []);
        
        if (container) container.classList.remove('refreshing');

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No users found.</td></tr>';
            return;
        }

        // Map app_ids to names for display
        const appMap = {};
        apps.forEach(a => { appMap[a.app_id] = a.name; });

        tbody.innerHTML = users.map(user => {
            const appName = user.app_id ? (appMap[user.app_id] || user.app_id) : 'None';
            const safeEmail = escapeAttr(user.email);
            const onlineClass = user.is_online ? 'active' : 'inactive';
            const onlineLabel = user.is_online ? 'Online' : 'Offline';
            const isChecked = selectedUserIds.has(user.id) ? 'checked' : '';
            return `
            <tr class="new-row">
                <td data-label="Select" class="td-check"><input type="checkbox" class="user-select-cb" data-user-id="${user.id}" ${isChecked} onchange="onUserCheckChange()"></td>
                <td data-label="Email" class="app-name-cell">${escapeHtml(user.email)}</td>
                <td data-label="Status"><span class="status-badge ${onlineClass}">${onlineLabel}</span></td>
                <td data-label="Active"><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
                <td data-label="Created">${formatDate(user.created_at)}</td>
                <td>
                    <div class="action-btns">
                        ${user.is_online ? `<button class="btn-icon danger" data-action="force-logout" data-user-id="${user.id}" data-user-email="${safeEmail}" title="Force Logout">
                            <i data-lucide="log-out"></i>
                        </button>` : ''}
                        <button class="btn-icon" data-action="edit-user" data-user-id="${user.id}" title="Edit">
                            <i data-lucide="pencil"></i>
                        </button>
                        <button class="btn-icon danger" data-action="delete-user" data-user-id="${user.id}" data-user-email="${safeEmail}" title="Delete">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        // Attach event listeners via delegation
        tbody.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                const userId = parseInt(btn.dataset.userId);
                if (action === 'edit-user') editUser(userId);
                else if (action === 'delete-user') confirmDeleteUser(userId, btn.dataset.userEmail);
                else if (action === 'force-logout') forceLogoutUserById(userId, btn.dataset.userEmail);
            });
        });

        // Sync select-all checkbox state
        const allCbs = document.querySelectorAll('.user-select-cb');
        const selectAllCb = document.getElementById('selectAllUsers');
        if (selectAllCb) selectAllCb.checked = allCbs.length > 0 && selectedUserIds.size === allCbs.length;
        updateBulkBar();

        renderIcons();
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="loading">Failed to load users</td></tr>';
    }
}

function showCreateUserModal() {
    editingUserId = null;
    document.getElementById('userModalTitle').textContent = 'Add New User';
    document.getElementById('userFormSubmit').textContent = 'Add User';
    document.getElementById('userForm').reset();
    document.getElementById('userEmail').disabled = false;
    document.getElementById('userAppId').disabled = false;
    document.getElementById('userStatusGroup').classList.add('hidden');
    var flGroup = document.getElementById('forceLogoutGroup');
    if (flGroup) flGroup.classList.add('hidden');
    loadAppsForSelect();
    openModal('userModal');
}

async function loadAppsForSelect() {
    const select = document.getElementById('userAppId');
    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        const appsList = await response.json();
        select.innerHTML = appsList.map(app =>
            `<option value="${app.app_id}">${escapeHtml(app.name)} (${app.app_id})</option>`
        ).join('');
    } catch (error) {
        console.error('Error loading apps for select:', error);
    }
}

function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (!user) return;

    editingUserId = userId;
    document.getElementById('userModalTitle').textContent = 'Edit User';
    document.getElementById('userFormSubmit').textContent = 'Save Changes';
    document.getElementById('userEmail').value = user.email;
    document.getElementById('userEmail').disabled = true;
    document.getElementById('userAppId').disabled = true;
    document.getElementById('userStatusGroup').classList.remove('hidden');
    document.getElementById('userStatus').value = user.is_active ? 'true' : 'false';
    // Show force-logout button only if user is online
    const flGroup = document.getElementById('forceLogoutGroup');
    if (flGroup) {
        flGroup.classList.toggle('hidden', !user.is_online);
    }
    loadAppsForSelect().then(() => {
        document.getElementById('userAppId').value = user.app_id || '';
    });
    openModal('userModal');
}

async function saveUser() {
    const email = document.getElementById('userEmail').value.trim();
    const app_id = document.getElementById('userAppId').value;

    if (!email) { showToast('Please enter an email', 'error'); return; }
    if (!app_id) { showToast('Please select an application', 'error'); return; }

    try {
        let response;
        if (editingUserId) {
            const is_active = document.getElementById('userStatus').value === 'true';
            response = await fetch(`${API_URL}/admin/users/${editingUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active })
            });
        } else {
            response = await fetch(`${API_URL}/admin/users`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, app_id })
            });
        }

        const data = await response.json();

        if (response.ok) {
            closeModal('userModal');
            loadUsers();
            loadDashboard();
            showToast(editingUserId ? 'User updated' : 'User created', 'success');
        } else {
            showToast(data.detail || 'Operation failed', 'error');
        }
    } catch (error) {
        showToast('Failed to save user', 'error');
    }
}

function confirmDeleteUser(userId, email) {
    document.getElementById('deleteTargetName').textContent = email;
    deleteCallback = async () => {
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}`, { method: 'DELETE' });
            if (response.ok) {
                closeModal('deleteModal');
                loadUsers();
                loadDashboard();
                showToast('User deleted', 'success');
            } else {
                showToast('Failed to delete user', 'error');
            }
        } catch { showToast('Failed to delete user', 'error'); }
    };
    document.getElementById('deleteConfirmBtn').onclick = deleteCallback;
    openModal('deleteModal');
}

// Force-logout from table action button — shows confirmation dialog first
async function forceLogoutUserById(userId, email) {
    confirmForceLogout(userId, email);
}

// Show force-logout confirmation dialog
function confirmForceLogout(userId, email) {
    document.getElementById('forceLogoutTargetName').textContent = email;
    document.getElementById('forceLogoutConfirmBtn').onclick = async () => {
        // Disable button to prevent double-click
        const btn = document.getElementById('forceLogoutConfirmBtn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i data-lucide="loader"></i> Logging out...';
        renderIcons();

        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}/force-logout`, { method: 'POST' });
            if (response.ok) {
                const data = await response.json();
                closeModal('forceLogoutModal');
                const emailNote = data.email_sent ? ' (notification email sent)' : '';
                showToast(`${email} has been forced offline${emailNote}`, 'success');
                loadUsers();
                loadDashboard();
            } else {
                const data = await response.json();
                showToast(data.detail || 'Failed to force logout', 'error');
            }
        } catch {
            showToast('Failed to force logout', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
            renderIcons();
        }
    };
    openModal('forceLogoutModal');
}

// Force-logout from edit modal — shows confirmation dialog first
async function forceLogoutUser() {
    if (!editingUserId) return;
    const user = users.find(u => u.id === editingUserId);
    const email = user ? user.email : '';
    closeModal('userModal');
    confirmForceLogout(editingUserId, email);
}

// ==================== Bulk User Operations ====================

function toggleSelectAll(masterCb) {
    document.querySelectorAll('.user-select-cb').forEach(cb => {
        cb.checked = masterCb.checked;
        const uid = parseInt(cb.dataset.userId);
        if (masterCb.checked) selectedUserIds.add(uid);
        else selectedUserIds.delete(uid);
    });
    updateBulkBar();
}

function onUserCheckChange() {
    selectedUserIds.clear();
    document.querySelectorAll('.user-select-cb:checked').forEach(cb => {
        selectedUserIds.add(parseInt(cb.dataset.userId));
    });
    // Sync "select all" checkbox
    const allCbs = document.querySelectorAll('.user-select-cb');
    const selectAllCb = document.getElementById('selectAllUsers');
    if (selectAllCb) selectAllCb.checked = allCbs.length > 0 && selectedUserIds.size === allCbs.length;
    updateBulkBar();
}

function updateBulkBar() {
    const bar = document.getElementById('bulkActionsBar');
    if (!bar) return;
    if (selectedUserIds.size > 0) {
        bar.classList.remove('hidden');
        document.getElementById('bulkSelectedCount').textContent = `${selectedUserIds.size} selected`;
    } else {
        bar.classList.add('hidden');
    }
    renderIcons();
}

function clearBulkSelection() {
    selectedUserIds.clear();
    const selectAllCb = document.getElementById('selectAllUsers');
    if (selectAllCb) selectAllCb.checked = false;
    document.querySelectorAll('.user-select-cb').forEach(cb => cb.checked = false);
    updateBulkBar();
}

function bulkAction(action) {
    if (selectedUserIds.size === 0) return;

    const count = selectedUserIds.size;
    const titleEl = document.getElementById('bulkConfirmTitle');
    const msgEl = document.getElementById('bulkConfirmMessage');
    const countEl = document.getElementById('bulkConfirmCount');
    const warnEl = document.getElementById('bulkConfirmWarning');
    const btn = document.getElementById('bulkConfirmBtn');

    if (action === 'delete') {
        titleEl.textContent = 'Bulk Delete Users';
        msgEl.textContent = 'Are you sure you want to permanently delete:';
        countEl.textContent = `${count} user${count > 1 ? 's' : ''}`;
        warnEl.textContent = 'This action cannot be undone.';
        btn.textContent = 'Delete All';
        btn.className = 'btn btn-danger';
    } else if (action === 'force-logout') {
        titleEl.textContent = 'Bulk Force Logout';
        msgEl.textContent = 'Force logout the following users immediately:';
        countEl.textContent = `${count} user${count > 1 ? 's' : ''}`;
        warnEl.textContent = 'All active sessions will be revoked.';
        btn.textContent = 'Force Logout All';
        btn.className = 'btn btn-danger';
    } else if (action === 'set-inactive') {
        titleEl.textContent = 'Set Users Inactive';
        msgEl.textContent = 'Set the following users to inactive:';
        countEl.textContent = `${count} user${count > 1 ? 's' : ''}`;
        warnEl.textContent = 'Users will no longer be able to log in until reactivated.';
        btn.textContent = 'Set Inactive';
        btn.className = 'btn btn-warning';
    }

    btn.onclick = () => executeBulkAction(action);
    openModal('bulkConfirmModal');
}

async function executeBulkAction(action) {
    const btn = document.getElementById('bulkConfirmBtn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Processing...';

    try {
        const response = await fetch(`${API_URL}/admin/users/bulk-action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action, user_ids: Array.from(selectedUserIds) })
        });
        const data = await response.json();

        if (response.ok) {
            closeModal('bulkConfirmModal');
            const extra = data.emails_sent > 0 ? ` (${data.emails_sent} emails sent)` : '';
            showToast(`${data.processed} user${data.processed > 1 ? 's' : ''} — ${action} completed${extra}`, 'success');
            clearBulkSelection();
            loadUsers();
            loadDashboard();
        } else {
            showToast(data.detail || 'Bulk action failed', 'error');
        }
    } catch {
        showToast('Bulk action failed', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

// ==================== Modals ====================

function setupModals() {
    // Use event delegation on document for all modal interactions
    document.addEventListener('click', (e) => {
        // Close button (X) — match the button or anything inside it
        const closeBtn = e.target.closest('.modal-close');
        if (closeBtn) {
            const modal = closeBtn.closest('.modal');
            if (modal) { closeModal(modal.id); }
            return;
        }
        // Click on backdrop (the .modal overlay itself)
        const modal = e.target.closest('.modal');
        if (modal && e.target === modal) {
            closeModal(modal.id);
        }
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.add('show');
    syncModalScrollLock();
    renderIcons();
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.remove('show');
    syncModalScrollLock();
}

function syncModalScrollLock() {
    const hasOpenModal = document.querySelector('.modal.show');
    document.body.classList.toggle('modal-open', !!hasOpenModal);
}

function setupForms() {
    document.getElementById('appForm').addEventListener('submit', (e) => {
        e.preventDefault();
        saveApp();
    });

    document.getElementById('userForm').addEventListener('submit', (e) => {
        e.preventDefault();
        saveUser();
    });
}

// ==================== API Health ====================

async function checkApiHealth() {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');

    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();

        if (data.status === 'healthy') {
            dot.classList.add('online');
            dot.classList.remove('offline');
            text.textContent = 'API Online';
        }
    } catch (error) {
        dot.classList.add('offline');
        dot.classList.remove('online');
        text.textContent = 'API Offline';
    }
}

// Periodically check health
setInterval(checkApiHealth, 30000);

// ==================== Utilities ====================

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const iconName = type === 'success' ? 'check-circle' : type === 'error' ? 'x-circle' : 'info';
    toast.innerHTML = `<i data-lucide="${iconName}"></i> ${escapeHtml(message)}`;
    container.appendChild(toast);
    renderIcons();

    // Use CSS animations for smoother transitions
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 200);
    }, 3000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeAttr(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function filterApps() {
    const search = document.getElementById('appSearch').value.toLowerCase();
    document.querySelectorAll('#appsTableBody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none';
    });
}

function filterUsers() {
    const search = document.getElementById('userSearch').value.toLowerCase();
    document.querySelectorAll('#usersTableBody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none';
    });
}

async function loadAppFilterOptions() {
    const select = document.getElementById('userAppFilter');
    if (!select) return;
    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        apps = await response.json();

        if (apps.length === 0) {
            select.innerHTML = '<option value="">No apps available</option>';
            return;
        }

        // Always default to first app if no filter is selected
        if (!selectedAppFilter || !apps.find(a => a.app_id === selectedAppFilter)) {
            selectedAppFilter = apps[0].app_id;
        }

        select.innerHTML = apps.map(app =>
            `<option value="${escapeAttr(app.app_id)}"${app.app_id === selectedAppFilter ? ' selected' : ''}>${escapeHtml(app.name || 'Unnamed App')}</option>`
        ).join('');
    } catch (error) {
        console.error('Error loading apps for filter:', error);
    }
}

function onAppFilterChange() {
    selectedAppFilter = document.getElementById('userAppFilter').value;
    loadUsers();
}
