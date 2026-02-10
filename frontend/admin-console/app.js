const API_URL = 'http://localhost:8000';

// Admin password (SHA-256 hash of "Darsh@26")
const ADMIN_PASSWORD_HASH = '713942dda7199acdaed4b307423db76a90185e005c38a668d28743c38a84a94f';

// State
let currentPage = 'dashboard';
let apps = [];
let users = [];
let editingAppId = null;
let editingUserId = null;
let deleteCallback = null;

// ==================== Init ====================

document.addEventListener('DOMContentLoaded', () => {
    renderIcons();
    checkSession();
    
    // Auto-render icons when DOM changes (more robust)
    const observer = new MutationObserver(() => {
        renderIcons();
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

function renderIcons() {
    if (typeof lucide !== 'undefined') {
        // Use setTimeout to ensure DOM is fully updated
        setTimeout(() => {
            lucide.createIcons();
        }, 0);
    }
}

// ==================== Auth Gate ====================

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function checkSession() {
    const session = sessionStorage.getItem('admin_authenticated');
    if (session === 'true') {
        showApp();
    } else {
        showLogin();
    }
}

function showLogin() {
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('appContainer').classList.add('hidden');
    renderIcons();

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('loginPassword').value;
        const hash = await hashPassword(password);

        if (hash === ADMIN_PASSWORD_HASH) {
            sessionStorage.setItem('admin_authenticated', 'true');
            document.getElementById('loginError').classList.add('hidden');
            showApp();
        } else {
            document.getElementById('loginError').classList.remove('hidden');
            document.getElementById('loginPassword').value = '';
            document.getElementById('loginPassword').focus();
        }
    });
}

function showApp() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('appContainer').classList.remove('hidden');
    setupNavigation();
    setupModals();
    setupForms();
    checkApiHealth();
    loadDashboard();
    renderIcons();
}

function adminLogout() {
    sessionStorage.removeItem('admin_authenticated');
    location.reload();
}

function togglePasswordVisibility() {
    const input = document.getElementById('loginPassword');
    const icon = document.getElementById('eyeIcon');
    if (input.type === 'password') {
        input.type = 'text';
        icon.setAttribute('data-lucide', 'eye-off');
    } else {
        input.type = 'password';
        icon.setAttribute('data-lucide', 'eye');
    }
    renderIcons();
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
    currentPage = page;

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `${page}Page`);
    });

    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'apps':      loadApps();      break;
        case 'users':     loadUsers();     break;
    }
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
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function animateValue(elementId, target) {
    const el = document.getElementById(elementId);
    const current = parseInt(el.textContent) || 0;
    if (current === target) { el.textContent = target; return; }

    const duration = 400;
    const start = performance.now();

    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(current + (target - current) * eased);
        if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
}

// ==================== Apps Management ====================

async function loadApps() {
    const tbody = document.getElementById('appsTableBody');
    tbody.innerHTML = '<tr><td colspan="7" class="loading">Loading applications...</td></tr>';

    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        apps = await response.json();

        if (apps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No applications yet. Create your first app.</td></tr>';
            return;
        }

        tbody.innerHTML = apps.map(app => `
            <tr>
                <td class="app-name-cell">${escapeHtml(app.name || 'Unnamed')}</td>
                <td><code>${app.app_id}</code></td>
                <td><span class="status-badge ${app.otp_enabled ? 'active' : 'inactive'}">${app.otp_enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td>${app.access_token_expiry_minutes}m / ${app.refresh_token_expiry_days}d</td>
                <td class="redirect-uris">${app.redirect_uris ? escapeHtml(app.redirect_uris) : '<span style="color:#94a3b8">Not set</span>'}</td>
                <td>${formatDate(app.created_at)}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" onclick="showCredentials('${app.app_id}')" title="View Credentials">
                            <i data-lucide="key-round"></i>
                        </button>
                        <button class="btn-icon" onclick="editApp('${app.app_id}')" title="Edit">
                            <i data-lucide="pencil"></i>
                        </button>
                        <button class="btn-icon danger" onclick="confirmDeleteApp('${app.app_id}', '${escapeHtml(app.name)}')" title="Delete">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
        renderIcons();
    } catch (error) {
        console.error('Error loading apps:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="loading">Failed to load applications</td></tr>';
    }
}

function showCreateAppModal() {
    editingAppId = null;
    document.getElementById('appModalTitle').textContent = 'Create Application';
    document.getElementById('appFormSubmit').textContent = 'Create App';
    document.getElementById('appForm').reset();
    document.getElementById('appOtpEnabled').checked = true;
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
    document.getElementById('appOtpEnabled').checked = app.otp_enabled !== false;
    document.getElementById('appAccessTokenExpiry').value = app.access_token_expiry_minutes || 30;
    document.getElementById('appRefreshTokenExpiry').value = app.refresh_token_expiry_days || 7;
    document.getElementById('appRedirectUris').value = app.redirect_uris || '';
    openModal('appModal');
}

async function saveApp() {
    const name = document.getElementById('appName').value.trim();
    const description = document.getElementById('appDescription').value.trim();
    const otp_enabled = document.getElementById('appOtpEnabled').checked;
    const access_token_expiry_minutes = parseInt(document.getElementById('appAccessTokenExpiry').value) || 30;
    const refresh_token_expiry_days = parseInt(document.getElementById('appRefreshTokenExpiry').value) || 7;
    const redirect_uris = document.getElementById('appRedirectUris').value.trim();

    if (!name) { showToast('Please enter an app name', 'error'); return; }

    try {
        const body = { name, description, otp_enabled, access_token_expiry_minutes, refresh_token_expiry_days };
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
                showToast('Application deleted', 'success');
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
    tbody.innerHTML = '<tr><td colspan="5" class="loading">Loading users...</td></tr>';

    try {
        const response = await fetch(`${API_URL}/admin/users`);
        const data = await response.json();
        users = Array.isArray(data) ? data : (data.users || []);

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading">No users yet.</td></tr>';
            return;
        }

        // Map app_ids to names for display
        const appMap = {};
        apps.forEach(a => { appMap[a.app_id] = a.name; });

        tbody.innerHTML = users.map(user => `
            <tr>
                <td class="app-name-cell">${escapeHtml(user.email)}</td>
                <td>${user.app_id ? `<code>${user.app_id}</code>` : '<span style="color:#94a3b8">None</span>'}</td>
                <td><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
                <td>${formatDate(user.created_at)}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" onclick="editUser(${user.id})" title="Edit">
                            <i data-lucide="pencil"></i>
                        </button>
                        <button class="btn-icon danger" onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.email)}')" title="Delete">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
        renderIcons();
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = '<tr><td colspan="5" class="loading">Failed to load users</td></tr>';
    }
}

function showCreateUserModal() {
    editingUserId = null;
    document.getElementById('userModalTitle').textContent = 'Add New User';
    document.getElementById('userFormSubmit').textContent = 'Add User';
    document.getElementById('userForm').reset();
    document.getElementById('userAppId').disabled = false;
    document.getElementById('userStatusGroup').classList.add('hidden');
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
    document.getElementById('userAppId').value = user.app_id;
    document.getElementById('userAppId').disabled = true;
    document.getElementById('userStatusGroup').classList.remove('hidden');
    loadAppsForSelect();
    openModal('userModal');
}

async function saveUser() {
    const email = document.getElementById('userEmail').value.trim();
    const app_id = document.getElementById('userAppId').value;

    if (!email) { showToast('Please enter an email', 'error'); return; }

    try {
        let response;
        if (editingUserId) {
            response = await fetch(`${API_URL}/admin/users/${editingUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
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

// ==================== Modals ====================

function setupModals() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal.id);
        });
    });

    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            if (modal) closeModal(modal.id);
        });
    });
}

function openModal(modalId) {
    document.getElementById(modalId).classList.add('show');
    // Re-render icons after modal opens
    setTimeout(() => renderIcons(), 10);
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('show');
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
        const response = await fetch(`${API_URL}/`);
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

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
