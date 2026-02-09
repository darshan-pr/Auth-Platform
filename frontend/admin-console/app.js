const API_URL = 'http://localhost:8000';

// State
let currentPage = 'dashboard';
let apps = [];
let users = [];
let editingAppId = null;
let editingUserId = null;
let deletingAppId = null;
let deletingUserId = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupModals();
    setupForms();
    checkApiHealth();
    loadDashboard();
});

// ==================== Navigation ====================

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            navigateTo(page);
        });
    });
}

function navigateTo(page) {
    currentPage = page;
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `${page}Page`);
    });
    
    // Load data for page
    switch(page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'apps':
            loadApps();
            break;
        case 'users':
            loadUsers();
            break;
    }
}

// ==================== Dashboard ====================

async function loadDashboard() {
    try {
        const response = await fetch(`${API_URL}/admin/stats`);
        if (response.ok) {
            const stats = await response.json();
            document.getElementById('totalApps').textContent = stats.total_apps || 0;
            document.getElementById('totalUsers').textContent = stats.total_users || 0;
            document.getElementById('activeUsers').textContent = stats.active_users || 0;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// ==================== Apps Management ====================

async function loadApps() {
    const tbody = document.getElementById('appsTableBody');
    tbody.innerHTML = '<tr><td colspan="6" class="loading">Loading applications...</td></tr>';

    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        apps = await response.json();

        if (apps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading">No applications yet. Create your first app!</td></tr>';
            return;
        }

        tbody.innerHTML = apps.map(app => `
            <tr>
                <td><strong>${escapeHtml(app.name || 'Unnamed')}</strong></td>
                <td><code>${app.app_id}</code></td>
                <td><span class="status-badge ${app.otp_enabled ? 'active' : 'inactive'}">${app.otp_enabled ? 'OTP On' : 'OTP Off'}</span></td>
                <td>${app.access_token_expiry_minutes}m / ${app.refresh_token_expiry_days}d</td>
                <td>${formatDate(app.created_at)}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" onclick="showCredentials('${app.app_id}')" title="View Credentials">🔑</button>
                        <button class="btn-icon" onclick="editApp('${app.app_id}')" title="Edit">✏️</button>
                        <button class="btn-icon" onclick="confirmDeleteApp('${app.app_id}', '${escapeHtml(app.name)}')" title="Delete">🗑️</button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading apps:', error);
        tbody.innerHTML = '<tr><td colspan="6" class="loading">Failed to load applications</td></tr>';
    }
}

function showCreateAppModal() {
    editingAppId = null;
    document.getElementById('appModalTitle').textContent = 'Create New Application';
    document.getElementById('appForm').reset();
    // Set defaults for new app
    document.getElementById('appOtpEnabled').checked = true;
    document.getElementById('appAccessTokenExpiry').value = 30;
    document.getElementById('appRefreshTokenExpiry').value = 7;
    openModal('appModal');
}

function editApp(appId) {
    const app = apps.find(a => a.app_id === appId);
    if (!app) return;
    
    editingAppId = appId;
    document.getElementById('appModalTitle').textContent = 'Edit Application';
    document.getElementById('appName').value = app.name || '';
    document.getElementById('appDescription').value = app.description || '';
    document.getElementById('appOtpEnabled').checked = app.otp_enabled !== false;
    document.getElementById('appAccessTokenExpiry').value = app.access_token_expiry_minutes || 30;
    document.getElementById('appRefreshTokenExpiry').value = app.refresh_token_expiry_days || 7;
    openModal('appModal');
}

async function saveApp() {
    const name = document.getElementById('appName').value.trim();
    const description = document.getElementById('appDescription').value.trim();
    const otp_enabled = document.getElementById('appOtpEnabled').checked;
    const access_token_expiry_minutes = parseInt(document.getElementById('appAccessTokenExpiry').value) || 30;
    const refresh_token_expiry_days = parseInt(document.getElementById('appRefreshTokenExpiry').value) || 7;

    if (!name) {
        showToast('Please enter an app name', 'error');
        return;
    }

    try {
        let response;
        if (editingAppId) {
            // Update existing app
            response = await fetch(`${API_URL}/admin/apps/${editingAppId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description, otp_enabled, access_token_expiry_minutes, refresh_token_expiry_days })
            });
        } else {
            // Create new app
            response = await fetch(`${API_URL}/admin/apps`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description, otp_enabled, access_token_expiry_minutes, refresh_token_expiry_days })
            });
        }

        const data = await response.json();

        if (response.ok) {
            closeModal('appModal');
            
            if (!editingAppId && data.app_id && data.app_secret) {
                // Show credentials for new app
                document.getElementById('credAppId').textContent = data.app_id;
                document.getElementById('credAppSecret').textContent = data.app_secret;
                openModal('credentialsModal');
            }
            
            loadApps();
            loadDashboard();
            showToast(editingAppId ? 'Application updated!' : 'Application created!', 'success');
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
    deletingAppId = appId;
    document.getElementById('deleteAppName').textContent = appName;
    openModal('deleteAppModal');
}

async function deleteApp() {
    if (!deletingAppId) return;

    try {
        const response = await fetch(`${API_URL}/admin/apps/${deletingAppId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            closeModal('deleteAppModal');
            loadApps();
            loadDashboard();
            showToast('Application deleted', 'success');
        } else {
            showToast('Failed to delete application', 'error');
        }
    } catch (error) {
        showToast('Failed to delete application', 'error');
    }
    
    deletingAppId = null;
}

// ==================== Users Management ====================

async function loadUsers() {
    const tbody = document.getElementById('usersTableBody');
    tbody.innerHTML = '<tr><td colspan="5" class="loading">Loading users...</td></tr>';

    try {
        const response = await fetch(`${API_URL}/admin/users`);
        const data = await response.json();
        
        // Handle both array and object with users array
        users = Array.isArray(data) ? data : (data.users || []);

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading">No users yet.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => `
            <tr>
                <td><strong>${escapeHtml(user.email)}</strong></td>
                <td><code>${user.app_id || 'None'}</code></td>
                <td><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
                <td>${formatDate(user.created_at)}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" onclick="editUser(${user.id})" title="Edit">✏️</button>
                        <button class="btn-icon" onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.email)}')" title="Delete">🗑️</button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = '<tr><td colspan="5" class="loading">Failed to load users</td></tr>';
    }
}

function showCreateUserModal() {
    editingUserId = null;
    document.getElementById('userModalTitle').textContent = 'Add New User';
    document.getElementById('userForm').reset();
    document.getElementById('userAppId').disabled = false;
    loadAppsForSelect();
    openModal('userModal');
}

async function loadAppsForSelect() {
    const select = document.getElementById('userAppId');
    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        const apps = await response.json();
        select.innerHTML = apps.map(app => 
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
    document.getElementById('userEmail').value = user.email;
    document.getElementById('userAppId').value = user.app_id;
    document.getElementById('userAppId').disabled = true;
    loadAppsForSelect();
    openModal('userModal');
}

async function saveUser() {
    const email = document.getElementById('userEmail').value.trim();
    const app_id = document.getElementById('userAppId').value;

    if (!email) {
        showToast('Please enter an email', 'error');
        return;
    }

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
            showToast(editingUserId ? 'User updated!' : 'User created!', 'success');
        } else {
            showToast(data.detail || 'Operation failed', 'error');
        }
    } catch (error) {
        showToast('Failed to save user', 'error');
    }
}

function confirmDeleteUser(userId, email) {
    deletingUserId = userId;
    document.getElementById('deleteUserEmail').textContent = email;
    openModal('deleteUserModal');
}

async function deleteUser() {
    if (!deletingUserId) return;

    try {
        const response = await fetch(`${API_URL}/admin/users/${deletingUserId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            closeModal('deleteUserModal');
            loadUsers();
            loadDashboard();
            showToast('User deleted', 'success');
        } else {
            showToast('Failed to delete user', 'error');
        }
    } catch (error) {
        showToast('Failed to delete user', 'error');
    }
    
    deletingUserId = null;
}

// ==================== Modals ====================

function setupModals() {
    // Close modal when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });
    
    // Close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            if (modal) closeModal(modal.id);
        });
    });
}

function openModal(modalId) {
    document.getElementById(modalId).classList.add('show');
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

// ==================== Utilities ====================

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => toast.remove(), 3000);
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

// Search functionality
function filterApps() {
    const search = document.getElementById('appSearch').value.toLowerCase();
    const rows = document.querySelectorAll('#appsTableBody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(search) ? '' : 'none';
    });
}

function filterUsers() {
    const search = document.getElementById('userSearch').value.toLowerCase();
    const rows = document.querySelectorAll('#usersTableBody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(search) ? '' : 'none';
    });
}
