// ==================== Apps Management ====================

async function loadApps() {
    const tbody = document.getElementById('appsTableBody');
    const container = tbody.closest('.table-container');
    
    // Show skeleton loading (instant visual feedback)
    tbody.innerHTML = generateTableSkeleton(5, 7);
    if (container) container.classList.add('refreshing');

    try {
        const response = await fetch(`${API_URL}/admin/apps`);
        apps = await response.json();
        
        if (container) container.classList.remove('refreshing');

        if (apps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No applications yet. Create your first app.</td></tr>';
            return;
        }

        tbody.innerHTML = apps.map(app => {
            const safeAppId = escapeAttr(app.app_id);
            const safeName = escapeAttr(app.name || 'Unnamed');
            const safeLogo = escapeAttr(app.logo_url || DEFAULT_APP_LOGO);
            return `
            <tr class="new-row">
                <td data-label="Name" class="app-name-cell">
                    <span class="app-name-wrap">
                        <img class="app-name-logo" src="${safeLogo}" alt="${safeName} logo" onerror="this.onerror=null;this.src='${DEFAULT_APP_LOGO}'">
                        <span>${escapeHtml(app.name || 'Unnamed')}</span>
                    </span>
                </td>
                <td data-label="App ID"><code>${app.app_id}</code></td>
                <td data-label="OTP"><span class="status-badge ${app.otp_enabled ? 'active' : 'inactive'}">${app.otp_enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td data-label="Passkey"><span class="status-badge ${app.passkey_enabled ? 'active' : 'inactive'}">${app.passkey_enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td data-label="Notification"><span class="status-badge ${app.login_notification_enabled ? 'active' : 'inactive'}">${app.login_notification_enabled ? 'On' : 'Off'}</span></td>
                <td data-label="Created">${formatDate(app.created_at)}</td>
                <td data-label="Actions">
                    <div class="action-btns">
                        <button class="btn-icon" data-action="credentials" data-app-id="${safeAppId}" title="View Credentials">
                            <i data-lucide="key-round"></i>
                        </button>
                        <button class="btn-icon" data-action="edit-app" data-app-id="${safeAppId}" title="Settings">
                            <i data-lucide="settings-2"></i>
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
        tbody.innerHTML = '<tr><td colspan="7" class="loading">Failed to load applications</td></tr>';
    }
}

function parseRedirectUriCsv(csv) {
    if (!csv) return [];
    return csv
        .split(',')
        .map((uri) => uri.trim())
        .filter(Boolean);
}

function removeRedirectUriRow(buttonEl) {
    const row = buttonEl.closest('.redirect-uri-item');
    if (!row) return;
    const list = document.getElementById('redirectUriList');
    if (!list) return;

    const rows = list.querySelectorAll('.redirect-uri-item');
    if (rows.length <= 1) {
        const input = row.querySelector('input');
        if (input) input.value = '';
        return;
    }

    row.remove();
}

function addRedirectUriRow(value = '') {
    const list = document.getElementById('redirectUriList');
    if (!list) return;

    const item = document.createElement('div');
    item.className = 'redirect-uri-item';
    item.innerHTML = `
        <input type="url" class="redirect-uri-input" placeholder="https://your-app.com/callback" value="${escapeAttr(value)}">
        <button type="button" class="btn-icon danger redirect-uri-remove" onclick="removeRedirectUriRow(this)" aria-label="Remove redirect URI" title="Remove URI">
            <span aria-hidden="true">-</span>
        </button>
    `;
    list.appendChild(item);
}

function setRedirectUriValues(csv) {
    const list = document.getElementById('redirectUriList');
    if (!list) return;
    list.innerHTML = '';

    const uris = parseRedirectUriCsv(csv);
    if (!uris.length) {
        addRedirectUriRow('');
        return;
    }

    uris.forEach((uri) => addRedirectUriRow(uri));
}

function getRedirectUriCsv() {
    const list = document.getElementById('redirectUriList');
    if (!list) return '';
    const values = Array.from(list.querySelectorAll('.redirect-uri-input'))
        .map((input) => input.value.trim())
        .filter(Boolean);
    return values.join(',');
}

function showCreateAppModal() {
    editingAppId = null;
    document.getElementById('appModalTitle').textContent = 'Create Application';
    document.getElementById('appFormSubmit').textContent = 'Create App';
    document.getElementById('appForm').reset();
    document.getElementById('appOAuthEnabled').checked = true;
    document.getElementById('appOtpEnabled').checked = true;
    document.getElementById('appPasskeyEnabled').checked = false;
    document.getElementById('appLoginNotification').checked = false;
    document.getElementById('appForceLogoutNotification').checked = false;
    document.getElementById('appAccessTokenExpiry').value = 30;
    document.getElementById('appRefreshTokenExpiry').value = 7;
    setRedirectUriValues('');
    resetAppLogoEditor('');
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
    document.getElementById('appOAuthEnabled').checked = app.oauth_enabled !== false;
    document.getElementById('appOtpEnabled').checked = !!app.otp_enabled;
    document.getElementById('appPasskeyEnabled').checked = !!app.passkey_enabled;
    document.getElementById('appLoginNotification').checked = !!app.login_notification_enabled;
    document.getElementById('appForceLogoutNotification').checked = !!app.force_logout_notification_enabled;
    document.getElementById('appAccessTokenExpiry').value = app.access_token_expiry_minutes || 30;
    document.getElementById('appRefreshTokenExpiry').value = app.refresh_token_expiry_days || 7;
    setRedirectUriValues(app.redirect_uris || '');
    resetAppLogoEditor(app.logo_url || '');
    openModal('appModal');
}

async function saveApp() {
    const name = document.getElementById('appName').value.trim();
    const description = document.getElementById('appDescription').value.trim();
    const oauth_enabled = document.getElementById('appOAuthEnabled').checked;
    const otp_enabled = document.getElementById('appOtpEnabled').checked;
    const passkey_enabled = document.getElementById('appPasskeyEnabled').checked;
    const login_notification_enabled = document.getElementById('appLoginNotification').checked;
    const force_logout_notification_enabled = document.getElementById('appForceLogoutNotification').checked;
    const access_token_expiry_minutes = parseInt(document.getElementById('appAccessTokenExpiry').value) || 30;
    const refresh_token_expiry_days = parseInt(document.getElementById('appRefreshTokenExpiry').value) || 7;
    const redirect_uris = getRedirectUriCsv();
    const logo_url = document.getElementById('appLogoUrl').value.trim();
    const submitBtn = document.getElementById('appFormSubmit');
    const originalBtnHtml = submitBtn.innerHTML;

    if (!name) { showToast('Please enter an app name', 'error'); return; }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="btn-inline-spinner" aria-hidden="true"></span>${editingAppId ? 'Saving...' : 'Adding...'} `;

    try {
        const body = { name, description, oauth_enabled, otp_enabled, passkey_enabled, login_notification_enabled, force_logout_notification_enabled, access_token_expiry_minutes, refresh_token_expiry_days };
        if (redirect_uris) body.redirect_uris = redirect_uris;
        if (editingAppId || logo_url) {
            body.logo_url = logo_url;
        }

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
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnHtml;
        renderIcons();
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
    const warningEl = document.querySelector('#deleteModal .delete-warning');
    if (warningEl) {
        warningEl.textContent = 'This action cannot be undone.';
    }
    deleteCallback = async () => {
        const deleteBtn = document.getElementById('deleteConfirmBtn');
        const originalHtml = deleteBtn.innerHTML;
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Deleting...';
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
        } catch {
            showToast('Failed to delete application', 'error');
        } finally {
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = originalHtml;
            renderIcons();
        }
    };
    document.getElementById('deleteConfirmBtn').onclick = deleteCallback;
    openModal('deleteModal');
}

