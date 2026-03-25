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
    document.getElementById('userForm').reset();
    document.getElementById('userEmail').disabled = false;
    document.getElementById('userAppId').disabled = false;
    document.getElementById('userStatusGroup').classList.add('hidden');
    document.getElementById('bulkCsvPanel').classList.remove('hidden');
    const modeSwitch = document.getElementById('userAddModeSwitch');
    if (modeSwitch) modeSwitch.classList.remove('hidden');
    if (!csvUploadState.running) {
        resetCsvUploadState();
        setUserAddMode('single');
    } else {
        setUserAddMode('multiple');
        syncCsvProgressUi();
    }
    updateUserModalPrimaryAction();
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
    document.getElementById('userEmail').value = user.email;
    document.getElementById('userEmail').disabled = true;
    document.getElementById('userAppId').disabled = true;
    document.getElementById('userStatusGroup').classList.remove('hidden');
    document.getElementById('bulkCsvPanel').classList.add('hidden');
    document.getElementById('singleUserPanel').classList.remove('hidden');
    const modeSwitch = document.getElementById('userAddModeSwitch');
    if (modeSwitch) modeSwitch.classList.add('hidden');
    userAddMode = 'single';
    updateUserModalPrimaryAction();
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
    const submitBtn = document.getElementById('userFormSubmit');
    const originalBtnHtml = submitBtn.innerHTML;

    if (!email) { showToast('Please enter an email', 'error'); return; }
    if (!app_id) { showToast('Please select an application', 'error'); return; }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="btn-inline-spinner" aria-hidden="true"></span>${editingUserId ? 'Saving...' : 'Adding...'} `;

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
            if (!editingUserId) {
                resetCsvUploadState();
            }
        } else {
            showToast(data.detail || 'Operation failed', 'error');
        }
    } catch (error) {
        showToast('Failed to save user', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnHtml;
        renderIcons();
    }
}

function confirmDeleteUser(userId, email) {
    document.getElementById('deleteTargetName').textContent = email;
    const warningEl = document.querySelector('#deleteModal .delete-warning');
    const user = users.find(u => u.id === userId);
    const shouldForceLogout = !!(user && user.is_online);
    if (warningEl) {
        warningEl.textContent = shouldForceLogout
            ? 'User is online. Active sessions will be revoked first, then permanently deleted.'
            : 'User is offline. User will be permanently deleted.';
    }
    deleteCallback = async () => {
        const deleteBtn = document.getElementById('deleteConfirmBtn');
        const originalHtml = deleteBtn.innerHTML;
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Deleting...';
        try {
            if (shouldForceLogout) {
                await fetch(`${API_URL}/admin/users/${userId}/force-logout`, { method: 'POST' });
            }
            const response = await fetch(`${API_URL}/admin/users/${userId}`, { method: 'DELETE' });
            if (response.ok) {
                closeModal('deleteModal');
                loadUsers();
                loadDashboard();
                showToast('User deleted', 'success');
            } else {
                showToast('Failed to delete user', 'error');
            }
        } catch {
            showToast('Failed to delete user', 'error');
        } finally {
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = originalHtml;
            renderIcons();
        }
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
        const btn = document.getElementById('forceLogoutConfirmBtn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Forcing logout...';

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
        msgEl.textContent = 'Delete the following users after forcing them offline:';
        countEl.textContent = `${count} user${count > 1 ? 's' : ''}`;
        warnEl.textContent = 'Sessions are revoked first. Deletion cannot be undone.';
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
        if (action === 'delete') {
            const ids = Array.from(selectedUserIds);
            let processed = 0;

            for (const id of ids) {
                const target = users.find(u => u.id === id);
                if (target && target.is_online) {
                    await fetch(`${API_URL}/admin/users/${id}/force-logout`, { method: 'POST' });
                }
                const delRes = await fetch(`${API_URL}/admin/users/${id}`, { method: 'DELETE' });
                if (delRes.ok) processed += 1;
            }

            closeModal('bulkConfirmModal');
            showToast(`${processed} user${processed !== 1 ? 's' : ''} deleted (force logout done first)`, 'success');
            clearBulkSelection();
            loadUsers();
            loadDashboard();
            return;
        }

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
        if (!editingUserId && userAddMode === 'multiple') {
            uploadUsersFromCsv();
            return;
        }
        saveUser();
    });

    const csvInput = document.getElementById('bulkUserCsvFile');
    if (csvInput) {
        csvInput.addEventListener('change', onCsvFileSelected);
    }

    const appLogoUrl = document.getElementById('appLogoUrl');
    const appLogoPreviewBtn = document.getElementById('appLogoPreviewBtn');
    const addRedirectUriBtn = document.getElementById('addRedirectUriBtn');

    if (appLogoUrl) {
        appLogoUrl.addEventListener('input', () => {
            const url = appLogoUrl.value.trim();
            setAppLogoPreview(url || DEFAULT_APP_LOGO);
        });
    }

    if (appLogoPreviewBtn && appLogoUrl) {
        appLogoPreviewBtn.addEventListener('click', () => {
            const url = appLogoUrl.value.trim();
            setAppLogoPreview(url || DEFAULT_APP_LOGO);
        });
    }

    if (addRedirectUriBtn) {
        addRedirectUriBtn.addEventListener('click', () => addRedirectUriRow(''));
    }
}

function setAppLogoPreview(src) {
    const preview = document.getElementById('appLogoPreview');
    if (!preview) return;
    preview.onerror = function () {
        this.onerror = null;
        this.src = DEFAULT_APP_LOGO;
    };
    preview.src = src || DEFAULT_APP_LOGO;
}

function resetAppLogoEditor(logoUrl = '') {
    const appLogoUrlInput = document.getElementById('appLogoUrl');
    if (appLogoUrlInput) appLogoUrlInput.value = logoUrl || '';
    setAppLogoPreview(logoUrl || DEFAULT_APP_LOGO);
}

// ==================== Bulk CSV Upload ====================

function updateUserModalPrimaryAction() {
    const submitBtn = document.getElementById('userFormSubmit');
    if (!submitBtn) return;

    if (editingUserId) {
        submitBtn.textContent = 'Save Changes';
        submitBtn.disabled = false;
        return;
    }

    if (csvUploadState.running) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Adding...';
        return;
    }

    if (userAddMode === 'multiple') {
        submitBtn.disabled = parsedCsvUsers.length === 0;
        submitBtn.innerHTML = 'Add From CSV';
        return;
    }

    submitBtn.disabled = false;
    submitBtn.innerHTML = 'Add User';
}

function setCloseWhileAddingVisible(visible) {
    const closeBtn = document.getElementById('userModalCloseWhileAddingBtn');
    if (!closeBtn) return;
    closeBtn.classList.toggle('hidden', !visible);
}

function resetCsvUploadState() {
    parsedCsvUsers = [];
    csvUploadState = {
        running: false,
        total: 0,
        processed: 0,
        added: 0,
        failed: 0
    };
    const summary = document.getElementById('bulkCsvSummary');
    const input = document.getElementById('bulkUserCsvFile');
    const fileName = document.getElementById('bulkUserCsvFileName');
    const submitBtn = document.getElementById('userFormSubmit');
    const list = document.getElementById('bulkCsvList');
    const bar = document.getElementById('bulkCsvProgressBar');
    if (summary) summary.textContent = 'Select a CSV file to preview users.';
    if (submitBtn && !editingUserId && userAddMode !== 'multiple') submitBtn.disabled = false;
    if (input) input.value = '';
    if (fileName) fileName.textContent = 'No file chosen';
    if (list) list.innerHTML = '<div class="bulk-csv-list-empty">No users loaded yet.</div>';
    if (bar) bar.style.width = '0%';
    setCloseWhileAddingVisible(false);
    updateUserModalPrimaryAction();
    updateAddUserButtonProgress();
}

function setUserAddMode(mode) {
    const singlePanel = document.getElementById('singleUserPanel');
    const bulkPanel = document.getElementById('bulkCsvPanel');
    const singleBtn = document.getElementById('userModeSingleBtn');
    const multipleBtn = document.getElementById('userModeMultipleBtn');
    if (!singlePanel || !bulkPanel || !singleBtn || !multipleBtn) return;

    userAddMode = mode === 'multiple' ? 'multiple' : 'single';

    const isMultiple = userAddMode === 'multiple';
    singlePanel.classList.toggle('hidden', isMultiple);
    bulkPanel.classList.toggle('hidden', !isMultiple);
    singleBtn.classList.toggle('active', !isMultiple);
    multipleBtn.classList.toggle('active', isMultiple);

    const emailInput = document.getElementById('userEmail');
    if (emailInput && !editingUserId) {
        emailInput.required = !isMultiple;
    }

    updateUserModalPrimaryAction();

    renderIcons();
}

async function onCsvFileSelected(event) {
    const file = event.target.files && event.target.files[0];
    const summary = document.getElementById('bulkCsvSummary');
    const fileName = document.getElementById('bulkUserCsvFileName');
    parsedCsvUsers = [];

    if (!file) {
        if (summary) summary.textContent = 'Select a CSV file to preview users.';
        if (fileName) fileName.textContent = 'No file chosen';
        updateUserModalPrimaryAction();
        return;
    }

    if (fileName) fileName.textContent = file.name;

    try {
        const text = await file.text();
        const parsed = parseUsersCsv(text);
        parsedCsvUsers = parsed.rows;

        const valid = parsed.rows.length;
        const skipped = parsed.skipped;
        if (summary) {
            summary.textContent = `Loaded ${valid} valid user${valid !== 1 ? 's' : ''}${skipped ? `, skipped ${skipped} row${skipped !== 1 ? 's' : ''}` : ''}.`;
        }
        renderCsvUserList();
        syncCsvProgressUi();
        updateUserModalPrimaryAction();
    } catch (err) {
        if (summary) summary.textContent = 'Invalid CSV format. Use headers: email, app_id';
        if (fileName) fileName.textContent = file.name;
        showToast('Could not read CSV file', 'error');
        updateUserModalPrimaryAction();
    }
}

function parseUsersCsv(text) {
    const lines = text
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    if (lines.length < 2) {
        return { rows: [], skipped: 0 };
    }

    const header = parseCsvLine(lines[0]).map(h => h.trim().toLowerCase());
    const emailIndex = header.indexOf('email');
    const appIdIndex = header.indexOf('app_id');
    if (emailIndex === -1) {
        throw new Error('Missing email header');
    }

    const rows = [];
    let skipped = 0;
    for (let i = 1; i < lines.length; i++) {
        const cols = parseCsvLine(lines[i]);
        const email = (cols[emailIndex] || '').trim();
        const app_id = appIdIndex >= 0 ? (cols[appIdIndex] || '').trim() : '';
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            skipped += 1;
            continue;
        }
        rows.push({ email, app_id, status: 'pending', message: '' });
    }

    return { rows, skipped };
}

function renderCsvUserList() {
    const list = document.getElementById('bulkCsvList');
    if (!list) return;

    if (!parsedCsvUsers.length) {
        list.innerHTML = '<div class="bulk-csv-list-empty">No users loaded yet.</div>';
        return;
    }

    list.innerHTML = parsedCsvUsers.map((row) => {
        const appLabel = row.app_id || 'Use selected app';
        const statusClass = row.status || 'pending';
        const statusLabel = row.status === 'added'
            ? '✓ Added'
            : row.status === 'failed'
                ? '✗ Failed'
                : row.status === 'adding'
                    ? 'Adding...'
                    : 'Pending';
        const messageAttr = row.message ? ` title="${escapeAttr(row.message)}"` : '';

        return `
            <div class="bulk-csv-user-row">
                <span class="bulk-csv-user-email">${escapeHtml(row.email)}</span>
                <span class="bulk-csv-user-app">${escapeHtml(appLabel)}</span>
                <span class="bulk-csv-user-status ${statusClass}"${messageAttr}>${statusLabel}</span>
            </div>
        `;
    }).join('');
}

function syncCsvProgressUi() {
    const bar = document.getElementById('bulkCsvProgressBar');
    const summary = document.getElementById('bulkCsvSummary');
    const total = csvUploadState.total || parsedCsvUsers.length || 0;
    const processed = csvUploadState.processed || 0;
    const added = csvUploadState.added || 0;
    const failed = csvUploadState.failed || 0;
    const pct = total > 0 ? Math.round((processed / total) * 100) : 0;

    if (bar) {
        bar.style.width = `${pct}%`;
    }

    if (summary && total > 0 && (csvUploadState.running || processed > 0 || added > 0 || failed > 0)) {
        if (csvUploadState.running) {
            summary.textContent = `Background add running: ${processed}/${total} processed, ${added} added, ${failed} failed.`;
        } else {
            summary.textContent = `Completed: ${added}/${total} added, ${failed} failed.`;
        }
    }

    setCloseWhileAddingVisible(csvUploadState.running);
    updateUserModalPrimaryAction();
    updateAddUserButtonProgress();
}

function updateAddUserButtonProgress() {
    const openBtn = document.getElementById('openAddUserBtn');
    if (!openBtn) return;

    if (csvUploadState.running && csvUploadState.total > 0) {
        openBtn.innerHTML = `<span class="btn-inline-spinner" aria-hidden="true"></span>Adding ${csvUploadState.processed}/${csvUploadState.total}`;
        return;
    }

    if (!csvUploadState.running && csvUploadState.total > 0 && csvUploadState.processed === csvUploadState.total) {
        openBtn.innerHTML = `<i data-lucide="check-circle"></i> Added ${csvUploadState.added}/${csvUploadState.total}`;
        renderIcons();
        if (csvUploadBtnResetTimer) clearTimeout(csvUploadBtnResetTimer);
        csvUploadBtnResetTimer = setTimeout(() => {
            const btn = document.getElementById('openAddUserBtn');
            if (btn && !csvUploadState.running) {
                btn.innerHTML = '<i data-lucide="user-plus"></i> Add User';
                renderIcons();
            }
        }, 3500);
        return;
    }

    openBtn.innerHTML = '<i data-lucide="user-plus"></i> Add User';
    renderIcons();
}

function parseCsvLine(line) {
    const result = [];
    let value = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            if (inQuotes && line[i + 1] === '"') {
                value += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (ch === ',' && !inQuotes) {
            result.push(value);
            value = '';
        } else {
            value += ch;
        }
    }
    result.push(value);
    return result;
}

async function uploadUsersFromCsv() {
    if (!parsedCsvUsers.length) {
        showToast('No valid CSV users to upload', 'error');
        return;
    }

    const defaultAppId = document.getElementById('userAppId').value;

    if (!defaultAppId) {
        showToast('Select an application for rows without app_id', 'error');
        return;
    }

    if (csvUploadState.running) {
        showToast('CSV upload already in progress', 'info');
        return;
    }

    csvUploadState = {
        running: true,
        total: parsedCsvUsers.length,
        processed: 0,
        added: 0,
        failed: 0
    };

    parsedCsvUsers.forEach(row => {
        row.status = 'pending';
        row.message = '';
    });

    renderCsvUserList();
    syncCsvProgressUi();

    processCsvUploadQueue(defaultAppId);
}

async function processCsvUploadQueue(defaultAppId) {
    const chunkSize = 3;

    while (csvUploadState.processed < csvUploadState.total) {
        const start = csvUploadState.processed;
        const end = Math.min(start + chunkSize, csvUploadState.total);

        for (let i = start; i < end; i++) {
            const row = parsedCsvUsers[i];
            const payload = {
                email: row.email,
                app_id: row.app_id || defaultAppId
            };

            try {
                row.status = 'adding';
                row.message = '';
                renderCsvUserList();
                const res = await fetch(`${API_URL}/admin/users`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    row.status = 'added';
                    csvUploadState.added += 1;
                } else {
                    row.status = 'failed';
                    try {
                        const data = await res.json();
                        row.message = data && data.detail ? String(data.detail) : 'Request failed';
                    } catch {
                        row.message = 'Request failed';
                    }
                    csvUploadState.failed += 1;
                }
            } catch {
                row.status = 'failed';
                row.message = 'Network error';
                csvUploadState.failed += 1;
            }

            csvUploadState.processed += 1;
            renderCsvUserList();
            syncCsvProgressUi();
        }

        // Yield control so UI remains responsive while processing large CSVs.
        await new Promise(resolve => setTimeout(resolve, 30));
    }

    csvUploadState.running = false;
    syncCsvProgressUi();

    if (csvUploadState.added > 0) {
        loadUsers();
        loadDashboard();
    }

    if (csvUploadState.failed === 0) {
        showToast(`Background add complete: ${csvUploadState.added} users added`, 'success');
    } else {
        showToast(`Background add complete: ${csvUploadState.added} added, ${csvUploadState.failed} failed`, 'info');
    }
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

function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
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
