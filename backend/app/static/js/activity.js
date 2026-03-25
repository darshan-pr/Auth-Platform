// ==================== Admin Personal Auth Activity ====================

async function loadMyAuthActivity() {
    await Promise.all([loadAdminSessions(), loadAdminHistory()]);
}

function getLocationLabel(record) {
    if (!record) return 'Unknown';
    if (record.location && String(record.location).trim()) return record.location;
    const parts = [record.city, record.region, record.country].filter(Boolean);
    return parts.length ? parts.join(', ') : 'Unknown';
}

function buildScopeLabel(sourceLabel, appLabel) {
    const source = String(sourceLabel || '').trim();
    const app = String(appLabel || '').trim();
    if (!source && !app) return 'Unknown';
    if (!source) return app;
    if (!app) return source;
    if (source.toLowerCase() === app.toLowerCase()) return source;
    return `${source} • ${app}`;
}

function formatActivityType(eventType) {
    const value = String(eventType || '').trim().toLowerCase();
    if (value === 'login') return 'Login';
    if (value === 'logout') return 'Logout';
    if (value === 'session_revoke') return 'Session Revoked';
    if (value === 'session_revoke_all') return 'Revoked All Sessions';
    if (value === 'access') return 'Access';
    if (!value) return 'Activity';
    return value
        .split('_')
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
}

async function loadAdminSessions() {
    const tbody = document.getElementById('adminSessionsTableBody');
    if (!tbody) return;

    const container = tbody.closest('.table-container');
    tbody.innerHTML = generateTableSkeleton(4, 6);
    if (container) container.classList.add('refreshing');

    try {
        const response = await fetch(`${API_URL}/admin/my-auth-activity/sessions`);
        const data = await response.json();
        adminSessions = Array.isArray(data.sessions) ? data.sessions : [];

        const countEl = document.getElementById('adminSessionCount');
        if (countEl) countEl.textContent = String(adminSessions.length);

        if (container) container.classList.remove('refreshing');

        if (!adminSessions.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading">No active sessions found.</td></tr>';
            return;
        }

        tbody.innerHTML = adminSessions.map((session, idx) => {
            const safeSessionId = escapeAttr(session.session_id);
            const sessionType = session.session_type || 'admin_console';
            const sourceLabel = session.source_label || (sessionType === 'client_app' ? 'Client App' : 'Admin Console');
            const appLabel = session.app_name || (session.app_id || 'Admin Console');
            const scopeLabel = buildScopeLabel(sourceLabel, appLabel);
            const location = getLocationLabel(session);
            const deviceLabel = session.device || 'Unknown';
            const browserLabel = session.browser || 'Unknown';
            const ipLabel = session.ip_address || 'Unknown';
            const rowLabel = `${scopeLabel} • ${deviceLabel} • ${browserLabel} • ${ipLabel}`;
            const detailRowId = `session-more-${idx}-${safeSessionId.replace(/[^a-zA-Z0-9_-]/g, '')}`;
            const loginAt = formatDateTime(session.login_at);
            const lastSeenAt = formatDateTime(session.last_seen_at);
            return `
                <tr class="new-row">
                    <td data-label="Device" class="session-device-cell">
                        <div class="session-device-top">
                            <span class="session-device-name">${escapeHtml(deviceLabel)}</span>
                            ${session.is_current ? '<span class="session-current-badge"><i data-lucide="shield-check"></i>Current</span>' : ''}
                        </div>
                        <div class="session-meta-row">
                            <small class="session-meta">${escapeHtml(scopeLabel)}</small>
                        </div>
                    </td>
                    <td data-label="Browser">${escapeHtml(browserLabel)}</td>
                    <td data-label="IP"><code>${escapeHtml(ipLabel)}</code></td>
                    <td data-label="Location">${escapeHtml(location)}</td>
                    <td data-label="Actions" class="session-action-cell">
                        <div class="action-btns">
                            <button class="btn-icon danger" data-action="revoke-admin-session" data-session-id="${safeSessionId}" data-session-type="${escapeAttr(sessionType)}" data-session-label="${escapeAttr(rowLabel)}" data-is-current="${session.is_current ? '1' : '0'}" title="${session.is_current ? 'Sign Out Current Session' : (sessionType === 'client_app' ? 'Revoke Client App Session' : 'Revoke Session')}">
                                <i data-lucide="${session.is_current ? 'log-out' : 'power'}"></i>
                            </button>
                        </div>
                    </td>
                    <td data-label="" class="session-more-cell">
                        <button type="button" class="session-more-toggle" data-action="toggle-session-more" data-target-row="${detailRowId}" aria-expanded="false">More info</button>
                    </td>
                </tr>
                <tr id="${detailRowId}" class="session-detail-row" hidden>
                    <td colspan="6" class="session-detail-cell">
                        <div class="session-more-body session-more-body-compact">
                            <div class="session-more-row">
                                <span class="session-more-item"><strong>Login:</strong> ${escapeHtml(loginAt)}</span>
                                <span class="session-more-item"><strong>Last seen:</strong> ${escapeHtml(lastSeenAt)}</span>
                                <span class="session-more-item"><strong>Type:</strong> ${escapeHtml(sessionType === 'client_app' ? 'Client app session' : 'Admin console session')}</span>
                            </div>
                            <div class="session-more-row">
                                <span class="session-more-item"><strong>Browser:</strong> ${escapeHtml(browserLabel)}</span>
                                <span class="session-more-item"><strong>IP:</strong> <code>${escapeHtml(ipLabel)}</code></span>
                                <span class="session-more-item"><strong>Location:</strong> ${escapeHtml(location)}</span>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('[data-action="toggle-session-more"]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const targetRowId = btn.dataset.targetRow;
                if (!targetRowId) return;
                const targetRow = document.getElementById(targetRowId);
                if (!targetRow) return;
                const isOpen = !targetRow.hidden;
                targetRow.hidden = isOpen;
                btn.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
            });
        });

        tbody.querySelectorAll('[data-action="revoke-admin-session"]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const sid = btn.dataset.sessionId;
                const label = btn.dataset.sessionLabel || sid;
                const isCurrent = btn.dataset.isCurrent === '1';
                const sessionType = btn.dataset.sessionType || 'admin_console';
                confirmRevokeAdminSession(sid, label, isCurrent, sessionType);
            });
        });

        renderIcons();
    } catch (error) {
        console.error('Error loading admin sessions:', error);
        if (container) container.classList.remove('refreshing');
        tbody.innerHTML = '<tr><td colspan="6" class="loading">Failed to load active sessions.</td></tr>';
    }
}

async function loadAdminHistory() {
    const tbody = document.getElementById('adminHistoryTableBody');
    if (!tbody) return;

    const container = tbody.closest('.table-container');
    tbody.innerHTML = generateTableSkeleton(6, 4);
    if (container) container.classList.add('refreshing');

    try {
        const response = await fetch(`${API_URL}/admin/my-auth-activity/history?per_page=80&page=1`);
        const data = await response.json();
        adminHistory = Array.isArray(data.events) ? data.events : [];

        const total = Number(data.total || adminHistory.length || 0);
        const countEl = document.getElementById('adminHistoryCount');
        if (countEl) countEl.textContent = String(total);

        if (container) container.classList.remove('refreshing');

        if (!adminHistory.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No personal activity recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = adminHistory.map((event, idx) => {
            const method = event.method ? String(event.method).toUpperCase() : '';
            const resource = event.resource || '-';
            const detailText = event.details || (method ? `${method} ${resource}` : resource);
            const sourceLabel = event.source_label || 'Activity';
            const appLabel = event.app_name || event.app_id || 'Admin Console';
            const scopeLabel = buildScopeLabel(sourceLabel, appLabel);
            const badgeClass = String(event.event_type || 'access').replace(/[^a-z_]/gi, '').toLowerCase();
            const hasDevice = !!(event.device || event.browser);
            const deviceLabel = hasDevice ? `${event.device || 'Unknown'} / ${event.browser || 'Unknown'}` : '-';
            const eventId = String(event.id || idx).replace(/[^a-zA-Z0-9_-]/g, '');
            const moreInfoId = `history-more-${idx}-${eventId}`;
            return `
                <tr class="new-row">
                    <td data-label="Time">${formatDateTime(event.created_at)}</td>
                    <td data-label="Action">
                        <span class="activity-event-type ${escapeAttr(badgeClass)}">${escapeHtml(formatActivityType(event.event_type))}</span>
                    </td>
                    <td data-label="Source / App" class="activity-source-cell">
                        <div class="activity-source-text">
                            <div class="activity-source-main">${escapeHtml(scopeLabel)}</div>
                            <small class="activity-source-detail">${escapeHtml(detailText)}</small>
                        </div>
                    </td>
                    <td data-label="More">
                        <button type="button" class="session-more-toggle" data-action="toggle-history-more" data-target-row="${moreInfoId}" aria-expanded="false">More info</button>
                    </td>
                </tr>
                <tr id="${moreInfoId}" class="history-detail-row" hidden>
                    <td colspan="4" class="history-detail-cell">
                        <div class="session-more-body session-more-body-history">
                            <div class="session-more-row">
                                <span class="session-more-item"><strong>IP:</strong> <code>${escapeHtml(event.ip_address || 'Unknown')}</code></span>
                                <span class="session-more-item"><strong>Location:</strong> ${escapeHtml(getLocationLabel(event))}</span>
                            </div>
                            <div class="session-more-row">
                                <span class="session-more-item"><strong>Device:</strong> ${escapeHtml(deviceLabel)}</span>
                                <span class="session-more-item"><strong>Method:</strong> ${escapeHtml(method || 'N/A')}</span>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('[data-action="toggle-history-more"]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const targetRowId = btn.dataset.targetRow;
                if (!targetRowId) return;
                const targetRow = document.getElementById(targetRowId);
                if (!targetRow) return;
                const isOpen = !targetRow.hidden;
                targetRow.hidden = isOpen;
                btn.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
            });
        });
    } catch (error) {
        console.error('Error loading admin activity history:', error);
        if (container) container.classList.remove('refreshing');
        tbody.innerHTML = '<tr><td colspan="4" class="loading">Failed to load activity history.</td></tr>';
    }
}

function confirmRevokeAdminSession(sessionId, sessionLabel, isCurrentSession, sessionType) {
    if (!sessionId) return;

    document.getElementById('deleteTargetName').textContent = sessionLabel || sessionId;
    const warningEl = document.querySelector('#deleteModal .delete-warning');
    if (warningEl) {
        warningEl.textContent = isCurrentSession
            ? 'This is your current session. You will be signed out immediately.'
            : (sessionType === 'client_app'
                ? 'This will immediately invalidate this client app session token.'
                : 'This will immediately invalidate this session token.');
    }

    deleteCallback = async () => {
        const deleteBtn = document.getElementById('deleteConfirmBtn');
        const originalHtml = deleteBtn.innerHTML;
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Revoking...';
        try {
            const response = await fetch(`${API_URL}/admin/my-auth-activity/sessions/${encodeURIComponent(sessionId)}`, {
                method: 'DELETE'
            });
            const data = await response.json().catch(() => ({}));

            if (response.ok) {
                closeModal('deleteModal');
                if (data.session_type === 'client_app') {
                    showToast('Client app session revoked successfully', 'success');
                } else {
                    showToast(isCurrentSession ? 'Current session revoked. Signing out...' : 'Session revoked successfully', 'success');
                }
                if (data.current_session_revoked) {
                    setTimeout(() => { window.location.href = '/login'; }, 250);
                } else {
                    loadMyAuthActivity();
                }
            } else {
                showToast(data.detail || 'Failed to revoke session', 'error');
            }
        } catch {
            showToast('Failed to revoke session', 'error');
        } finally {
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = originalHtml;
            renderIcons();
        }
    };

    document.getElementById('deleteConfirmBtn').onclick = deleteCallback;
    openModal('deleteModal');
}

function confirmRevokeAllAdminSessions() {
    document.getElementById('deleteTargetName').textContent = 'All active sessions';
    const warningEl = document.querySelector('#deleteModal .delete-warning');
    if (warningEl) {
        warningEl.textContent = 'This revokes every session for your identity (admin + client apps), including your current one.';
    }

    deleteCallback = async () => {
        const deleteBtn = document.getElementById('deleteConfirmBtn');
        const originalHtml = deleteBtn.innerHTML;
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<span class="btn-inline-spinner" aria-hidden="true"></span>Revoking...';
        try {
            const response = await fetch(`${API_URL}/admin/my-auth-activity/sessions/revoke-all`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            });
            const data = await response.json().catch(() => ({}));

            if (response.ok) {
                closeModal('deleteModal');
                const count = Number(data.revoked_count || 0);
                showToast(`Revoked ${count} session${count === 1 ? '' : 's'}. Signing out...`, 'success');
                setTimeout(() => { window.location.href = '/login'; }, 250);
            } else {
                showToast(data.detail || 'Failed to revoke sessions', 'error');
            }
        } catch {
            showToast('Failed to revoke sessions', 'error');
        } finally {
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = originalHtml;
            renderIcons();
        }
    };

    document.getElementById('deleteConfirmBtn').onclick = deleteCallback;
    openModal('deleteModal');
}
