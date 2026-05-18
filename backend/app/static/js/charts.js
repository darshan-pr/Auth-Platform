// ==================== Dashboard ====================

async function loadDashboard(options = {}) {
    const force = !!options.force;
    const appMap = {};

    try {
        const [
            statsResult,
            appsResult,
            usersResult,
            eventsResult
        ] = await Promise.allSettled([
            fetchJsonCached(`${API_URL}/admin/stats`, { cacheKey: 'dashboard:stats', maxAgeMs: 15000, force }),
            fetchJsonCached(`${API_URL}/admin/apps`, { cacheKey: 'admin:apps', maxAgeMs: 15000, force }),
            fetchUsersSnapshot({ maxUsers: 100, force }),
            fetchJsonCached(`${API_URL}/admin/login-events?page=1&per_page=6`, { cacheKey: 'dashboard:events', maxAgeMs: 15000, force })
        ]);

        const stats = statsResult.status === 'fulfilled' ? (statsResult.value || {}) : {};
        const appsList = appsResult.status === 'fulfilled' && Array.isArray(appsResult.value) ? appsResult.value : [];
        const usersSnapshot = usersResult.status === 'fulfilled'
            ? usersResult.value
            : { users: [], total: Number(stats.total_users || 0), truncated: false };
        const loginEvents = eventsResult.status === 'fulfilled' && Array.isArray(eventsResult.value.events)
            ? eventsResult.value.events
            : [];

        const totalApps = Number(stats.total_apps || appsList.length || 0);
        const totalUsers = Number(stats.total_users || usersSnapshot.total || usersSnapshot.users.length || 0);
        const activeUsers = Number(stats.active_users || 0);
        const inactiveUsers = Number(stats.inactive_users || Math.max(totalUsers - activeUsers, 0));
        const onlineUsers = Number(stats.online_users || 0);

        appsList.forEach((app) => {
            if (app && app.app_id) appMap[app.app_id] = app.name || app.app_id;
        });

        animateValue('totalApps', totalApps);
        animateValue('totalUsers', totalUsers);
        animateValue('activeUsers', activeUsers);
        animateValue('onlineUsers', onlineUsers);

        renderHeroSummary({
            totalApps,
            totalUsers,
            activeUsers,
            onlineUsers,
            usersTruncated: !!usersSnapshot.truncated
        });

        renderCoverageStats(appsList, totalApps);
        renderGrowthStats({
            appsList,
            usersList: usersSnapshot.users,
            totalUsers,
            inactiveUsers,
            onlineUsers
        });
        renderRecentEvents(loginEvents, appMap);
        renderTopApps(usersSnapshot.users, appMap, usersSnapshot.truncated);

        setText('dashboardLastRefresh', `Updated ${formatRelativeTime(new Date())}`);
        renderIcons();
    } catch (error) {
        console.error('Error loading stats:', error);
        showDashboardFallback();
    }
}

async function fetchUsersSnapshot({ maxUsers = 100, force = false } = {}) {
    const response = await fetchJsonCached(
        `${API_URL}/admin/users?limit=${maxUsers}&offset=0`,
        { cacheKey: `dashboard:users:${maxUsers}`, maxAgeMs: 15000, force }
    );
    const total = Number(response.total || 0);
    const usersList = Array.isArray(response.users) ? response.users : [];
    return {
        users: usersList,
        total,
        truncated: usersList.length < total
    };
}

function renderHeroSummary({ usersTruncated }) {
    const tenantName = (sessionStorage.getItem('tenant_name') || '').trim() || 'Auth Platform Tenant';
    const summary = usersTruncated
        ? 'Manage apps, users, and auth activity from one unified control plane. Insights are based on the latest user snapshot.'
        : 'Manage apps, users, and auth activity from one unified control plane.';
    setText('dashboardHeroSummary', summary);
    setText('dashboardTenantPill', `Tenant: ${tenantName}`);
}

function renderCoverageStats(appsList, totalApps) {
    const denom = totalApps || 0;
    const oauthEnabled = appsList.filter((app) => app.oauth_enabled !== false).length;
    const otpEnabled = appsList.filter((app) => !!app.otp_enabled).length;
    const passkeyEnabled = appsList.filter((app) => !!app.passkey_enabled).length;
    const loginAlerts = appsList.filter((app) => !!app.login_notification_enabled).length;

    setText('metricOauthEnabled', formatCoverageMetric(oauthEnabled, denom));
    setText('metricOtpEnabled', formatCoverageMetric(otpEnabled, denom));
    setText('metricPasskeyEnabled', formatCoverageMetric(passkeyEnabled, denom));
    setText('metricLoginAlerts', formatCoverageMetric(loginAlerts, denom));
}

function renderGrowthStats({ appsList, usersList, totalUsers, inactiveUsers, onlineUsers }) {
    const now = Date.now();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    const newApps7d = appsList.filter((app) => {
        const created = new Date(app.created_at || 0).getTime();
        return created && now - created <= sevenDaysMs;
    }).length;

    const newUsers7d = usersList.filter((user) => {
        const created = new Date(user.created_at || 0).getTime();
        return created && now - created <= sevenDaysMs;
    }).length;

    const onlineRate = totalUsers > 0 ? Math.round((onlineUsers / totalUsers) * 100) : 0;

    setText('metricNewApps7d', String(newApps7d));
    setText('metricNewUsers7d', String(newUsers7d));
    setText('metricInactiveUsers', String(inactiveUsers));
    setText('metricOnlineRate', `${onlineRate}%`);
}

function renderRecentEvents(events, appMap) {
    const list = document.getElementById('dashboardEventsList');
    if (!list) return;

    if (!Array.isArray(events) || events.length === 0) {
        list.innerHTML = '<li class="dashboard-list-empty">No recent login events yet.</li>';
        return;
    }

    list.innerHTML = events.slice(0, 6).map((event) => {
        const eventLabel = humanizeEventType(event.event_type);
        const appName = event.app_id ? (appMap[event.app_id] || event.app_id) : 'Admin Console';
        const when = safeFormatDateTime(event.created_at);
        return `
            <li>
                <div class="dashboard-list-main">
                    <strong>${escapeForHtml(eventLabel)}</strong>
                    <small>${escapeForHtml(appName)} • ${escapeForHtml(when)}</small>
                </div>
                <span class="dashboard-list-meta">${escapeForHtml(shortEventCode(event.event_type))}</span>
            </li>
        `;
    }).join('');
}

function renderTopApps(usersList, appMap, truncated) {
    const list = document.getElementById('dashboardTopAppsList');
    if (!list) return;

    if (!Array.isArray(usersList) || usersList.length === 0) {
        list.innerHTML = '<li class="dashboard-list-empty">No users available yet.</li>';
        return;
    }

    const counts = {};
    usersList.forEach((user) => {
        const appId = user.app_id || 'unknown';
        counts[appId] = (counts[appId] || 0) + 1;
    });

    const topApps = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6);

    list.innerHTML = topApps.map(([appId, count]) => {
        const appName = appMap[appId] || appId;
        return `
            <li>
                <div class="dashboard-list-main">
                    <strong>${escapeForHtml(appName)}</strong>
                    <small>${escapeForHtml(appId)}</small>
                </div>
                <span class="dashboard-list-meta">${count} user${count === 1 ? '' : 's'}</span>
            </li>
        `;
    }).join('');

    if (truncated) {
        list.insertAdjacentHTML(
            'beforeend',
            '<li class="dashboard-list-empty">Based on the latest 500 users.</li>'
        );
    }
}

function formatCoverageMetric(enabledCount, totalCount) {
    if (!totalCount) return '0/0';
    return `${enabledCount}/${totalCount}`;
}

function showDashboardFallback() {
    setText('dashboardHeroSummary', 'Unable to load dashboard insights right now.');
    setText('dashboardLastRefresh', 'Refresh failed');
    setText('metricOauthEnabled', '-');
    setText('metricOtpEnabled', '-');
    setText('metricPasskeyEnabled', '-');
    setText('metricLoginAlerts', '-');
    setText('metricNewApps7d', '-');
    setText('metricNewUsers7d', '-');
    setText('metricInactiveUsers', '-');
    setText('metricOnlineRate', '-');
}

function humanizeEventType(eventType) {
    const raw = String(eventType || '').trim();
    if (!raw) return 'Unknown Event';
    return raw
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (match) => match.toUpperCase());
}

function shortEventCode(eventType) {
    const raw = String(eventType || '').trim();
    if (!raw) return 'N/A';
    const parts = raw.split('_').filter(Boolean);
    const code = parts.map((part) => part[0]?.toUpperCase() || '').join('');
    return code || raw.slice(0, 3).toUpperCase();
}

function safeFormatDateTime(dateStr) {
    if (typeof formatDateTime === 'function') {
        return formatDateTime(dateStr);
    }
    const date = new Date(dateStr || 0);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString();
}

function formatRelativeTime(dateObj) {
    const deltaMs = Math.max(0, Date.now() - dateObj.getTime());
    const seconds = Math.floor(deltaMs / 1000);
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

function setText(elementId, value) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = value;
}

function escapeForHtml(value) {
    if (value === null || value === undefined) return '';
    const str = String(value);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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
