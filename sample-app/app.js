/**
 * ============================================================
 *  Notes App — A sample app using Auth Platform for login
 * ============================================================
 *  
 *  This is an example of how any external project integrates
 *  with the Auth Platform. The app itself (notes) has nothing
 *  to do with auth — it just uses AuthClient from auth.js.
 * 
 *  Files:
 *    config.js  — AUTH_SERVER url + CLIENT_ID  (your app config)
 *    auth.js    — Auth SDK (drop into any project)
 *    app.js     — Your actual app logic (this file)
 * 
 * ============================================================
 */

// ==================== Initialize Auth ====================

const auth = new AuthClient(AUTH_CONFIG);

// Notes are stored per-user in localStorage
let notes = [];

// ==================== App Initialization ====================

document.addEventListener('DOMContentLoaded', async () => {
    // Step 1: Check if we're returning from the auth platform's login page
    const handled = await auth.handleCallback();
    if (handled) {
        // Successfully logged in via OAuth callback
        showApp();
        return;
    }

    // Step 2: Check if user already has a session
    if (auth.isAuthenticated()) {
        showApp();
    } else {
        showLanding();
    }

    // Step 3: Listen for auth changes (e.g., session expired)
    auth.onAuthChange((isLoggedIn) => {
        if (isLoggedIn) {
            showApp();
        } else {
            showLanding();
        }
    });
});

// ==================== Page Routing ====================

function showLanding() {
    document.getElementById('landingPage').classList.remove('hidden');
    document.getElementById('appPage').classList.add('hidden');

    // Check if CLIENT_ID is configured
    if (!AUTH_CONFIG.CLIENT_ID) {
        document.getElementById('configWarning').classList.remove('hidden');
        document.getElementById('loginBtn').disabled = true;
    }
}

function showApp() {
    document.getElementById('landingPage').classList.add('hidden');
    document.getElementById('appPage').classList.remove('hidden');

    // Display user info
    const user = auth.getUser();
    if (user) {
        document.getElementById('userEmail').textContent = user.email;
        document.getElementById('profileEmail').textContent = user.email;
        document.getElementById('profileUserId').textContent = user.user_id || '-';
        document.getElementById('profileExpiry').textContent = user.expires_at.toLocaleString();
        document.getElementById('profileIssuer').textContent = user.issuer || '-';
    }

    // Load notes for this user
    loadNotes();

    // Start session auto-refresh
    auth.startAutoRefresh();

    // Update session timer display
    updateSessionTimer();
    setInterval(updateSessionTimer, 1000);
}

// ==================== Auth Actions ====================

function handleLogin() {
    auth.login();
}

function handleLogout() {
    notes = [];
    auth.logout();
}

async function handleRefreshToken() {
    const btn = document.getElementById('refreshBtn');
    btn.disabled = true;
    btn.textContent = 'Refreshing...';

    const success = await auth.refreshAccessToken();

    if (success) {
        btn.textContent = '✓ Refreshed!';
        const user = auth.getUser();
        if (user) {
            document.getElementById('profileExpiry').textContent = user.expires_at.toLocaleString();
        }
    } else {
        btn.textContent = '✗ Failed';
    }

    setTimeout(() => {
        btn.disabled = false;
        btn.textContent = 'Refresh Token';
    }, 2000);
}

async function handleVerifyToken() {
    const btn = document.getElementById('verifyBtn');
    btn.disabled = true;
    btn.textContent = 'Verifying...';

    const result = await auth.verifyToken();

    if (result?.valid) {
        btn.textContent = '✓ Valid';
        btn.classList.add('btn-verified');
    } else {
        btn.textContent = '✗ Invalid';
    }

    setTimeout(() => {
        btn.disabled = false;
        btn.textContent = 'Verify Token';
        btn.classList.remove('btn-verified');
    }, 2000);
}

function updateSessionTimer() {
    const el = document.getElementById('sessionTimer');
    if (!el) return;

    const ttl = auth.getTimeUntilExpiry();
    if (ttl <= 0) {
        el.textContent = 'Expired';
        el.classList.add('expired');
        return;
    }

    const mins = Math.floor(ttl / 60);
    const secs = ttl % 60;
    el.textContent = `${mins}m ${secs.toString().padStart(2, '0')}s`;
    el.classList.toggle('warning', ttl < 120);
    el.classList.remove('expired');
}

// ==================== Notes CRUD ====================

function loadNotes() {
    const user = auth.getUser();
    if (!user) return;

    const key = `notes_${user.email}`;
    const saved = localStorage.getItem(key);
    notes = saved ? JSON.parse(saved) : [];
    renderNotes();
}

function saveNotes() {
    const user = auth.getUser();
    if (!user) return;

    const key = `notes_${user.email}`;
    localStorage.setItem(key, JSON.stringify(notes));
}

function addNote() {
    const input = document.getElementById('noteInput');
    const text = input.value.trim();
    if (!text) return;

    notes.unshift({
        id: Date.now(),
        text: text,
        created: new Date().toISOString(),
    });

    input.value = '';
    saveNotes();
    renderNotes();
}

function deleteNote(id) {
    notes = notes.filter(n => n.id !== id);
    saveNotes();
    renderNotes();
}

function renderNotes() {
    const container = document.getElementById('notesList');
    const count = document.getElementById('notesCount');

    count.textContent = notes.length;

    if (notes.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">📝</span>
                <p>No notes yet. Write something!</p>
            </div>
        `;
        return;
    }

    container.innerHTML = notes.map(note => `
        <div class="note-item">
            <div class="note-content">
                <p>${escapeHtml(note.text)}</p>
                <small>${timeAgo(note.created)}</small>
            </div>
            <button class="note-delete" onclick="deleteNote(${note.id})" title="Delete">×</button>
        </div>
    `).join('');
}

// Handle Enter key in note input
document.addEventListener('keydown', (e) => {
    if (e.target.id === 'noteInput' && e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        addNote();
    }
});

// ==================== Utilities ====================

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function timeAgo(dateStr) {
    const now = Date.now();
    const date = new Date(dateStr).getTime();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return new Date(dateStr).toLocaleDateString();
}