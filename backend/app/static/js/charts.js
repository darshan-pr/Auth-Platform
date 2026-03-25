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

