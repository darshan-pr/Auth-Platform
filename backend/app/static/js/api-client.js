const API_URL = window.location.origin;
const DEFAULT_APP_LOGO = '/assets/logo.png';

// ==================== Auth Interceptor ====================
// Relies on HttpOnly cookie for admin auth — browser sends it automatically.
// Redirects to login on 401 responses.
(function () {
    const _fetch = window.fetch;

    function getCookie(name) {
        const cookies = document.cookie ? document.cookie.split('; ') : [];
        for (const c of cookies) {
            const idx = c.indexOf('=');
            const key = idx >= 0 ? c.slice(0, idx) : c;
            if (key === name) {
                return idx >= 0 ? decodeURIComponent(c.slice(idx + 1)) : '';
            }
        }
        return '';
    }

    window.fetch = function (url, opts) {
        opts = opts || {};
        if (typeof url === 'string' && url.includes('/admin')) {
            opts.credentials = 'include';  // Ensure HttpOnly cookie is sent

            const method = String(opts.method || 'GET').toUpperCase();
            if (method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH') {
                const csrf = getCookie('csrf_token');
                if (csrf) {
                    opts.headers = Object.assign({}, opts.headers || {}, { 'X-CSRF-Token': csrf });
                }
            }
        }
        return _fetch.call(this, url, opts).then(function (res) {
            if (res.status === 401 && typeof url === 'string' && url.includes('/admin')) {
                sessionStorage.removeItem('tenant_id');
                sessionStorage.removeItem('tenant_name');
                window.location.href = '/login';
            }
            return res;
        });
    };
})();

