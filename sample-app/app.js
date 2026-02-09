const API_URL = 'http://localhost:8000';

// State
let currentEmail = '';
let tokens = {
    access_token: null,
    refresh_token: null
};
let appCredentials = {
    app_id: null,
    app_secret: null,
    app_name: null
};
let appSettings = {
    otp_enabled: true
};
let sessionCheckInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Check for existing app configuration
    const savedCredentials = localStorage.getItem('app_credentials');
    if (savedCredentials) {
        appCredentials = JSON.parse(savedCredentials);
    }

    // Check for existing session
    const savedTokens = localStorage.getItem('auth_tokens');
    if (savedTokens) {
        tokens = JSON.parse(savedTokens);
    }

    // Determine which page to show
    if (!appCredentials.app_id || !appCredentials.app_secret) {
        showSetupPage();
    } else if (savedTokens) {
        validateAndShowHome();
    } else {
        loadAppSettings().then(() => showLoginPage());
    }

    // Setup form handlers
    setupSetupForm();
    setupLoginForm();
    setupSignupForm();
    setupOTPForm();
    setupOTPInputs();
});

// ==================== App Settings ====================

async function loadAppSettings() {
    if (!appCredentials.app_id || !appCredentials.app_secret) return;
    
    try {
        const response = await fetch(
            `${API_URL}/auth/app-settings/${appCredentials.app_id}?app_secret=${appCredentials.app_secret}`
        );
        if (response.ok) {
            const data = await response.json();
            appSettings = {
                otp_enabled: data.otp_enabled,
                access_token_expiry_minutes: data.access_token_expiry_minutes,
                refresh_token_expiry_days: data.refresh_token_expiry_days
            };
        }
    } catch (error) {
        console.error('Error loading app settings:', error);
    }
}

// ==================== Setup Page ====================

function setupSetupForm() {
    document.getElementById('setupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await registerApp();
    });
}

async function registerApp() {
    const appName = document.getElementById('appName').value.trim();
    const appDescription = document.getElementById('appDescription').value.trim();
    
    if (!appName) {
        showSetupError('Please enter an app name');
        return;
    }

    showSetupLoading(true);
    hideSetupError();

    try {
        // Register the app with the auth platform
        const response = await fetch(`${API_URL}/admin/apps`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                name: appName,
                description: appDescription || `Sample App - ${appName}`
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Save credentials
            appCredentials = {
                app_id: data.app_id,
                app_secret: data.app_secret,
                app_name: appName
            };
            localStorage.setItem('app_credentials', JSON.stringify(appCredentials));
            
            // Store app settings
            appSettings = {
                otp_enabled: data.otp_enabled !== false
            };
            
            // Show success and credentials
            showCredentialsModal(data.app_id, data.app_secret);
        } else {
            showSetupError(data.detail || 'Failed to register app');
        }
    } catch (error) {
        console.error('Error:', error);
        showSetupError('Failed to connect to Auth Platform. Make sure it is running.');
    } finally {
        showSetupLoading(false);
    }
}

function useExistingCredentials() {
    document.getElementById('setupForm').classList.add('hidden');
    document.getElementById('existingCredentialsForm').classList.remove('hidden');
}

function backToSetup() {
    document.getElementById('existingCredentialsForm').classList.add('hidden');
    document.getElementById('setupForm').classList.remove('hidden');
    hideSetupError();
}

async function saveExistingCredentials() {
    const appId = document.getElementById('existingAppId').value.trim();
    const appSecret = document.getElementById('existingAppSecret').value.trim();
    
    if (!appId || !appSecret) {
        showSetupError('Please enter both App ID and App Secret');
        return;
    }

    showSetupLoading(true);
    hideSetupError();

    try {
        // Verify credentials by fetching app info
        const response = await fetch(`${API_URL}/admin/apps/${appId}`);
        
        if (response.ok) {
            const appData = await response.json();
            
            // Save credentials
            appCredentials = {
                app_id: appId,
                app_secret: appSecret,
                app_name: appData.name || 'My App'
            };
            localStorage.setItem('app_credentials', JSON.stringify(appCredentials));
            
            // Load app settings and go to login
            await loadAppSettings();
            showLoginPage();
        } else {
            showSetupError('Invalid App ID. Please check your credentials.');
        }
    } catch (error) {
        console.error('Error:', error);
        showSetupError('Failed to verify credentials');
    } finally {
        showSetupLoading(false);
    }
}

function showCredentialsModal(appId, appSecret) {
    document.getElementById('modalAppId').textContent = appId;
    document.getElementById('modalAppSecret').textContent = appSecret;
    document.getElementById('credentialsModal').classList.remove('hidden');
}

function closeCredentialsModal() {
    document.getElementById('credentialsModal').classList.add('hidden');
    loadAppSettings().then(() => showLoginPage());
}

function copyCredentials() {
    const appId = document.getElementById('modalAppId').textContent;
    const appSecret = document.getElementById('modalAppSecret').textContent;
    const text = `App ID: ${appId}\nApp Secret: ${appSecret}`;
    
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.copy-btn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = originalText, 2000);
    });
}

function showSetupError(message) {
    const errorDiv = document.getElementById('setupError');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
}

function hideSetupError() {
    document.getElementById('setupError').classList.add('hidden');
}

function showSetupLoading(show) {
    document.getElementById('setupBtnText').classList.toggle('hidden', show);
    document.getElementById('setupLoader').classList.toggle('hidden', !show);
}

// ==================== Page Navigation ====================

function showSetupPage() {
    stopSessionMonitoring();
    document.getElementById('setupPage').classList.remove('hidden');
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('homePage').classList.add('hidden');
}

function showLoginPage() {
    stopSessionMonitoring();
    document.getElementById('setupPage').classList.add('hidden');
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('homePage').classList.add('hidden');
    
    // Update app name in login page
    if (appCredentials.app_name) {
        document.getElementById('loginAppName').textContent = appCredentials.app_name;
    }
    
    // Show login form by default
    switchAuthMode('login');
}

// ==================== Auth Mode Switching ====================

function switchAuthMode(mode) {
    // Update tabs
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.mode === mode);
    });
    
    // Show/hide forms
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const otpForm = document.getElementById('otpForm');
    
    loginForm.classList.toggle('hidden', mode !== 'login');
    signupForm.classList.toggle('hidden', mode !== 'signup');
    otpForm.classList.add('hidden');
    
    // Clear messages
    hideError();
    hideSuccess();
}

// ==================== Form Handlers ====================

function setupLoginForm() {
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await handleLogin();
    });
}

function setupSignupForm() {
    document.getElementById('signupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await handleSignup();
    });
}

function setupOTPForm() {
    document.getElementById('otpForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await verifyLoginOTP();
    });
}

// ==================== Signup ====================

async function handleSignup() {
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    
    if (!email || !password) {
        showError('Please fill in all fields');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('Passwords do not match');
        return;
    }
    
    // Password validation
    if (password.length < 8) {
        showError('Password must be at least 8 characters long');
        return;
    }
    if (!/[A-Z]/.test(password)) {
        showError('Password must contain at least one uppercase letter');
        return;
    }
    if (!/[a-z]/.test(password)) {
        showError('Password must contain at least one lowercase letter');
        return;
    }
    if (!/[0-9]/.test(password)) {
        showError('Password must contain at least one digit');
        return;
    }
    
    showLoading('signupBtnText', 'signupLoader', true);
    hideError();
    hideSuccess();
    
    try {
        const response = await fetch(`${API_URL}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                app_id: appCredentials.app_id,
                app_secret: appCredentials.app_secret
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showSuccess('Account created successfully! Please login.');
            // Clear form and switch to login
            document.getElementById('signupForm').reset();
            setTimeout(() => {
                switchAuthMode('login');
                document.getElementById('loginEmail').value = email;
            }, 1500);
        } else {
            showError(data.detail || 'Signup failed');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Failed to connect to server');
    } finally {
        showLoading('signupBtnText', 'signupLoader', false);
    }
}

// ==================== Login ====================

async function handleLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showError('Please fill in all fields');
        return;
    }
    
    currentEmail = email;
    showLoading('loginBtnText', 'loginLoader', true);
    hideError();
    hideSuccess();
    
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                app_id: appCredentials.app_id,
                app_secret: appCredentials.app_secret
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.otp_required) {
                // OTP is enabled - show OTP form
                document.getElementById('loginForm').classList.add('hidden');
                document.getElementById('otpForm').classList.remove('hidden');
                document.getElementById('sentEmail').textContent = email;
                document.querySelector('.auth-tabs').classList.add('hidden');
                
                // Focus first OTP input
                document.querySelector('.otp-input').focus();
                showSuccess('Password verified! OTP sent to your email.');
            } else {
                // OTP disabled - tokens received directly
                tokens = {
                    access_token: data.access_token,
                    refresh_token: data.refresh_token
                };
                localStorage.setItem('auth_tokens', JSON.stringify(tokens));
                showHomePage();
            }
        } else {
            showError(data.detail || 'Login failed');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Failed to connect to server');
    } finally {
        showLoading('loginBtnText', 'loginLoader', false);
    }
}

// ==================== OTP Verification ====================

async function verifyLoginOTP() {
    const inputs = document.querySelectorAll('.otp-input');
    const otp = Array.from(inputs).map(input => input.value).join('');
    
    if (otp.length !== 6) {
        showError('Please enter the complete 6-digit code');
        return;
    }
    
    showLoading('otpBtnText', 'otpLoader', true);
    hideError();
    hideSuccess();
    
    try {
        const response = await fetch(`${API_URL}/auth/login/verify-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: currentEmail,
                otp,
                app_id: appCredentials.app_id,
                app_secret: appCredentials.app_secret
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Save tokens
            tokens = {
                access_token: data.access_token,
                refresh_token: data.refresh_token
            };
            localStorage.setItem('auth_tokens', JSON.stringify(tokens));
            showHomePage();
        } else {
            showError(data.detail || 'Invalid OTP');
            clearOTPInputs();
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Failed to verify OTP');
    } finally {
        showLoading('otpBtnText', 'otpLoader', false);
    }
}

// OTP Input Navigation
function setupOTPInputs() {
    const inputs = document.querySelectorAll('.otp-input');
    
    inputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value;
            
            // Only allow digits
            e.target.value = value.replace(/[^0-9]/g, '');
            
            // Move to next input
            if (value && index < inputs.length - 1) {
                inputs[index + 1].focus();
            }
        });

        input.addEventListener('keydown', (e) => {
            // Move to previous input on backspace
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                inputs[index - 1].focus();
            }
        });

        // Handle paste
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text');
            const digits = paste.replace(/[^0-9]/g, '').slice(0, 6);
            
            digits.split('').forEach((digit, i) => {
                if (inputs[i]) {
                    inputs[i].value = digit;
                }
            });
            
            if (digits.length > 0) {
                inputs[Math.min(digits.length, inputs.length) - 1].focus();
            }
        });
    });
}

function backToLogin() {
    document.getElementById('otpForm').classList.add('hidden');
    document.getElementById('loginForm').classList.remove('hidden');
    document.querySelector('.auth-tabs').classList.remove('hidden');
    clearOTPInputs();
    hideError();
    hideSuccess();
}

// ==================== Token Validation ====================

async function validateAndShowHome() {
    try {
        const response = await fetch(`${API_URL}/token/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: tokens.access_token })
        });

        if (response.ok) {
            showHomePage();
        } else {
            // Token invalid, logout
            console.log('Token invalid on startup, logging out...');
            logout();
        }
    } catch (error) {
        console.error('Validation error:', error);
        logout();
    }
}

// ==================== Home Page ====================

function showHomePage() {
    document.getElementById('setupPage').classList.add('hidden');
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('homePage').classList.remove('hidden');

    // Decode token and display info
    try {
        const payload = parseJWT(tokens.access_token);
        
        document.getElementById('userEmail').textContent = payload.sub;
        document.getElementById('infoEmail').textContent = payload.sub;
        document.getElementById('infoUserId').textContent = payload.user_id || '-';
        document.getElementById('infoIssuer').textContent = payload.iss || '-';
        document.getElementById('infoAppId').textContent = payload.app_id || appCredentials.app_id || '-';
        document.getElementById('infoAppName').textContent = appCredentials.app_name || '-';
        
        // Format expiry
        const expiry = new Date(payload.exp * 1000);
        document.getElementById('infoExpiry').textContent = expiry.toLocaleString();
        
        // Token preview (first 40 chars)
        document.getElementById('tokenPreview').textContent = 
            tokens.access_token.substring(0, 40) + '...';
        
        // Start session monitoring
        startSessionMonitoring();
    } catch (error) {
        console.error('Error parsing token:', error);
    }
}

function parseJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

// ==================== Token Actions ====================

async function verifyToken() {
    const resultDiv = document.getElementById('actionResult');
    resultDiv.classList.remove('hidden', 'success', 'error');

    try {
        const response = await fetch(`${API_URL}/token/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: tokens.access_token })
        });

        const data = await response.json();
        resultDiv.classList.add(response.ok ? 'success' : 'error');
        resultDiv.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        resultDiv.classList.add('error');
        resultDiv.textContent = 'Error: ' + error.message;
    }
}

async function refreshToken() {
    const resultDiv = document.getElementById('actionResult');
    resultDiv.classList.remove('hidden', 'success', 'error');

    try {
        const response = await fetch(`${API_URL}/token/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: tokens.refresh_token })
        });

        const data = await response.json();

        if (response.ok) {
            tokens.access_token = data.access_token;
            localStorage.setItem('auth_tokens', JSON.stringify(tokens));
            
            resultDiv.classList.add('success');
            resultDiv.textContent = 'Token refreshed successfully!\n\n' + 
                JSON.stringify(data, null, 2);
            
            // Update UI with new token info
            showHomePage();
        } else {
            resultDiv.classList.add('error');
            resultDiv.textContent = JSON.stringify(data, null, 2);
        }
    } catch (error) {
        resultDiv.classList.add('error');
        resultDiv.textContent = 'Error: ' + error.message;
    }
}

// ==================== Session Monitoring ====================

function startSessionMonitoring() {
    // Clear any existing interval
    if (sessionCheckInterval) {
        clearInterval(sessionCheckInterval);
    }
    
    // Check every 10 seconds
    sessionCheckInterval = setInterval(async () => {
        await checkSessionValidity();
    }, 10000);
    
    // Also check immediately
    checkSessionValidity();
}

function stopSessionMonitoring() {
    if (sessionCheckInterval) {
        clearInterval(sessionCheckInterval);
        sessionCheckInterval = null;
    }
}

async function checkSessionValidity() {
    if (!tokens.access_token) return;
    
    try {
        // Parse JWT to check expiry
        const payload = parseJWT(tokens.access_token);
        const expiryTime = payload.exp * 1000; // Convert to milliseconds
        const currentTime = Date.now();
        const timeUntilExpiry = expiryTime - currentTime;
        
        // If already expired, logout immediately
        if (timeUntilExpiry <= 0) {
            console.log('Access token expired, logging out...');
            handleSessionExpired();
            return;
        }
        
        // Just monitor, don't auto-refresh
        console.log(`Session check: ${Math.floor(timeUntilExpiry / 1000)}s remaining`);
    } catch (error) {
        console.error('Error checking session validity:', error);
        // On error, verify with server
        try {
            const response = await fetch(`${API_URL}/token/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: tokens.access_token })
            });
            
            if (!response.ok) {
                // Token invalid, logout
                handleSessionExpired();
            }
        } catch (err) {
            console.error('Error verifying token:', err);
        }
    }
}

async function attemptTokenRefresh() {
    if (!tokens.refresh_token) {
        return false;
    }
    
    try {
        const response = await fetch(`${API_URL}/token/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: tokens.refresh_token })
        });
        
        if (response.ok) {
            const data = await response.json();
            tokens.access_token = data.access_token;
            localStorage.setItem('auth_tokens', JSON.stringify(tokens));
            console.log('Token refreshed successfully');
            
            // Update display with new token info
            try {
                const payload = parseJWT(tokens.access_token);
                const expiry = new Date(payload.exp * 1000);
                document.getElementById('infoExpiry').textContent = expiry.toLocaleString();
                document.getElementById('tokenPreview').textContent = 
                    tokens.access_token.substring(0, 40) + '...';
            } catch (err) {
                console.error('Error updating display:', err);
            }
            
            return true;
        } else {
            console.error('Token refresh failed:', await response.text());
            return false;
        }
    } catch (error) {
        console.error('Error refreshing token:', error);
        return false;
    }
}

function handleSessionExpired() {
    stopSessionMonitoring();
    alert('Your session has expired. Please login again.');
    logout();
}

// ==================== Logout & Navigation ====================

function logout() {
    stopSessionMonitoring();
    tokens = { access_token: null, refresh_token: null };
    localStorage.removeItem('auth_tokens');
    currentEmail = '';
    
    // Reset forms
    document.getElementById('loginEmail').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('signupForm').reset();
    clearOTPInputs();
    document.getElementById('otpForm').classList.add('hidden');
    document.getElementById('loginForm').classList.remove('hidden');
    document.querySelector('.auth-tabs').classList.remove('hidden');
    document.getElementById('actionResult').classList.add('hidden');
    
    // Show login page
    showLoginPage();
}

function resetApp() {
    if (confirm('This will clear all app credentials and you will need to set up again. Continue?')) {
        localStorage.removeItem('app_credentials');
        localStorage.removeItem('auth_tokens');
        appCredentials = { app_id: null, app_secret: null, app_name: null };
        tokens = { access_token: null, refresh_token: null };
        
        // Reset forms
        document.getElementById('appName').value = '';
        document.getElementById('appDescription').value = '';
        document.getElementById('existingAppId').value = '';
        document.getElementById('existingAppSecret').value = '';
        document.getElementById('existingCredentialsForm').classList.add('hidden');
        document.getElementById('setupForm').classList.remove('hidden');
        
        showSetupPage();
    }
}

function clearOTPInputs() {
    document.querySelectorAll('.otp-input').forEach(input => {
        input.value = '';
    });
    const firstInput = document.querySelector('.otp-input');
    if (firstInput) firstInput.focus();
}

// ==================== UI Helpers ====================

function showLoading(textId, loaderId, show) {
    document.getElementById(textId).classList.toggle('hidden', show);
    document.getElementById(loaderId).classList.toggle('hidden', !show);
}

function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
    hideSuccess();
}

function hideError() {
    document.getElementById('errorMessage').classList.add('hidden');
}

function showSuccess(message) {
    const successDiv = document.getElementById('successMessage');
    successDiv.textContent = message;
    successDiv.classList.remove('hidden');
    hideError();
}

function hideSuccess() {
    document.getElementById('successMessage').classList.add('hidden');
}
