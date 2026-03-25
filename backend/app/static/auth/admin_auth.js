const ADMIN_AUTH_UI_CONFIG = window.ADMIN_AUTH_UI_CONFIG || {};
const API_BASE = ADMIN_AUTH_UI_CONFIG.API_BASE || window.location.origin;
const REDIRECT_URL = ADMIN_AUTH_UI_CONFIG.REDIRECT_URL || '/admin/dashboard';
const INITIAL_WARNING = ADMIN_AUTH_UI_CONFIG.INITIAL_WARNING || '';

        let activeSection = "login";
        let signupState = "create"; // "create" or "otp"
        let signupEmail = "";
        let signupTenantName = "";
        let signupPassword = "";
        let resetEmail = "";
        let resetState = "otp"; // "otp" or "password"
        let resetOtpAutoBusy = false;
        let signupOtpAutoBusy = false;
        let loginState = "password"; // "password" or "mfa"
        let loginMfaTicket = "";
        let loginMfaEmail = "";
        let loginMfaAutoBusy = false;
        let passkeyCheckTimer = null;
        let passkeyCheckRequestId = 0;

        // ==================== Section Transitions ====================

        const sectionConfig = {
            login:    { mode: "login",     title: "Sign In",          subtitle: "Admin Portal",               illust: "illustLogin" },
            signup:   { mode: "signup",    title: "Sign Up",          subtitle: "Create your admin account",  illust: "illustSignup" },
            forgot:   { mode: "forgot",    title: "Forgot Password",  subtitle: "Reset your password",        illust: "illustForgot" },
            resetOtp: { mode: "reset-otp", title: "Reset Password",   subtitle: "Verify code, then set a new password", illust: "illustForgot" }
        };

        const sectionIds = {
            login: "loginSection",
            signup: "signupSection",
            forgot: "forgotSection",
            resetOtp: "resetOtpSection"
        };

        function showSection(name) {
            if (name === activeSection) return;
            clearMessages();

            if (activeSection === "signup" && name !== "signup") {
                resetSignupToCreate();
            }
            if (activeSection === "resetOtp" && name !== "resetOtp") {
                resetResetFlow(true);
            }
            if (activeSection === "login" && name !== "login") {
                resetLoginToPassword(true);
            }

            const prevEl = document.getElementById(sectionIds[activeSection]);
            const nextEl = document.getElementById(sectionIds[name]);
            const config = sectionConfig[name];

            prevEl.classList.remove("active");
            prevEl.classList.add("leaving");

            setTimeout(() => {
                prevEl.classList.remove("leaving");
                nextEl.classList.add("active");
            }, 200);

            document.body.className = "mode-" + config.mode;

            document.getElementById("inlineModeTitle").textContent = config.title;
            document.getElementById("formSubtitle").textContent = config.subtitle;

            document.querySelectorAll(".illust").forEach(el => el.classList.remove("active"));
            document.getElementById(config.illust).classList.add("active");

            activeSection = name;
        }

        // ==================== Utility ====================

        function clearMessages() {
            const err = document.getElementById("errorMsg");
            const suc = document.getElementById("successMsg");
            if (err) { err.className = "msg"; err.textContent = ""; }
            if (suc) { suc.className = "msg"; suc.textContent = ""; }
        }

        function showError(msg) {
            const el = document.getElementById("errorMsg");
            if (el) { el.className = "msg error"; el.textContent = msg; }
        }

        function showSuccess(msg) {
            const el = document.getElementById("successMsg");
            if (el) { el.className = "msg success"; el.textContent = msg; }
        }

        function setLoading(btnId, loading, label) {
            const btn = document.getElementById(btnId);
            if (!btn) return;
            const labelEl = btn.querySelector(".btn-label");

            if (loading) {
                btn.disabled = true;
                btn.classList.add("loading");
                if (labelEl && label) labelEl.textContent = label;
            } else {
                btn.disabled = false;
                btn.classList.remove("loading");
                if (labelEl && btn.dataset.defaultLabel) {
                    labelEl.textContent = btn.dataset.defaultLabel;
                }
            }
        }

        function base64urlToBuffer(base64url) {
            const padded = base64url + "=".repeat((4 - (base64url.length % 4)) % 4);
            const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
            const raw = atob(base64);
            const buffer = new ArrayBuffer(raw.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < raw.length; i++) {
                view[i] = raw.charCodeAt(i);
            }
            return buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = "";
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        }

        function normalizePublicKeyRequestOptions(options) {
            const normalized = { ...options };
            normalized.challenge = base64urlToBuffer(options.challenge);
            if (Array.isArray(options.allowCredentials)) {
                normalized.allowCredentials = options.allowCredentials.map((cred) => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id),
                }));
            }
            return normalized;
        }

        function setPasskeyHint(message, variant) {
            const hintEl = document.getElementById("passkeyHint");
            if (!hintEl) return;
            hintEl.classList.remove("ready", "error");
            if (variant === "ready") hintEl.classList.add("ready");
            if (variant === "error") hintEl.classList.add("error");
            hintEl.textContent = message;
        }

        function resetLoginToPassword(clearOtp) {
            loginState = "password";
            loginMfaTicket = "";
            loginMfaEmail = "";
            loginMfaAutoBusy = false;

            const mfaInline = document.getElementById("loginMfaInline");
            const passGroup = document.getElementById("loginPasswordGroup");
            const emailInput = document.getElementById("loginEmail");
            const passwordInput = document.getElementById("loginPassword");
            const loginBtn = document.getElementById("loginBtn");
            const loginLabel = loginBtn ? loginBtn.querySelector(".btn-label") : null;
            const passkeyDivider = document.getElementById("passkeyDivider");
            const passkeyBtn = document.getElementById("passkeyBtn");
            const passkeyHint = document.getElementById("passkeyHint");

            if (mfaInline) mfaInline.classList.remove("active");
            if (passGroup) passGroup.style.display = "";
            if (emailInput) emailInput.removeAttribute("readonly");
            if (passwordInput) passwordInput.setAttribute("required", "");
            if (loginBtn) loginBtn.dataset.defaultLabel = "Login";
            if (loginLabel) loginLabel.textContent = "Login";
            if (passkeyDivider) passkeyDivider.style.display = "";
            if (passkeyBtn) {
                passkeyBtn.style.display = "";
                passkeyBtn.disabled = false;
            }
            if (passkeyHint) passkeyHint.style.display = "";

            if (clearOtp) {
                document.querySelectorAll("#loginMfaOtpInputs .otp-input").forEach(i => { i.value = ""; });
            }

            schedulePasskeyCheck();
        }

        function showLoginMfaInline(email, ticket) {
            loginState = "mfa";
            loginMfaTicket = ticket;
            loginMfaEmail = email;
            loginMfaAutoBusy = false;

            const mfaInline = document.getElementById("loginMfaInline");
            const passGroup = document.getElementById("loginPasswordGroup");
            const emailInput = document.getElementById("loginEmail");
            const passwordInput = document.getElementById("loginPassword");
            const loginBtn = document.getElementById("loginBtn");
            const loginLabel = loginBtn ? loginBtn.querySelector(".btn-label") : null;
            const passkeyDivider = document.getElementById("passkeyDivider");
            const passkeyBtn = document.getElementById("passkeyBtn");
            const passkeyHint = document.getElementById("passkeyHint");

            document.getElementById("loginMfaEmailDisplay").textContent = email;
            if (mfaInline) mfaInline.classList.add("active");
            if (passGroup) passGroup.style.display = "none";
            if (emailInput) emailInput.setAttribute("readonly", "readonly");
            if (passwordInput) passwordInput.removeAttribute("required");
            if (loginBtn) loginBtn.dataset.defaultLabel = "Verify & Continue";
            if (loginLabel) loginLabel.textContent = "Verify & Continue";
            if (passkeyDivider) passkeyDivider.style.display = "none";
            if (passkeyBtn) {
                passkeyBtn.style.display = "none";
                passkeyBtn.disabled = true;
            }
            if (passkeyHint) passkeyHint.style.display = "none";

            document.querySelectorAll("#loginMfaOtpInputs .otp-input").forEach(i => { i.value = ""; });
            setTimeout(() => {
                const first = document.querySelector("#loginMfaOtpInputs .otp-input");
                if (first) first.focus();
            }, 120);
        }

        function setPasskeyButtonState({ enabled, label }) {
            const passkeyBtn = document.getElementById("passkeyBtn");
            const passkeyLabel = passkeyBtn ? passkeyBtn.querySelector(".btn-label") : null;
            if (!passkeyBtn || !passkeyLabel) return;
            passkeyBtn.disabled = !enabled;
            passkeyLabel.textContent = label;
            passkeyBtn.dataset.defaultLabel = label;
        }

        async function checkPasskeyAvailability(email) {
            const hasWebAuthn = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
            if (!hasWebAuthn) {
                setPasskeyButtonState({ enabled: false, label: "Passkey unsupported on this browser" });
                setPasskeyHint("Use password sign-in on this browser/device.", "error");
                return;
            }

            if (!email) {
                setPasskeyButtonState({ enabled: false, label: "Sign in with passkey" });
                setPasskeyHint("Enter your admin email to check passkey availability.");
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                setPasskeyButtonState({ enabled: false, label: "Sign in with passkey" });
                setPasskeyHint("Enter a valid email address to check passkey availability.");
                return;
            }

            const requestId = ++passkeyCheckRequestId;
            try {
                const res = await fetch(`${API_BASE}/admin/passkeys/check`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email: email })
                });
                const data = await res.json();
                if (requestId !== passkeyCheckRequestId) return;

                if (res.ok && data.has_passkey) {
                    setPasskeyButtonState({ enabled: true, label: "Sign in with passkey" });
                    setPasskeyHint("Passkey is set up for this account.", "ready");
                } else {
                    setPasskeyButtonState({ enabled: false, label: "Sign in with passkey" });
                    setPasskeyHint("No passkey found yet. Set one up from Settings after password sign-in.");
                }
            } catch (err) {
                if (requestId !== passkeyCheckRequestId) return;
                setPasskeyButtonState({ enabled: false, label: "Sign in with passkey" });
                setPasskeyHint("Could not check passkey status right now.", "error");
            }
        }

        function schedulePasskeyCheck() {
            if (passkeyCheckTimer) clearTimeout(passkeyCheckTimer);
            passkeyCheckTimer = setTimeout(() => {
                const email = document.getElementById("loginEmail").value.trim();
                checkPasskeyAvailability(email);
            }, 220);
        }

        // ==================== OTP Input Handling ====================

        function setupOtpInputs(containerId, onComplete) {
            const container = document.getElementById(containerId);
            if (!container) return;

            const inputs = container.querySelectorAll(".otp-input");
            inputs.forEach((input, idx) => {
                input.addEventListener("input", function(e) {
                    const val = e.target.value.replace(/[^0-9]/g, "");
                    e.target.value = val.slice(0, 1);
                    if (val && idx < inputs.length - 1) {
                        inputs[idx + 1].focus();
                    }
                    // Auto-submit when all filled
                    const otp = Array.from(inputs).map(i => i.value).join("");
                    if (otp.length === 6 && onComplete) {
                        onComplete();
                    }
                });
                input.addEventListener("keydown", function(e) {
                    if (e.key === "Backspace" && !e.target.value && idx > 0) {
                        inputs[idx - 1].focus();
                    }
                });
                input.addEventListener("paste", function(e) {
                    e.preventDefault();
                    const paste = (e.clipboardData || window.clipboardData).getData("text").replace(/[^0-9]/g, "").slice(0, 6);
                    paste.split("").forEach((char, i) => {
                        if (inputs[i]) inputs[i].value = char;
                    });
                    if (paste.length === 6 && onComplete) {
                        onComplete();
                    }
                });
            });
        }

        // ==================== Signup ====================

        function showSignupOtpInline(email) {
            signupState = "otp";
            signupEmail = email;

            const signupOtpInline = document.getElementById("signupOtpInline");
            document.getElementById("signupOtpEmailDisplay").textContent = email;
            signupOtpInline.classList.add("active");

            const signupBtn = document.getElementById("signupBtn");
            const signupLabel = signupBtn ? signupBtn.querySelector(".btn-label") : null;
            if (signupBtn) {
                signupBtn.dataset.defaultLabel = "Verify & Sign Up";
            }
            if (signupLabel) {
                signupLabel.textContent = "Verify & Sign Up";
            }

            document.getElementById("signupEmail").setAttribute("readonly", "readonly");
            document.getElementById("signupTenantName").setAttribute("readonly", "readonly");
            document.getElementById("signupPasswordGroup").style.display = "none";
            document.getElementById("signupConfirmGroup").style.display = "none";
            document.getElementById("signupPassword").removeAttribute("required");
            document.getElementById("signupConfirmPassword").removeAttribute("required");

            setTimeout(() => {
                const first = document.querySelector("#signupOtpInputs .otp-input");
                if (first) first.focus();
            }, 120);
        }

        function resetSignupToCreate() {
            signupState = "create";
            signupEmail = "";
            signupTenantName = "";
            signupPassword = "";

            const signupOtpInline = document.getElementById("signupOtpInline");
            signupOtpInline.classList.remove("active");
            document.querySelectorAll("#signupOtpInputs .otp-input").forEach(i => { i.value = ""; });

            document.getElementById("signupEmail").removeAttribute("readonly");
            document.getElementById("signupTenantName").removeAttribute("readonly");
            document.getElementById("signupPasswordGroup").style.display = "";
            document.getElementById("signupConfirmGroup").style.display = "";
            document.getElementById("signupPassword").setAttribute("required", "");
            document.getElementById("signupConfirmPassword").setAttribute("required", "");

            const signupBtn = document.getElementById("signupBtn");
            const signupLabel = signupBtn ? signupBtn.querySelector(".btn-label") : null;
            if (signupBtn) {
                signupBtn.dataset.defaultLabel = "Create Account";
            }
            if (signupLabel) {
                signupLabel.textContent = "Create Account";
            }
            const signupConfirmInput = document.getElementById("signupConfirmPassword");
            const openEye = document.getElementById("signupConfirmEyeOpen");
            const closedEye = document.getElementById("signupConfirmEyeClosed");
            const toggleBtn = document.getElementById("signupConfirmToggle");
            if (signupConfirmInput) signupConfirmInput.type = "password";
            if (openEye) openEye.style.display = "";
            if (closedEye) closedEye.style.display = "none";
            if (toggleBtn) toggleBtn.setAttribute("aria-label", "Show confirm password");
        }

        function toggleSignupConfirmPasswordVisibility() {
            const input = document.getElementById("signupConfirmPassword");
            const openEye = document.getElementById("signupConfirmEyeOpen");
            const closedEye = document.getElementById("signupConfirmEyeClosed");
            const toggleBtn = document.getElementById("signupConfirmToggle");
            if (!input) return;

            const showText = input.type === "password";
            input.type = showText ? "text" : "password";

            if (openEye) openEye.style.display = showText ? "none" : "";
            if (closedEye) closedEye.style.display = showText ? "" : "none";
            if (toggleBtn) {
                toggleBtn.setAttribute("aria-label", showText ? "Hide confirm password" : "Show confirm password");
            }
        }

        async function handleSignup(e) {
            e.preventDefault();
            clearMessages();

            if (signupState === "otp") {
                return handleSignupOTPVerify();
            }

            const email = document.getElementById("signupEmail").value.trim();
            const tenantName = document.getElementById("signupTenantName").value.trim();
            const password = document.getElementById("signupPassword").value;
            const confirm = document.getElementById("signupConfirmPassword").value;

            if (!tenantName) { showError("Organization name is required"); return; }
            if (password !== confirm) { showError("Passwords do not match"); return; }
            if (password.length < 8) { showError("Password must be at least 8 characters"); return; }
            if (!/[A-Z]/.test(password)) { showError("Password must contain an uppercase letter"); return; }
            if (!/[a-z]/.test(password)) { showError("Password must contain a lowercase letter"); return; }
            if (!/[0-9]/.test(password)) { showError("Password must contain a digit"); return; }

            setLoading("signupBtn", true, "Creating account...");
            signupTenantName = tenantName;
            signupPassword = password;

            try {
                const res = await fetch(`${API_BASE}/admin/register`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email: email,
                        password: password,
                        tenant_name: tenantName
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    setLoading("signupBtn", true, "Sending OTP...");
                    await new Promise(resolve => setTimeout(resolve, 220));
                    showSignupOtpInline(email);
                    showSuccess(data.message || "A verification code has been sent to your email.");
                } else {
                    showError(data.detail || "Signup failed");
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("signupBtn", false);
            }
        }

        async function handleSignupOTPVerify() {
            if (signupOtpAutoBusy) return;
            clearMessages();

            if (!signupEmail) {
                resetSignupToCreate();
                showError("Session expired. Please create your account again.");
                return;
            }

            const inputs = document.querySelectorAll("#signupOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");

            if (otp.length !== 6) { showError("Please enter the complete 6-digit code"); return; }

            signupOtpAutoBusy = true;
            setLoading("signupBtn", true, "Verifying...");

            try {
                const res = await fetch(`${API_BASE}/admin/register/verify-otp`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email: signupEmail,
                        otp: otp
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    const verifiedEmail = signupEmail;
                    resetSignupToCreate();
                    showSection("login");
                    document.getElementById("loginEmail").value = verifiedEmail;
                    document.getElementById("loginPassword").focus();
                    showSuccess(data.message || "Registration complete. Please sign in.");
                } else {
                    showError(data.detail || "Invalid code");
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                signupOtpAutoBusy = false;
                setLoading("signupBtn", false);
            }
        }

        // ==================== Login ====================

        async function handleLogin(e) {
            e.preventDefault();
            clearMessages();

            if (loginState === "mfa") {
                return handleLoginMfaVerify();
            }

            const email = document.getElementById("loginEmail").value.trim();
            const password = document.getElementById("loginPassword").value;
            if (!email) {
                showError("Please enter your admin email");
                return;
            }

            setLoading("loginBtn", true, "Signing in...");

            try {
                const res = await fetch(`${API_BASE}/admin/login`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    if (data.mfa_required && data.mfa_ticket) {
                        showLoginMfaInline(email, data.mfa_ticket);
                        showSuccess(data.message || "MFA code sent to your email.");
                    } else {
                        showSuccess("Login successful! Redirecting...");
                        setTimeout(() => { window.location.href = REDIRECT_URL; }, 500);
                    }
                } else {
                    showError(data.detail || "Login failed");
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("loginBtn", false);
            }
        }

        async function handleLoginMfaVerify() {
            if (loginMfaAutoBusy) return;
            clearMessages();

            if (!loginMfaTicket) {
                resetLoginToPassword(true);
                showError("MFA session expired. Please sign in again.");
                return;
            }

            const inputs = document.querySelectorAll("#loginMfaOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");
            if (otp.length !== 6) {
                showError("Please enter the complete 6-digit code");
                return;
            }

            loginMfaAutoBusy = true;
            setLoading("loginBtn", true, "Verifying code...");

            try {
                const res = await fetch(`${API_BASE}/admin/login/verify-mfa`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify({
                        mfa_ticket: loginMfaTicket,
                        otp: otp
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    showSuccess("MFA verified! Redirecting...");
                    setTimeout(() => { window.location.href = REDIRECT_URL; }, 450);
                } else {
                    const detail = String(data.detail || "").trim();
                    const lower = detail.toLowerCase();
                    showError(detail || "MFA verification failed");

                    if (lower.includes("mfa session expired") || lower.includes("sign in again")) {
                        resetLoginToPassword(true);
                        schedulePasskeyCheck();
                        return;
                    }
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                loginMfaAutoBusy = false;
                setLoading("loginBtn", false);
            }
        }

        async function handlePasskeyLogin() {
            clearMessages();

            const hasWebAuthn = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
            if (!hasWebAuthn) {
                showError("Passkey sign-in is not supported on this browser.");
                return;
            }

            const email = document.getElementById("loginEmail").value.trim();
            if (!email) {
                showError("Enter your admin email to continue with passkey sign-in.");
                return;
            }

            setLoading("passkeyBtn", true, "Checking passkey...");

            try {
                const beginRes = await fetch(`${API_BASE}/admin/passkeys/login/begin`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email: email })
                });
                const beginData = await beginRes.json();
                if (!beginRes.ok) {
                    showError(beginData.detail || "Unable to start passkey sign-in");
                    return;
                }
                if (!beginData.has_passkey || !beginData.options) {
                    showError(beginData.message || "No passkey is linked to this account yet.");
                    schedulePasskeyCheck();
                    return;
                }

                setLoading("passkeyBtn", true, "Waiting for passkey...");
                const publicKey = normalizePublicKeyRequestOptions(beginData.options);
                const assertion = await navigator.credentials.get({ publicKey });
                if (!assertion || !assertion.response) {
                    throw new Error("No passkey response received");
                }

                const completeRes = await fetch(`${API_BASE}/admin/passkeys/login/complete`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify({
                        email: email,
                        credential: {
                            id: assertion.id,
                            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                            signature: bufferToBase64url(assertion.response.signature)
                        }
                    })
                });
                const completeData = await completeRes.json();

                if (completeRes.ok) {
                    showSuccess("Passkey verified! Redirecting...");
                    setTimeout(() => { window.location.href = REDIRECT_URL; }, 450);
                } else {
                    showError(completeData.detail || "Passkey sign-in failed");
                }
            } catch (err) {
                const msg = String(err && err.name ? err.name : err && err.message ? err.message : "");
                if (msg.includes("NotAllowedError")) {
                    showError("Passkey prompt cancelled.");
                } else {
                    showError("Passkey sign-in failed. Please try password sign-in.");
                }
            } finally {
                setLoading("passkeyBtn", false);
            }
        }

        // ==================== Forgot Password ====================

        async function handleForgotPassword(e) {
            e.preventDefault();
            clearMessages();

            const email = document.getElementById("forgotEmail").value.trim();
            resetEmail = email;

            setLoading("forgotBtn", true, "Sending code...");

            try {
                const res = await fetch(`${API_BASE}/admin/forgot-password`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email: email })
                });
                const data = await res.json();

                if (res.ok) {
                    document.getElementById("resetOtpEmailDisplay").textContent = email;
                    showSection("resetOtp");
                    showSuccess(data.message || "Reset code sent. Check your email.");
                    setTimeout(() => {
                        const first = document.querySelector("#resetOtpInputs .otp-input");
                        if (first) first.focus();
                    }, 300);
                } else {
                    showError(data.detail || "Failed to send reset code");
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("forgotBtn", false);
            }
        }

        // ==================== Reset Password ====================

        function setResetStep(step) {
            resetState = step;

            const codeBlock = document.getElementById("resetOtpCodeBlock");
            const verifiedInfo = document.getElementById("resetVerifiedInfo");
            const passwordFields = document.getElementById("resetPasswordFields");
            const resetBtn = document.getElementById("resetBtn");
            const resetBtnLabel = resetBtn ? resetBtn.querySelector(".btn-label") : null;
            const newPassword = document.getElementById("resetNewPassword");
            const confirmPassword = document.getElementById("resetConfirmPassword");

            if (step === "otp") {
                if (codeBlock) codeBlock.style.display = "";
                if (verifiedInfo) verifiedInfo.style.display = "none";
                if (passwordFields) passwordFields.style.display = "none";
                if (newPassword) newPassword.removeAttribute("required");
                if (confirmPassword) confirmPassword.removeAttribute("required");
                if (resetBtn) resetBtn.dataset.defaultLabel = "Verify Code";
                if (resetBtnLabel) resetBtnLabel.textContent = "Verify Code";
                return;
            }

            if (codeBlock) codeBlock.style.display = "none";
            if (verifiedInfo) verifiedInfo.style.display = "block";
            if (passwordFields) passwordFields.style.display = "block";
            if (newPassword) newPassword.setAttribute("required", "");
            if (confirmPassword) confirmPassword.setAttribute("required", "");
            if (resetBtn) resetBtn.dataset.defaultLabel = "Reset Password";
            if (resetBtnLabel) resetBtnLabel.textContent = "Reset Password";
        }

        function resetResetFlow(clearAll = false) {
            setResetStep("otp");
            document.querySelectorAll("#resetOtpInputs .otp-input").forEach(i => { i.value = ""; });
            if (clearAll) {
                const newPassword = document.getElementById("resetNewPassword");
                const confirmPassword = document.getElementById("resetConfirmPassword");
                if (newPassword) newPassword.value = "";
                if (confirmPassword) confirmPassword.value = "";
            }
        }

        async function handleResetPassword(e) {
            e.preventDefault();
            clearMessages();

            if (resetState === "otp") {
                return handleResetOTPVerify();
            }

            const newPw = document.getElementById("resetNewPassword").value;
            const confirmPw = document.getElementById("resetConfirmPassword").value;

            if (newPw !== confirmPw) { showError("Passwords do not match"); return; }
            if (newPw.length < 8) { showError("Password must be at least 8 characters"); return; }
            if (!/[A-Z]/.test(newPw)) { showError("Password must contain an uppercase letter"); return; }
            if (!/[a-z]/.test(newPw)) { showError("Password must contain a lowercase letter"); return; }
            if (!/[0-9]/.test(newPw)) { showError("Password must contain a digit"); return; }

            setLoading("resetBtn", true, "Resetting...");

            try {
                const res = await fetch(`${API_BASE}/admin/reset-password`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email: resetEmail,
                        new_password: newPw
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    const email = resetEmail;
                    resetResetFlow(true);
                    resetEmail = "";
                    showSection("login");
                    document.getElementById("loginEmail").value = email;
                    document.getElementById("loginPassword").focus();
                    showSuccess(data.message || "Password reset successful. Please sign in.");
                } else {
                    showError(data.detail || "Reset failed");
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("resetBtn", false);
            }
        }

        async function handleResetOTPVerify() {
            if (resetOtpAutoBusy) return;
            clearMessages();

            const inputs = document.querySelectorAll("#resetOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");

            if (otp.length !== 6) { showError("Please enter the complete 6-digit code"); return; }

            resetOtpAutoBusy = true;
            setLoading("resetBtn", true, "Verifying...");

            try {
                const res = await fetch(`${API_BASE}/admin/forgot-password/verify-otp`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email: resetEmail,
                        otp: otp
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    setResetStep("password");
                    showSuccess(data.message || "Code verified. Set your new password.");
                    setTimeout(() => {
                        document.getElementById("resetNewPassword").focus();
                    }, 100);
                } else {
                    showError(data.detail || "Invalid code");
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                resetOtpAutoBusy = false;
                setLoading("resetBtn", false);
            }
        }

        // ==================== Initialize ====================

        document.addEventListener("DOMContentLoaded", function() {
            // Set default labels for buttons
            const loginBtn = document.getElementById("loginBtn");
            const signupBtn = document.getElementById("signupBtn");
            const forgotBtn = document.getElementById("forgotBtn");
            const resetBtn = document.getElementById("resetBtn");
            const passkeyBtn = document.getElementById("passkeyBtn");

            if (loginBtn) loginBtn.dataset.defaultLabel = "Login";
            if (signupBtn) signupBtn.dataset.defaultLabel = "Create Account";
            if (forgotBtn) forgotBtn.dataset.defaultLabel = "Send Reset Code";
            if (resetBtn) resetBtn.dataset.defaultLabel = "Verify Code";
            if (passkeyBtn) passkeyBtn.dataset.defaultLabel = "Sign in with passkey";

            // Setup OTP inputs with auto-submit
            setupOtpInputs("signupOtpInputs", function() {
                if (!signupOtpAutoBusy) handleSignupOTPVerify();
            });
            setupOtpInputs("loginMfaOtpInputs", function() {
                if (!loginMfaAutoBusy && loginState === "mfa") handleLoginMfaVerify();
            });
            setupOtpInputs("resetOtpInputs", function() {
                if (!resetOtpAutoBusy) handleResetOTPVerify();
            });

            resetLoginToPassword(true);
            schedulePasskeyCheck();

            const loginEmailInput = document.getElementById("loginEmail");
            if (loginEmailInput) {
                loginEmailInput.addEventListener("input", schedulePasskeyCheck);
                loginEmailInput.addEventListener("blur", schedulePasskeyCheck);
            }

            // Mobile keyboard handling
            const inputs = document.querySelectorAll("input");
            inputs.forEach(input => {
                input.addEventListener("focus", () => document.body.classList.add("keyboard-open"));
                input.addEventListener("blur", () => document.body.classList.remove("keyboard-open"));
            });

            if (INITIAL_WARNING) {
                showError(INITIAL_WARNING);
            }
        });
