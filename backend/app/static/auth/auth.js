const AUTH_UI_CONFIG = window.AUTH_UI_CONFIG || {};
const SESSION_ID = AUTH_UI_CONFIG.SESSION_ID || '';
const API_BASE = AUTH_UI_CONFIG.API_BASE || window.location.origin;
const OTP_ENABLED = Boolean(AUTH_UI_CONFIG.OTP_ENABLED);
const PASSKEY_ENABLED = Boolean(AUTH_UI_CONFIG.PASSKEY_ENABLED);

        let currentEmail = "";
        let resetEmail = "";
        let activeSection = "login";
        let loginState = "password"; // "password" or "otp"
        let signupState = "create"; // "create" or "otp"
        let signupEmail = "";
        let resetState = "otp"; // "otp" or "password"
        let loginOtpAutoBusy = false;
        let signupOtpAutoBusy = false;
        let resetOtpAutoBusy = false;
        let passkeyOtpAutoBusy = false;
        let passkeySetupMode = false;
        let passkeyPendingOptions = null;

        // ==================== Section Transitions ====================

        const sectionConfig = {
            login:    { mode: "login",     title: "Sign In",          subtitle: "Access your account",               illust: "illustLogin" },
            signup:   { mode: "signup",    title: "Sign Up",          subtitle: "Create your account",               illust: "illustSignup" },
            forgot:   { mode: "forgot",    title: "Forgot Password",  subtitle: "Reset your password",               illust: "illustForgot" },
            resetOtp: { mode: "reset-otp", title: "Reset Password",   subtitle: "Verify your code, then set a new password",   illust: "illustForgot" }
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

            // Reset login state when navigating back to login
            if (name === "login") {
                resetLoginToPassword();
            }
            if (activeSection === "signup" && name !== "signup") {
                resetSignupToCreate();
            }
            if (activeSection === "resetOtp" && name !== "resetOtp") {
                resetResetFlow(true);
            }

            const prevEl = document.getElementById(sectionIds[activeSection]);
            const nextEl = document.getElementById(sectionIds[name]);
            const config = sectionConfig[name];

            // Animate out the previous section
            prevEl.classList.remove("active");
            prevEl.classList.add("leaving");

            setTimeout(() => {
                prevEl.classList.remove("leaving");
                // Animate in the next section
                nextEl.classList.add("active");
            }, 200);

            document.body.className = "mode-" + config.mode;

            document.getElementById("inlineModeTitle").textContent = config.title;
            document.getElementById("formSubtitle").textContent = config.subtitle;

            document.querySelectorAll(".illust").forEach(el => el.classList.remove("active"));
            document.getElementById(config.illust).classList.add("active");

            activeSection = name;
        }

        // ==================== Login OTP Inline ====================

        function showOtpInline(email) {
            loginState = "otp";
            const otpInline = document.getElementById("loginOtpInline");
            const pwGroup = document.getElementById("loginPasswordGroup");
            const loginPassword = document.getElementById("loginPassword");

            pwGroup.style.display = "none";
            loginPassword.removeAttribute("required");

            document.getElementById("otpEmailDisplay").textContent = email;
            otpInline.classList.add("active");

            const loginBtn = document.getElementById("loginBtn");
            const loginLabel = loginBtn ? loginBtn.querySelector(".btn-label") : null;
            if (loginBtn) {
                loginBtn.dataset.defaultLabel = "Verify & Continue";
            }
            if (loginLabel) {
                loginLabel.textContent = "Verify & Continue";
            }

            // Hide passkey section when showing OTP
            const passkeyDivider = document.querySelector("#loginSection .divider");
            const passkeyBtn = document.getElementById("passkeyLoginBtn");
            const passkeyRegRow = document.getElementById("passkeyRegisterRow");
            if (passkeyDivider) passkeyDivider.style.display = "none";
            if (passkeyBtn) passkeyBtn.style.display = "none";
            if (passkeyRegRow) passkeyRegRow.style.display = "none";

            // Focus first OTP input
            setTimeout(() => {
                const first = document.querySelector("#loginOtpInputs .otp-input");
                if (first) first.focus();
            }, 100);

        }

        function resetLoginToPassword() {
            loginState = "password";
            const otpInline = document.getElementById("loginOtpInline");
            const pwGroup = document.getElementById("loginPasswordGroup");
            const loginPassword = document.getElementById("loginPassword");

            otpInline.classList.remove("active");
            pwGroup.style.display = "";
            loginPassword.setAttribute("required", "");

            // Clear OTP inputs
            document.querySelectorAll("#loginOtpInputs .otp-input").forEach(i => { i.value = ""; });

            const loginBtn = document.getElementById("loginBtn");
            const loginLabel = loginBtn ? loginBtn.querySelector(".btn-label") : null;
            if (loginBtn) {
                loginBtn.dataset.defaultLabel = "Login";
            }
            if (loginLabel) {
                loginLabel.textContent = "Login";
            }

            // Restore passkey section
            const passkeyDivider = document.querySelector("#loginSection .divider");
            const passkeyBtn = document.getElementById("passkeyLoginBtn");
            const passkeyRegRow = document.getElementById("passkeyRegisterRow");
            if (passkeyDivider) passkeyDivider.style.display = "";
            if (passkeyBtn) passkeyBtn.style.display = "";
            if (passkeyRegRow) passkeyRegRow.style.display = "";
            if (loginBtn) loginBtn.style.display = "";

            const passkeyOtpInline = document.getElementById("passkeyOtpInline");
            if (passkeyOtpInline) passkeyOtpInline.classList.remove("active");
            passkeySetupMode = false;
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

            const signupOtpInline = document.getElementById("signupOtpInline");
            signupOtpInline.classList.remove("active");
            document.querySelectorAll("#signupOtpInputs .otp-input").forEach(i => { i.value = ""; });

            document.getElementById("signupEmail").removeAttribute("readonly");
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
            const password = document.getElementById("signupPassword").value;
            const confirm = document.getElementById("signupConfirmPassword").value;

            if (password !== confirm) { showError("Passwords do not match"); return; }
            if (password.length < 8) { showError("Password must be at least 8 characters"); return; }
            if (!/[A-Z]/.test(password)) { showError("Password must contain an uppercase letter"); return; }
            if (!/[a-z]/.test(password)) { showError("Password must contain a lowercase letter"); return; }
            if (!/[0-9]/.test(password)) { showError("Password must contain a digit"); return; }

            setLoading("signupBtn", true, "Creating account...");

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "signup",
                        email: email,
                        password: password
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    if (data.action === "show_signup_otp" || data.action === "show_otp") {
                        setLoading("signupBtn", true, "Sending OTP...");
                        await new Promise(resolve => setTimeout(resolve, 220));
                        showSignupOtpInline(email);
                        showSuccess(data.message || "A verification code has been sent to your email.");
                    } else if (data.action === "redirect") {
                        showSuccess("Account created! Redirecting...");
                        setTimeout(() => { window.location.href = data.redirect_url; }, 500);
                    } else {
                        showSuccess(data.message || "Account created! Please sign in.");
                        setTimeout(() => {
                            resetSignupToCreate();
                            showSection("login");
                            document.getElementById("loginEmail").value = email;
                            document.getElementById("loginPassword").focus();
                        }, 1200);
                    }
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
            clearMessages();

            if (!signupEmail) {
                resetSignupToCreate();
                showError("Session expired. Please create your account again.");
                return;
            }

            const inputs = document.querySelectorAll("#signupOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");

            if (otp.length !== 6) { showError("Please enter the complete 6-digit code"); return; }

            setLoading("signupBtn", true);

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "verify_signup_otp",
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
                    showSuccess(data.message || "Email verified. Sign up complete. Please sign in.");
                } else {
                    showError(data.detail || "Invalid code");
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("signupBtn", false);
            }
        }

        // ==================== Login ====================

        async function handleLogin(e) {
            e.preventDefault();
            clearMessages();

            const email = document.getElementById("loginEmail").value.trim();
            currentEmail = email;

            // If we're in OTP state, handle OTP verification
            if (loginState === "otp") {
                return handleOTPVerify();
            }

            const password = document.getElementById("loginPassword").value;
            setLoading("loginBtn", true, "Verifying...");

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "login",
                        email: email,
                        password: password
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    if (data.action === "show_otp") {
                        setLoading("loginBtn", true, "Sending OTP...");
                        await new Promise(resolve => setTimeout(resolve, 220));
                        // Show OTP inline instead of navigating to separate page
                        showOtpInline(email);
                        showSuccess(data.message);
                    } else if (data.action === "redirect") {
                        showSuccess("Authentication successful! Redirecting...");
                        setTimeout(() => { window.location.href = data.redirect_url; }, 500);
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

        // ==================== OTP Verification (Inline) ====================

        async function handleOTPVerify() {
            clearMessages();

            const inputs = document.querySelectorAll("#loginOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");

            if (otp.length !== 6) { showError("Please enter the complete 6-digit code"); return; }

            setLoading("loginBtn", true);

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "verify_otp",
                        email: currentEmail,
                        otp: otp
                    })
                });
                const data = await res.json();

                if (res.ok && data.action === "redirect") {
                    showSuccess("Verified! Redirecting...");
                    setTimeout(() => { window.location.href = data.redirect_url; }, 500);
                } else {
                    showError(data.detail || "Invalid code");
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("loginBtn", false);
            }
        }

        // ==================== Passkey ====================

        // ====== Passkey Overlay Helpers ======

        function showPasskeyOverlay(state, status, hint) {
            const overlay = document.getElementById('passkeyOverlay');
            const icon = document.getElementById('pkIcon');
            const statusEl = document.getElementById('pkStatus');
            const hintEl = document.getElementById('pkHint');
            if (!overlay || !icon || !statusEl || !hintEl) return;

            icon.className = 'pk-icon ' + state;

            // Swap icon SVG based on state
            if (state === 'success') {
                icon.innerHTML = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
            } else if (state === 'error') {
                icon.innerHTML = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
            } else {
                icon.innerHTML = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg><div class="pk-ring" id="pkRing"></div>';
            }

            const ring = icon.querySelector('#pkRing');
            if (ring) {
                ring.style.display = state === 'waiting' ? '' : 'none';
            }

            statusEl.textContent = status;
            hintEl.textContent = hint || '';
            overlay.classList.add('active');
        }

        function hidePasskeyOverlay() {
            const overlay = document.getElementById('passkeyOverlay');
            if (overlay) overlay.classList.remove('active');
        }

        function setButtonBusy(btn, busy, busyLabel) {
            if (!btn) return;
            if (busy) {
                if (!btn.dataset.originalHtml) {
                    btn.dataset.originalHtml = btn.innerHTML;
                }
                btn.disabled = true;
                btn.classList.add("loading");
                btn.textContent = busyLabel;
                return;
            }
            btn.disabled = false;
            btn.classList.remove("loading");
            if (btn.dataset.originalHtml) {
                btn.innerHTML = btn.dataset.originalHtml;
            }
        }

        async function parseApiResponse(res) {
            const contentType = (res.headers.get("content-type") || "").toLowerCase();
            if (contentType.includes("application/json")) {
                try {
                    return await res.json();
                } catch {
                    // Fall through to text parser for malformed JSON bodies.
                }
            }
            const text = await res.text();
            return {
                detail: text || `Request failed (HTTP ${res.status})`,
                raw: text || ""
            };
        }

        function enablePasskeySetupMode() {
            if (passkeySetupMode) return;
            passkeySetupMode = true;

            const pwGroup = document.getElementById("loginPasswordGroup");
            const loginPassword = document.getElementById("loginPassword");
            if (pwGroup) pwGroup.style.display = "none";
            if (loginPassword) loginPassword.removeAttribute("required");
        }

        function disablePasskeySetupMode() {
            passkeySetupMode = false;
            if (loginState !== "password") return;

            const pwGroup = document.getElementById("loginPasswordGroup");
            const loginPassword = document.getElementById("loginPassword");
            if (pwGroup) pwGroup.style.display = "";
            if (loginPassword) loginPassword.setAttribute("required", "");
        }

        async function handlePasskeyLogin() {
            if (!PASSKEY_ENABLED) return;
            clearMessages();

            const email = document.getElementById("loginEmail").value.trim();
            if (!email) {
                showError("Enter your email first to sign in with passkey.");
                document.getElementById("loginEmail").focus();
                return;
            }

            const btn = document.getElementById("passkeyLoginBtn");
            setButtonBusy(btn, true, "Checking account...");
            showPasskeyOverlay('waiting', 'Initiating passkey...', 'Connecting to server');

            try {
                // 1. Get authentication options from server
                const rpId = window.location.hostname;
                const beginRes = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_auth_begin",
                        email: email,
                        rp_id: rpId
                    })
                });
                const beginData = await parseApiResponse(beginRes);

                if (!beginRes.ok) {
                    showPasskeyOverlay('error', 'Connection failed', beginData.detail || '');
                    setTimeout(hidePasskeyOverlay, 1800);
                    return;
                }

                // If no passkey for this account, prompt user to create one
                if (beginData.action === "no_passkey_for_account") {
                    hidePasskeyOverlay();
                    showPasskeySetupPrompt();
                    showError(beginData.message || "No passkey is linked to this account.");
                    return;
                }

                const options = beginData.options;

                showPasskeyOverlay('waiting', 'Waiting for passkey...', 'Follow your browser or device prompt');

                // 2. Call WebAuthn API
                const publicKeyOptions = {
                    challenge: base64urlToBuffer(options.challenge),
                    rpId: options.rpId,
                    timeout: options.timeout,
                    userVerification: options.userVerification || "required",
                };

                if (options.allowCredentials && options.allowCredentials.length > 0) {
                    publicKeyOptions.allowCredentials = options.allowCredentials.map(c => ({
                        type: c.type,
                        id: base64urlToBuffer(c.id),
                    }));
                }

                const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });

                showPasskeyOverlay('waiting', 'Verifying...', 'Almost there');

                // 3. Send assertion to server
                const completeRes = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_auth_complete",
                        email: email,
                        rp_id: rpId,
                        credential: {
                            id: bufferToBase64url(assertion.rawId),
                            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                            signature: bufferToBase64url(assertion.response.signature),
                        }
                    })
                });
                const completeData = await parseApiResponse(completeRes);

                if (completeRes.ok && completeData.action === "redirect") {
                    showPasskeyOverlay('success', 'Authenticated!', 'Redirecting you now...');
                    setTimeout(() => { window.location.href = completeData.redirect_url; }, 800);
                } else {
                    showPasskeyOverlay('error', 'Authentication failed', completeData.detail || '');
                    setTimeout(hidePasskeyOverlay, 2000);
                }
            } catch (err) {
                if (err.name === "NotAllowedError") {
                    showPasskeyOverlay('error', 'Cancelled', 'Passkey authentication was cancelled');
                } else if (err.name === "SecurityError") {
                    showPasskeyOverlay('error', 'Not available', 'Passkey not available in this context');
                } else {
                    console.error("Passkey error:", err);
                    showPasskeyOverlay('error', 'Failed', 'Try password login instead');
                }
                setTimeout(hidePasskeyOverlay, 2000);
            } finally {
                setButtonBusy(btn, false);
            }
        }

        function showPasskeySetupPrompt() {
            const existingPrompt = document.getElementById("passkeySetupPrompt");
            if (existingPrompt) { existingPrompt.remove(); }

            const prompt = document.createElement("div");
            prompt.id = "passkeySetupPrompt";
            prompt.style.cssText = "animation: fadeIn 0.3s ease; margin-top: 4px;";
            prompt.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 14px; margin-bottom: 10px;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;">
                        <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/>
                        <circle cx="16.5" cy="7.5" r=".5" fill="#d97706"/>
                    </svg>
                    <div style="flex:1; min-width:0;">
                        <span style="font-size: 13px; color: #92400e; font-weight: 500;">No passkey linked to this account.</span>
                        <span style="font-size: 12px; color: #a16207;"> Use OTP to set one up now.</span>
                        <button type="button" onclick="dismissPasskeyPrompt(); handlePasskeyRegister();" 
                                style="font-size: 12px; color: #d97706; font-weight: 600; background: none; border: none; cursor: pointer; font-family: inherit; padding: 0; text-decoration: underline;">
                            Set up passkey</button>
                    </div>
                    <button type="button" onclick="dismissPasskeyPrompt()" style="background: none; border: none; cursor: pointer; padding: 2px; color: #d97706; flex-shrink: 0; line-height: 1;" aria-label="Dismiss">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
            `;

            // Insert after the passkey button
            const passkeyBtn = document.getElementById("passkeyLoginBtn");
            passkeyBtn.parentNode.insertBefore(prompt, passkeyBtn.nextSibling.nextSibling);

            // Hide the passkey register row
            const passkeyRegRow = document.getElementById("passkeyRegisterRow");
            if (passkeyRegRow) passkeyRegRow.style.display = "none";
        }

        function dismissPasskeyPrompt() {
            const prompt = document.getElementById("passkeySetupPrompt");
            if (prompt) {
                prompt.style.animation = 'sectionOut 0.2s ease forwards';
                setTimeout(() => prompt.remove(), 200);
            }
            const passkeyRegRow = document.getElementById("passkeyRegisterRow");
            if (passkeyRegRow) passkeyRegRow.style.display = "";
        }

        // ==================== Passkey Check & Conditional Setup ====================

        let passkeyCheckTimeout = null;

        async function checkPasskeyStatus() {
            if (!PASSKEY_ENABLED) return;
            const email = document.getElementById("loginEmail").value.trim();
            const regRow = document.getElementById("passkeyRegisterRow");
            if (!regRow) return;

            if (!email) {
                regRow.style.display = "none";
                return;
            }

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_check",
                        email: email
                    })
                });
                const data = await parseApiResponse(res);
                // Show "Set up passkey" only if user has NO passkey
                regRow.style.display = data.has_passkey ? "none" : "";
            } catch {
                regRow.style.display = "none";
            }
        }

        // ==================== Passkey Registration (3-step OTP flow) ====================

        let passkeyRegEmail = "";

        async function handlePasskeyRegister() {
            if (!PASSKEY_ENABLED) return;
            clearMessages();

            const email = document.getElementById("loginEmail").value.trim();
            if (!email) {
                showError("Please enter your email first, then set up a passkey.");
                document.getElementById("loginEmail").focus();
                return;
            }

            passkeyRegEmail = email;
            const registerBtn = document.getElementById("passkeyRegisterBtn");
            setButtonBusy(registerBtn, true, "Sending OTP...");

            try {
                // Step 1: Request OTP
                const beginRes = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_register_begin",
                        email: email,
                        rp_id: window.location.hostname
                    })
                });
                const beginData = await parseApiResponse(beginRes);

                if (!beginRes.ok) {
                    showError(beginData.detail || "Failed to start passkey registration");
                    return;
                }

                // Show OTP inline form
                showPasskeyOtpForm(email);
                showSuccess(beginData.message || "Verification code sent to your email.");

            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setButtonBusy(registerBtn, false);
            }
        }

        function showPasskeyOtpForm(email) {
            const otpForm = document.getElementById("passkeyOtpInline");
            const regRow = document.getElementById("passkeyRegisterRow");
            const passkeyBtn = document.getElementById("passkeyLoginBtn");
            const divider = document.querySelector("#loginSection .divider");
            const loginBtn = document.getElementById("loginBtn");
            const verifyStep = document.getElementById("pkStepVerify");
            const setupStep = document.getElementById("pkStepSetup");
            const sub = document.getElementById("pkOtpSub");
            const verifyBtn = document.getElementById("pkOtpVerifyBtn");

            if (regRow) regRow.style.display = "none";
            if (passkeyBtn) passkeyBtn.style.display = "none";
            if (divider) divider.style.display = "none";
            if (loginBtn) loginBtn.style.display = "none";
            enablePasskeySetupMode();

            document.getElementById("pkOtpInfo").innerHTML =
                `Enter the 6-digit code sent to<br><strong>${email}</strong>`;
            if (sub) sub.textContent = "Complete verification first, then set up your passkey.";
            if (verifyStep) verifyStep.classList.add("active");
            if (setupStep) setupStep.classList.remove("active");
            if (verifyBtn) verifyBtn.textContent = "Step 1: Verify Code";
            otpForm.classList.add("active");

            // Clear any previous values
            document.querySelectorAll("#pkOtpInputs .pk-otp-input").forEach(i => { i.value = ""; });
            setTimeout(() => {
                const first = document.querySelector("#pkOtpInputs .pk-otp-input");
                if (first) first.focus();
            }, 100);
        }

        function cancelPasskeyOtp() {
            const otpForm = document.getElementById("passkeyOtpInline");
            otpForm.classList.remove("active");
            clearMessages();
            passkeyPendingOptions = null;

            // Restore passkey buttons
            const passkeyBtn = document.getElementById("passkeyLoginBtn");
            const divider = document.querySelector("#loginSection .divider");
            const loginBtn = document.getElementById("loginBtn");
            if (passkeyBtn) passkeyBtn.style.display = "";
            if (divider) divider.style.display = "";
            if (loginBtn) loginBtn.style.display = "";
            disablePasskeySetupMode();
            checkPasskeyStatus();
        }

        async function handlePasskeyOtpResend() {
            clearMessages();
            if (!passkeyRegEmail) return;
            const resendBtn = document.getElementById("pkOtpResendBtn");
            if (resendBtn) {
                resendBtn.disabled = true;
                resendBtn.textContent = "Sending...";
            }

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_register_begin",
                        email: passkeyRegEmail,
                        rp_id: window.location.hostname
                    })
                });
                const data = await parseApiResponse(res);
                if (res.ok) {
                    showSuccess("New verification code sent.");
                } else {
                    showError(data.detail || "Failed to resend code.");
                }
            } catch {
                showError("Connection error.");
            } finally {
                if (resendBtn) {
                    resendBtn.disabled = false;
                    resendBtn.textContent = "Resend code";
                }
            }
        }

        async function handlePasskeyOtpVerify() {
            clearMessages();

            const inputs = document.querySelectorAll("#pkOtpInputs .pk-otp-input");
            const verifyBtn = document.getElementById("pkOtpVerifyBtn");
            verifyBtn.disabled = true;
            verifyBtn.textContent = passkeyPendingOptions ? "Setting up..." : "Verifying...";

            try {
                const rpId = window.location.hostname;

                if (!passkeyPendingOptions) {
                    const otp = Array.from(inputs).map(i => i.value).join("");
                    if (otp.length !== 6) {
                        showError("Please enter the complete 6-digit code.");
                        return;
                    }

                    // Step 2: Verify OTP and fetch WebAuthn challenge
                    const otpRes = await fetch(`${API_BASE}/oauth/authenticate`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            session_id: SESSION_ID,
                            action: "passkey_register_verify_otp",
                            email: passkeyRegEmail,
                            otp: otp,
                            rp_id: rpId
                        })
                    });
                    const otpData = await parseApiResponse(otpRes);

                    if (!otpRes.ok) {
                        showError(otpData.detail || "Invalid verification code.");
                        inputs.forEach(i => { i.value = ""; });
                        inputs[0].focus();
                        return;
                    }

                    // Store options and require a second explicit click for WebAuthn user gesture reliability.
                    passkeyPendingOptions = otpData.options;
                    const verifyStep = document.getElementById("pkStepVerify");
                    const setupStep = document.getElementById("pkStepSetup");
                    const sub = document.getElementById("pkOtpSub");
                    if (verifyStep) verifyStep.classList.remove("active");
                    if (setupStep) setupStep.classList.add("active");
                    if (sub) sub.textContent = "Verification complete. Continue to create your passkey.";
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = "Step 2: Set Up Passkey";
                    showSuccess("Code verified. Click 'Step 2: Set Up Passkey' to finish.");
                    return;
                }

                // Hide OTP form, show passkey overlay
                document.getElementById("passkeyOtpInline").classList.remove("active");
                showPasskeyOverlay('waiting', 'Creating passkey...', 'Follow your browser or device prompt');

                const options = passkeyPendingOptions;

                // Step 3: Call WebAuthn API
                const publicKeyOptions = {
                    challenge: base64urlToBuffer(options.challenge),
                    rp: { name: options.rp.name, id: options.rp.id },
                    user: {
                        id: base64urlToBuffer(options.user.id),
                        name: options.user.name,
                        displayName: options.user.displayName,
                    },
                    pubKeyCredParams: options.pubKeyCredParams,
                    timeout: options.timeout,
                    authenticatorSelection: options.authenticatorSelection,
                    attestation: options.attestation || "none",
                };

                if (options.excludeCredentials) {
                    publicKeyOptions.excludeCredentials = options.excludeCredentials.map(c => ({
                        type: c.type,
                        id: base64urlToBuffer(c.id),
                    }));
                }

                const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

                showPasskeyOverlay('waiting', 'Saving passkey...', 'Almost done');

                // Step 4: Complete registration on server
                const completeRes = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "passkey_register_complete",
                        email: passkeyRegEmail,
                        rp_id: rpId,
                        credential: {
                            id: bufferToBase64url(credential.rawId),
                            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                            attestationObject: bufferToBase64url(credential.response.attestationObject),
                            deviceName: navigator.userAgent.includes("Mac") ? "Mac" :
                                        navigator.userAgent.includes("iPhone") ? "iPhone" :
                                        navigator.userAgent.includes("Android") ? "Android" :
                                        navigator.userAgent.includes("Windows") ? "Windows" : "Device",
                        }
                    })
                });
                const completeData = await parseApiResponse(completeRes);

                if (completeRes.ok) {
                    passkeyPendingOptions = null;
                    verifyBtn.disabled = true;
                    verifyBtn.textContent = "Passkey setup successful";
                    showPasskeyOverlay('success', 'Passkey created!', 'You can now sign in with your passkey');
                    setTimeout(() => {
                        hidePasskeyOverlay();
                        showSuccess(completeData.message || "Passkey registered! You can now use it to sign in.");
                        // Hide the setup row since passkey now exists
                        const regRow = document.getElementById("passkeyRegisterRow");
                        const loginBtn = document.getElementById("loginBtn");
                        if (regRow) regRow.style.display = "none";
                        // Restore login buttons
                        const passkeyBtn = document.getElementById("passkeyLoginBtn");
                        const divider = document.querySelector("#loginSection .divider");
                        if (passkeyBtn) passkeyBtn.style.display = "";
                        if (divider) divider.style.display = "";
                        if (loginBtn) loginBtn.style.display = "";
                        disablePasskeySetupMode();
                    }, 1500);
                } else {
                    passkeyPendingOptions = null;
                    showPasskeyOverlay('error', 'Registration failed', completeData.detail || '');
                    setTimeout(hidePasskeyOverlay, 2000);
                }
            } catch (err) {
                hidePasskeyOverlay();
                passkeyPendingOptions = null;
                if (err.name === "NotAllowedError") {
                    showError("Passkey registration was cancelled.");
                } else if (err.name === "InvalidStateError") {
                    showError("A passkey already exists for this account on this device.");
                } else if (err.name === "SecurityError") {
                    showError("Passkey setup requires HTTPS or localhost.");
                } else {
                    console.error("Passkey reg error:", err);
                    showError("Passkey registration failed.");
                }
                cancelPasskeyOtp();
            } finally {
                if (passkeyPendingOptions) {
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = "Step 2: Set Up Passkey";
                } else {
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = "Step 1: Verify Code";
                }
            }
        }

        // ==================== WebAuthn Helpers ====================

        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            const binary = atob(base64 + padding);
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            return buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        // ==================== Forgot Password ====================

        async function handleForgotPassword(e) {
            e.preventDefault();
            clearMessages();

            const email = document.getElementById("forgotEmail").value.trim();
            resetEmail = email;

            setLoading("forgotBtn", true, "Verifying...");

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "forgot_password",
                        email: email
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    setLoading("forgotBtn", true, "Sending OTP...");
                    await new Promise(resolve => setTimeout(resolve, 220));
                    showSection("resetOtp");
                    resetResetFlow(true);
                    document.getElementById("resetOtpEmailDisplay").textContent = email;
                    setTimeout(() => {
                        document.querySelector("#resetOtpInputs .otp-input").focus();
                    }, 350);
                    showSuccess(data.message);
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

        async function handleResetPassword(e) {
            e.preventDefault();
            clearMessages();

            if (resetState === "otp") {
                return handleResetOtpVerify();
            }

            const newPassword = document.getElementById("resetNewPassword").value;
            const confirmPassword = document.getElementById("resetConfirmPassword").value;

            if (newPassword !== confirmPassword) { showError("Passwords do not match"); return; }
            if (newPassword.length < 8) { showError("Password must be at least 8 characters"); return; }
            if (!/[A-Z]/.test(newPassword)) { showError("Password must contain an uppercase letter"); return; }
            if (!/[a-z]/.test(newPassword)) { showError("Password must contain a lowercase letter"); return; }
            if (!/[0-9]/.test(newPassword)) { showError("Password must contain a digit"); return; }

            setLoading("resetBtn", true);

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "reset_password",
                        email: resetEmail,
                        new_password: newPassword
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    showSuccess(data.message || "Password reset successfully!");
                    setTimeout(() => {
                        resetResetFlow(true);
                        showSection("login");
                        document.getElementById("loginEmail").value = resetEmail;
                        document.getElementById("loginPassword").focus();
                    }, 1500);
                } else {
                    showError(data.detail || "Failed to reset password");
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("resetBtn", false);
            }
        }

        async function handleResetOtpVerify() {
            clearMessages();

            const inputs = document.querySelectorAll("#resetOtpInputs .otp-input");
            const otp = Array.from(inputs).map(i => i.value).join("");

            if (otp.length !== 6) { showError("Please enter the complete 6-digit code"); return; }

            setLoading("resetBtn", true, "Verifying...");

            try {
                const res = await fetch(`${API_BASE}/oauth/authenticate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: SESSION_ID,
                        action: "verify_reset_otp",
                        email: resetEmail,
                        otp: otp
                    })
                });
                const data = await res.json();

                if (res.ok) {
                    showSuccess(data.message || "Code verified. You can now set a new password.");
                    setResetStep("password");
                    setTimeout(() => {
                        document.getElementById("resetNewPassword").focus();
                    }, 120);
                } else {
                    showError(data.detail || "Invalid code");
                    inputs.forEach(i => { i.value = ""; });
                    inputs[0].focus();
                }
            } catch (err) {
                showError("Connection error. Please try again.");
            } finally {
                setLoading("resetBtn", false);
            }
        }

        // ==================== OTP Input Navigation ====================

        function setupOtpInputs(container, inputSelector = ".otp-input", onComplete = null) {
            const inputs = container.querySelectorAll(inputSelector);
            inputs.forEach((input, index) => {
                input.addEventListener("input", (e) => {
                    e.target.value = e.target.value.replace(/[^0-9]/g, "");
                    if (e.target.value && index < inputs.length - 1) {
                        inputs[index + 1].focus();
                    }
                    const allFilled = Array.from(inputs).every(i => i.value && i.value.length === 1);
                    if (allFilled && typeof onComplete === "function") {
                        setTimeout(() => onComplete(), 80);
                    }
                });
                input.addEventListener("keydown", (e) => {
                    if (e.key === "Backspace" && !e.target.value && index > 0) {
                        inputs[index - 1].focus();
                    }
                });
                input.addEventListener("paste", (e) => {
                    e.preventDefault();
                    const paste = (e.clipboardData || window.clipboardData).getData("text");
                    const digits = paste.replace(/[^0-9]/g, "").slice(0, 6);
                    digits.split("").forEach((d, i) => {
                        if (inputs[i]) inputs[i].value = d;
                    });
                    if (digits.length > 0) {
                        inputs[Math.min(digits.length, inputs.length) - 1].focus();
                    }
                    if (digits.length === inputs.length && typeof onComplete === "function") {
                        setTimeout(() => onComplete(), 80);
                    }
                });
            });
        }

        setupOtpInputs(document.getElementById("loginOtpInputs"), ".otp-input", async () => {
            if (activeSection !== "login" || loginState !== "otp" || loginOtpAutoBusy) return;
            loginOtpAutoBusy = true;
            try {
                await handleOTPVerify();
            } finally {
                setTimeout(() => { loginOtpAutoBusy = false; }, 180);
            }
        });
        setupOtpInputs(document.getElementById("signupOtpInputs"), ".otp-input", async () => {
            if (activeSection !== "signup" || signupState !== "otp" || signupOtpAutoBusy) return;
            signupOtpAutoBusy = true;
            try {
                await handleSignupOTPVerify();
            } finally {
                setTimeout(() => { signupOtpAutoBusy = false; }, 180);
            }
        });
        setupOtpInputs(document.getElementById("resetOtpInputs"), ".otp-input", async () => {
            if (activeSection !== "resetOtp" || resetState !== "otp" || resetOtpAutoBusy) return;
            resetOtpAutoBusy = true;
            try {
                await handleResetOtpVerify();
            } finally {
                setTimeout(() => { resetOtpAutoBusy = false; }, 180);
            }
        });
        if (document.getElementById("pkOtpInputs")) {
            setupOtpInputs(document.getElementById("pkOtpInputs"), ".pk-otp-input", async () => {
                if (activeSection !== "login" || passkeyOtpAutoBusy || passkeyPendingOptions) return;
                const otpInline = document.getElementById("passkeyOtpInline");
                if (!otpInline || !otpInline.classList.contains("active")) return;
                passkeyOtpAutoBusy = true;
                try {
                    await handlePasskeyOtpVerify();
                } finally {
                    setTimeout(() => { passkeyOtpAutoBusy = false; }, 180);
                }
            });
        }

        // ==================== UI Helpers ====================

        function showError(msg) {
            const el = document.getElementById("errorMsg");
            el.textContent = msg;
            el.className = "msg error";
            document.getElementById("successMsg").className = "msg";
        }

        function showSuccess(msg) {
            const el = document.getElementById("successMsg");
            el.textContent = msg;
            el.className = "msg success";
            document.getElementById("errorMsg").className = "msg";
        }

        function clearMessages() {
            document.getElementById("errorMsg").className = "msg";
            document.getElementById("successMsg").className = "msg";
        }

        function setLoading(btnId, loading, loadingText = null) {
            const btn = document.getElementById(btnId);
            if (!btn) return;

            const labelEl = btn.querySelector(".btn-label");
            if (labelEl && !btn.dataset.defaultLabel) {
                btn.dataset.defaultLabel = labelEl.textContent.trim();
            }

            btn.classList.toggle("loading", loading);
            btn.disabled = loading;

            if (labelEl) {
                if (loading && loadingText) {
                    labelEl.textContent = loadingText;
                } else if (!loading && btn.dataset.defaultLabel) {
                    labelEl.textContent = btn.dataset.defaultLabel;
                }
            }
        }

        function setupMobileKeyboardAwareLayout() {
            const MOBILE_BREAKPOINT = 720;
            const OPEN_THRESHOLD = 120;

            const updateKeyboardState = () => {
                if (window.innerWidth > MOBILE_BREAKPOINT) {
                    document.body.classList.remove("keyboard-open");
                    return;
                }

                if (!window.visualViewport) {
                    document.body.classList.remove("keyboard-open");
                    return;
                }

                const keyboardOpen = window.visualViewport.height < (window.innerHeight - OPEN_THRESHOLD);
                document.body.classList.toggle("keyboard-open", keyboardOpen);
            };

            updateKeyboardState();

            if (window.visualViewport) {
                window.visualViewport.addEventListener("resize", updateKeyboardState);
                window.visualViewport.addEventListener("scroll", updateKeyboardState);
            }

            window.addEventListener("resize", updateKeyboardState);
            window.addEventListener("orientationchange", () => {
                setTimeout(updateKeyboardState, 120);
            });
        }

        setupMobileKeyboardAwareLayout();
