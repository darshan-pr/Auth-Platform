from app.api import admin_core as core

for _name, _value in core.__dict__.items():
    if not _name.startswith("__"):
        globals()[_name] = _value

@router.post("/register", response_model=dict, dependencies=[Depends(_rl_admin_register)])
def admin_register(request: AdminRegisterRequest, db: Session = Depends(get_db)):
    """Step 1: Validate input and send OTP to admin email for verification"""
    from app.services.otp_service import generate_otp
    from app.services.mail_service import send_otp_email

    try:
        enforce_password_strength(request.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    
    # Check if admin already exists
    existing = db.query(Admin).filter(Admin.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An admin with this email already exists"
        )
    
    # Store pending registration data in Redis (expires in 10 minutes)
    import json
    pending_key = f"admin_pending_reg:{request.email}"
    _redis_client().setex(pending_key, 600, json.dumps({
        "email": request.email,
        "password": request.password,
        "tenant_name": request.tenant_name
    }))
    
    # Generate and send OTP
    otp = generate_otp(request.email)
    send_otp_email(request.email, otp, "Auth Platform Admin", ADMIN_EMAIL_LOGO_URL)
    
    return {"message": "OTP sent to your email. Please verify to complete registration.", "email": request.email}

@router.post("/register/verify-otp", response_model=dict)
def admin_register_verify_otp(
    request: AdminVerifyOTPRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    """Step 2: Verify OTP and complete admin registration (no auto-login)."""
    from app.services.otp_service import verify_otp
    import json
    
    # Verify OTP
    if not verify_otp(request.email, request.otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )
    
    # Retrieve pending registration data
    pending_key = f"admin_pending_reg:{request.email}"
    pending_data = _redis_client().get(pending_key)
    if not pending_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration session expired. Please start again."
        )
    
    data = json.loads(pending_data)
    _redis_client().delete(pending_key)
    
    # Double-check admin doesn't exist (race condition guard)
    existing = db.query(Admin).filter(Admin.email == data["email"]).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An admin with this email already exists"
        )
    
    # Create tenant
    tenant = create_tenant(db, data["tenant_name"])
    
    # Create admin
    admin = Admin(
        email=data["email"],
        password_hash=hash_password(data["password"]),
        tenant_id=tenant.id
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    db.refresh(tenant)
    
    # Non-blocking welcome email for new admin signup
    send_admin_welcome_email(to=admin.email, tenant_name=tenant.name, app_name="Auth Platform", app_logo_url=ADMIN_EMAIL_LOGO_URL)

    return _issue_admin_login_response(
        admin=admin,
        request=http_request,
        db=db,
        event_type="register",
        details="Admin registration successful",
        extra_content={
            "admin_id": admin.id,
            "tenant_id": tenant.id,
            "tenant_name": tenant.name,
            "message": "Admin registered successfully",
        },
    )


@router.post("/login", response_model=dict, dependencies=[Depends(_rl_admin_login)])
def admin_login(request: AdminLoginRequest, http_request: Request, db: Session = Depends(get_db)):
    """Admin login — sets JWT as HttpOnly cookie with brute-force protection"""
    # Check lockout
    normalized_email = request.email.strip().lower()
    _check_admin_lockout(normalized_email)

    admin = db.query(Admin).filter(func.lower(Admin.email) == normalized_email).first()
    if not admin or not verify_password(request.password, admin.password_hash):
        _record_admin_failed_login(normalized_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Clear failed attempts on password success.
    _clear_admin_login_attempts(normalized_email)

    if admin.mfa_enabled:
        from app.services.otp_service import generate_otp
        try:
            otp = generate_otp(admin.email)
            send_otp_email(admin.email, otp, "Auth Platform Admin", ADMIN_EMAIL_LOGO_URL)
        except Exception as e:
            logger.warning(f"Failed to send admin MFA OTP to {admin.email}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send MFA code. Please try again.",
            )

        mfa_ticket = secrets.token_urlsafe(24)
        _redis_client().setex(f"{ADMIN_MFA_LOGIN_TICKET_PREFIX}:{mfa_ticket}", 300, str(admin.id))
        return {
            "mfa_required": True,
            "mfa_ticket": mfa_ticket,
            "message": "MFA code sent to your email. Enter the 6-digit code to continue.",
        }

    return _issue_admin_login_response(
        admin=admin,
        request=http_request,
        db=db,
        event_type="login",
        details="Admin login successful",
    )


@router.post("/login/verify-mfa", response_model=dict, dependencies=[Depends(_rl_admin_otp)])
def admin_login_verify_mfa(
    request: AdminLoginMFAVerifyRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    """Verify an MFA OTP after password login and issue admin session cookie."""
    if not request.mfa_ticket.strip():
        raise HTTPException(status_code=400, detail="MFA ticket is required")

    ticket_key = f"{ADMIN_MFA_LOGIN_TICKET_PREFIX}:{request.mfa_ticket}"
    admin_id_value = _redis_client().get(ticket_key)
    if not admin_id_value or not str(admin_id_value).isdigit():
        raise HTTPException(status_code=400, detail="MFA session expired. Please sign in again.")

    admin = db.query(Admin).filter(Admin.id == int(admin_id_value)).first()
    if not admin or not admin.mfa_enabled:
        raise HTTPException(status_code=401, detail="MFA validation failed")

    from app.services.otp_service import verify_otp
    # Differentiate "code expired/missing" vs "wrong code" so the UI can
    # avoid prematurely forcing users back to the base login form.
    otp_key = f"otp:{admin.email}"
    if not _redis_client().get(otp_key):
        raise HTTPException(status_code=400, detail="MFA code expired. Please sign in again.")

    if not verify_otp(admin.email, request.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    _redis_client().delete(ticket_key)
    return _issue_admin_login_response(
        admin=admin,
        request=http_request,
        db=db,
        event_type="login_mfa",
        details="Admin login successful with MFA",
    )


@router.post("/passkeys/check", response_model=dict)
def admin_passkey_check(request: AdminPasskeyCheckRequest, db: Session = Depends(get_db)):
    """Check if an admin account has at least one passkey enrolled."""
    normalized_email = request.email.strip().lower()
    admin = db.query(Admin).filter(func.lower(Admin.email) == normalized_email).first()
    if not admin:
        return {"has_passkey": False}

    has_passkey = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.admin_id == admin.id
    ).count() > 0
    return {"has_passkey": has_passkey}


@router.post("/passkeys/login/begin", response_model=dict, dependencies=[Depends(_rl_admin_login)])
def admin_passkey_login_begin(
    request: AdminPasskeyLoginBeginRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    """Start admin passkey login by returning WebAuthn challenge options."""
    normalized_email = request.email.strip().lower()
    admin = db.query(Admin).filter(func.lower(Admin.email) == normalized_email).first()
    if not admin:
        return {"has_passkey": False, "message": "No passkey is linked to this account yet."}

    creds = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.admin_id == admin.id
    ).all()
    if not creds:
        return {"has_passkey": False, "message": "No passkey is linked to this account yet."}

    rp_id = _resolve_rp_id_from_request(http_request)
    options = generate_passkey_auth_challenge(
        ADMIN_PASSKEY_SCOPE,
        rp_id,
        credential_ids=[cred.credential_id for cred in creds],
    )
    return {"has_passkey": True, "options": options}


@router.post("/passkeys/login/complete", response_model=dict, dependencies=[Depends(_rl_admin_login)])
def admin_passkey_login_complete(
    request: AdminPasskeyLoginCompleteRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    """Complete admin passkey login and issue admin session cookie."""
    normalized_email = request.email.strip().lower()
    admin = db.query(Admin).filter(func.lower(Admin.email) == normalized_email).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Passkey does not match this account")

    stored_cred = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.credential_id == request.credential.id,
        AdminPasskeyCredential.admin_id == admin.id,
    ).first()
    if not stored_cred:
        raise HTTPException(status_code=401, detail="Passkey does not match this account")

    rp_id = _resolve_rp_id_from_request(http_request)
    new_sign_count = verify_passkey_authentication(
        app_id=ADMIN_PASSKEY_SCOPE,
        rp_id=rp_id,
        credential_id=request.credential.id,
        client_data_json_b64=request.credential.clientDataJSON,
        authenticator_data_b64=request.credential.authenticatorData or "",
        signature_b64=request.credential.signature or "",
        stored_public_key_b64=stored_cred.public_key,
        stored_sign_count=stored_cred.sign_count,
        stored_algorithm=stored_cred.algorithm,
    )
    if new_sign_count is None:
        raise HTTPException(status_code=401, detail="Passkey verification failed")

    stored_cred.sign_count = new_sign_count
    stored_cred.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return _issue_admin_login_response(
        admin=admin,
        request=http_request,
        db=db,
        event_type="login_passkey",
        details="Admin login successful with passkey",
    )


@router.post("/logout")
def admin_logout(http_request: Request, db: Session = Depends(get_db)):
    """Admin logout — clears the HttpOnly cookie"""
    token = http_request.cookies.get(ADMIN_TOKEN_COOKIE)
    admin = None
    admin_session_id = None

    if token:
        payload = verify_token(token)
        if payload and payload.get("type") == "admin_access":
            admin = db.query(Admin).filter(Admin.id == payload.get("admin_id")).first()
            if admin:
                admin_session_id = _resolve_admin_session_id(payload, token)
                revoke_admin_session(db, admin.id, admin_session_id, reason="logout")
                log_admin_activity(
                    db=db,
                    admin=admin,
                    request=http_request,
                    event_type="logout",
                    session_id=admin_session_id,
                    resource="/admin/logout",
                    method="POST",
                    details="Admin logged out",
                )

    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key=ADMIN_TOKEN_COOKIE, path="/")
    response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    return response


@router.post("/forgot-password", response_model=dict, dependencies=[Depends(_rl_admin_forgot)])
def admin_forgot_password(request: AdminForgotPasswordRequest, db: Session = Depends(get_db)):
    """Request admin password reset OTP (generic response to prevent email enumeration)."""
    admin = db.query(Admin).filter(Admin.email == request.email).first()

    if admin:
        from app.services.otp_service import generate_password_reset_otp
        try:
            otp = generate_password_reset_otp(request.email, ADMIN_RESET_SCOPE)
            send_password_reset_email(request.email, otp, "Auth Platform Admin", ADMIN_EMAIL_LOGO_URL)
        except Exception as e:
            logger.warning(f"Failed sending admin password reset OTP to {request.email}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send reset code. Please try again."
            )

    return {
        "message": "If an account with this email exists, a password reset code has been sent.",
        "email": request.email
    }


@router.post("/forgot-password/verify-otp", response_model=dict, dependencies=[Depends(_rl_admin_otp)])
def admin_verify_forgot_password_otp(request: AdminForgotPasswordVerifyOTPRequest, db: Session = Depends(get_db)):
    """Verify admin forgot-password OTP and mark reset flow as verified."""
    from app.services.otp_service import verify_password_reset_otp, mark_password_reset_otp_verified

    if not verify_password_reset_otp(request.email, ADMIN_RESET_SCOPE, request.otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )

    admin = db.query(Admin).filter(Admin.email == request.email).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

    mark_password_reset_otp_verified(request.email, ADMIN_RESET_SCOPE)
    return {"message": "Code verified. You can now set a new password.", "email": request.email}


@router.post("/reset-password", response_model=dict)
def admin_reset_password(request: AdminResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset admin password after OTP verification."""
    from app.services.otp_service import is_password_reset_otp_verified, clear_password_reset_otp_verified

    try:
        enforce_password_strength(request.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not is_password_reset_otp_verified(request.email, ADMIN_RESET_SCOPE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your reset code first."
        )

    admin = db.query(Admin).filter(Admin.email == request.email).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

    admin.password_hash = hash_password(request.new_password)
    db.commit()
    clear_password_reset_otp_verified(request.email, ADMIN_RESET_SCOPE)
    _clear_admin_login_attempts(request.email)

    return {"message": "Password reset successful. Please sign in.", "email": request.email}


# ============== Admin Settings ==============

@router.get("/settings/profile", response_model=dict)
def get_admin_profile(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    return {
        "email": admin.email,
        "tenant_name": tenant.name if tenant else "",
        "tenant_slug": tenant.slug if tenant else "",
        "mfa_enabled": bool(admin.mfa_enabled),
    }


@router.put("/settings/profile", response_model=dict)
def update_admin_profile(
    request: AdminProfileUpdateRequest,
    http_request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    changed = False

    if request.email is not None:
        normalized_email = str(request.email).strip().lower()
        if normalized_email != (admin.email or "").lower():
            existing = db.query(Admin).filter(func.lower(Admin.email) == normalized_email).first()
            if existing and existing.id != admin.id:
                raise HTTPException(status_code=400, detail="An admin with this email already exists")
            admin.email = normalized_email
            changed = True

    if changed:
        db.commit()
        db.refresh(admin)
        current_session_id = getattr(http_request.state, "admin_session_id", None)
        log_admin_activity(
            db=db,
            admin=admin,
            request=http_request,
            event_type="profile_update",
            session_id=current_session_id,
            resource="/admin/settings/profile",
            method="PUT",
            details="Admin profile updated",
        )

    return {
        "email": admin.email,
        "mfa_enabled": bool(admin.mfa_enabled),
        "message": "Profile updated successfully" if changed else "No changes applied",
    }


@router.get("/settings/security", response_model=dict)
def get_admin_security_settings(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    passkeys = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.admin_id == admin.id
    ).order_by(AdminPasskeyCredential.created_at.desc()).all()

    return {
        "mfa_enabled": bool(admin.mfa_enabled),
        "passkey_count": len(passkeys),
        "passkeys": [
            {
                "id": p.id,
                "device_name": p.device_name or "Admin Device",
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None,
            }
            for p in passkeys
        ],
    }


@router.post("/settings/passkeys/register/begin", response_model=dict)
def begin_admin_passkey_registration(
    http_request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    rp_id = _resolve_rp_id_from_request(http_request)
    options = generate_passkey_registration_challenge(
        user_email=admin.email,
        app_id=ADMIN_PASSKEY_SCOPE,
        rp_id=rp_id,
    )

    existing = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.admin_id == admin.id
    ).all()
    if existing:
        options["excludeCredentials"] = [
            {"type": "public-key", "id": cred.credential_id}
            for cred in existing
        ]

    return {"options": options}


@router.post("/settings/passkeys/register/complete", response_model=dict)
def complete_admin_passkey_registration(
    request: AdminPasskeyRegisterCompleteRequest,
    http_request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    payload = request.credential
    if not payload.id or not payload.clientDataJSON or not payload.attestationObject:
        raise HTTPException(status_code=400, detail="Invalid passkey payload")

    rp_id = _resolve_rp_id_from_request(http_request)
    result = verify_passkey_registration(
        user_email=admin.email,
        app_id=ADMIN_PASSKEY_SCOPE,
        rp_id=rp_id,
        credential_id=payload.id,
        client_data_json_b64=payload.clientDataJSON,
        attestation_object_b64=payload.attestationObject,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Passkey registration verification failed")

    existing = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.credential_id == result["credential_id"]
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="This passkey is already registered")

    passkey = AdminPasskeyCredential(
        admin_id=admin.id,
        tenant_id=admin.tenant_id,
        credential_id=result["credential_id"],
        public_key=result["public_key"],
        sign_count=result["sign_count"],
        algorithm=result.get("algorithm", -7),
        device_name=payload.deviceName or "Admin Device",
    )
    db.add(passkey)
    db.commit()
    db.refresh(passkey)

    current_session_id = getattr(http_request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=http_request,
        event_type="passkey_register",
        session_id=current_session_id,
        resource="/admin/settings/passkeys/register/complete",
        method="POST",
        details=f"Registered passkey {passkey.id}",
    )

    return {
        "message": "Passkey setup complete. You can now sign in with passkey.",
        "passkey_id": passkey.id,
    }


@router.delete("/settings/passkeys/{passkey_id}", response_model=dict)
def delete_admin_passkey(
    passkey_id: int,
    http_request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    passkey = db.query(AdminPasskeyCredential).filter(
        AdminPasskeyCredential.id == passkey_id,
        AdminPasskeyCredential.admin_id == admin.id,
    ).first()
    if not passkey:
        raise HTTPException(status_code=404, detail="Passkey not found")

    db.delete(passkey)
    db.commit()

    current_session_id = getattr(http_request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=http_request,
        event_type="passkey_delete",
        session_id=current_session_id,
        resource=f"/admin/settings/passkeys/{passkey_id}",
        method="DELETE",
        details=f"Removed passkey {passkey_id}",
    )

    return {"message": "Passkey removed successfully"}


@router.post("/settings/mfa/request-otp", response_model=dict, dependencies=[Depends(_rl_admin_otp)])
def request_admin_mfa_setup_otp(
    request: AdminMFARequestOTPRequest,
    admin: Admin = Depends(get_current_admin),
):
    action = (request.action or "enable").strip().lower()
    if action not in {"enable", "disable"}:
        raise HTTPException(status_code=400, detail="action must be enable or disable")

    from app.services.otp_service import generate_otp

    try:
        otp = generate_otp(admin.email)
        send_otp_email(admin.email, otp, "Auth Platform Admin", ADMIN_EMAIL_LOGO_URL)
    except Exception as e:
        logger.warning(f"Failed to send admin MFA setup OTP to {admin.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification code. Please try again.",
        )

    _redis_client().setex(f"{ADMIN_MFA_SETUP_KEY_PREFIX}:{admin.id}", 300, action)

    return {
        "message": "Verification code sent to your email.",
        "action": action,
    }


@router.post("/settings/mfa/verify", response_model=dict, dependencies=[Depends(_rl_admin_otp)])
def verify_admin_mfa_setup(
    request: AdminMFASetupVerifyRequest,
    http_request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    setup_key = f"{ADMIN_MFA_SETUP_KEY_PREFIX}:{admin.id}"
    action = _redis_client().get(setup_key)
    if action not in {"enable", "disable"}:
        raise HTTPException(status_code=400, detail="MFA setup request expired. Request a new code.")

    from app.services.otp_service import verify_otp
    if not verify_otp(admin.email, request.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

    admin.mfa_enabled = action == "enable"
    db.commit()
    db.refresh(admin)
    _redis_client().delete(setup_key)

    current_session_id = getattr(http_request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=http_request,
        event_type="mfa_enable" if admin.mfa_enabled else "mfa_disable",
        session_id=current_session_id,
        resource="/admin/settings/mfa/verify",
        method="POST",
        details="MFA enabled" if admin.mfa_enabled else "MFA disabled",
    )

    return {
        "message": "MFA enabled successfully." if admin.mfa_enabled else "MFA disabled successfully.",
        "mfa_enabled": bool(admin.mfa_enabled),
    }


# ============== Tenant Management ==============

@router.get("/tenant", response_model=dict)
def get_tenant(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Get the current admin's tenant details"""
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None
    }


@router.put("/tenant", response_model=dict)
def update_tenant(
    request: TenantUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update the current admin's tenant"""
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    if request.name is not None:
        tenant.name = request.name
    
    db.commit()
    db.refresh(tenant)
    
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "message": "Tenant updated successfully"
    }
