from app.api import admin_core as core

for _name, _value in core.__dict__.items():
    if not _name.startswith("__"):
        globals()[_name] = _value

@router.post("/apps", response_model=dict)
def create_app(
    request: AppCreateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create a new application under the admin's tenant"""
    created_logo_url: Optional[str] = None
    try:
        app_id = secrets.token_hex(8)
        app_secret = secrets.token_hex(16)
        app_secret_hash = _hash_app_secret(app_secret)
        logo_url = _sanitize_logo_url(request.logo_url)
        if request.logo_data_url and request.logo_data_url.strip():
            logo_url = _store_logo_data_url(request.logo_data_url, app_id)
            created_logo_url = logo_url

        app = App(
            app_id=app_id, 
            app_secret=app_secret_hash,
            tenant_id=admin.tenant_id,
            name=request.name,
            description=request.description,
            logo_url=logo_url,
            oauth_enabled=request.oauth_enabled,
            otp_enabled=request.otp_enabled,
            login_notification_enabled=request.login_notification_enabled,
            force_logout_notification_enabled=request.force_logout_notification_enabled,
            passkey_enabled=request.passkey_enabled,
            access_token_expiry_minutes=request.access_token_expiry_minutes,
            refresh_token_expiry_days=request.refresh_token_expiry_days,
            redirect_uris=request.redirect_uris
        )
        db.add(app)
        db.commit()
        db.refresh(app)

        return {
            "id": app.id,
            "app_id": app_id, 
            "app_secret": app_secret,  # Plaintext shown ONLY on creation
            "name": app.name,
            "logo_url": app.logo_url,
            "tenant_id": app.tenant_id,
            "oauth_enabled": app.oauth_enabled,
            "otp_enabled": app.otp_enabled,
            "login_notification_enabled": app.login_notification_enabled,
            "force_logout_notification_enabled": app.force_logout_notification_enabled,
            "passkey_enabled": app.passkey_enabled,
            "access_token_expiry_minutes": app.access_token_expiry_minutes,
            "refresh_token_expiry_days": app.refresh_token_expiry_days,
            "redirect_uris": app.redirect_uris,
            "message": "App created successfully"
        }
    except HTTPException:
        db.rollback()
        if created_logo_url:
            _cleanup_local_logo(created_logo_url)
        raise
    except Exception as e:
        db.rollback()
        if created_logo_url:
            _cleanup_local_logo(created_logo_url)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create app: {str(e)}"
        )

# Keep old endpoint for backward compatibility
@router.post("/create-app", response_model=dict, include_in_schema=False)
def create_app_legacy(
    request: AppCreateRequest = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    if request is None:
        request = AppCreateRequest(name="Unnamed App")
    return create_app(request, admin, db)

@router.get("/apps", response_model=list[dict])
def list_apps(
    search: Optional[str] = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """List applications for the admin's tenant"""
    query = db.query(App).filter(App.tenant_id == admin.tenant_id)
    
    if search:
        query = query.filter(
            or_(
                App.name.ilike(f"%{search}%"),
                App.app_id.ilike(f"%{search}%")
            )
        )
    
    apps = query.order_by(App.created_at.desc()).all()
    return [{
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "logo_url": app.logo_url,
        "tenant_id": app.tenant_id,
        "is_active": True,  # All apps are active by default
        "oauth_enabled": app.oauth_enabled,
        "otp_enabled": app.otp_enabled,
        "passkey_enabled": app.passkey_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None
    } for app in apps]

@router.get("/apps/{app_id}", response_model=dict)
def get_app(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get a specific application by app_id (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "logo_url": app.logo_url,
        "tenant_id": app.tenant_id,
        "oauth_enabled": app.oauth_enabled,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None
    }

@router.put("/apps/{app_id}", response_model=dict)
def update_app(
    app_id: str,
    request: AppUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update an application's properties (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    previous_logo = app.logo_url
    uploaded_logo_url: Optional[str] = None
    try:
        if request.name is not None:
            app.name = request.name
        if request.description is not None:
            app.description = request.description
        if request.oauth_enabled is not None:
            app.oauth_enabled = request.oauth_enabled
        if request.otp_enabled is not None:
            app.otp_enabled = request.otp_enabled
        if request.login_notification_enabled is not None:
            app.login_notification_enabled = request.login_notification_enabled
        if request.force_logout_notification_enabled is not None:
            app.force_logout_notification_enabled = request.force_logout_notification_enabled
        if request.passkey_enabled is not None:
            app.passkey_enabled = request.passkey_enabled
        if request.access_token_expiry_minutes is not None:
            app.access_token_expiry_minutes = request.access_token_expiry_minutes
        if request.refresh_token_expiry_days is not None:
            app.refresh_token_expiry_days = request.refresh_token_expiry_days
        if request.redirect_uris is not None:
            app.redirect_uris = request.redirect_uris

        if request.logo_data_url and request.logo_data_url.strip():
            uploaded_logo_url = _store_logo_data_url(request.logo_data_url, app.app_id)
            app.logo_url = uploaded_logo_url
        elif request.logo_url is not None:
            cleaned_logo = _sanitize_logo_url(request.logo_url, allow_empty=True)
            app.logo_url = cleaned_logo or None

        db.commit()
        db.refresh(app)
    except Exception:
        db.rollback()
        if uploaded_logo_url and uploaded_logo_url != previous_logo:
            _cleanup_local_logo(uploaded_logo_url)
        raise

    if previous_logo != app.logo_url:
        _cleanup_local_logo(previous_logo)
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "logo_url": app.logo_url,
        "tenant_id": app.tenant_id,
        "oauth_enabled": app.oauth_enabled,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "message": "App updated successfully"
    }

@router.delete("/apps/{app_id}")
def delete_app(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete an application and all its associated data (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    # Delete passkey credentials for this app within the tenant
    db.query(PasskeyCredential).filter(
        PasskeyCredential.app_id == app_id,
        PasskeyCredential.tenant_id == admin.tenant_id
    ).delete()
    # Delete all users associated with this app within the tenant
    db.query(User).filter(
        User.app_id == app_id,
        User.tenant_id == admin.tenant_id
    ).delete()
    _cleanup_local_logo(app.logo_url)
    db.delete(app)
    db.commit()
    
    return {"message": "App and its associated data deleted successfully"}

@router.get("/apps/{app_id}/credentials", response_model=AppCredentialsResponse)
def get_app_credentials(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get the credentials for an application (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return AppCredentialsResponse(app_id=app.app_id, app_secret_hint="****" + app.app_secret[-4:] if len(app.app_secret) > 4 else "****")

@router.post("/apps/{app_id}/regenerate-secret", response_model=AppCredentialsResponse)
def regenerate_app_secret(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Regenerate the secret for an application (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    new_secret = secrets.token_hex(16)
    app.app_secret = _hash_app_secret(new_secret)
    db.commit()
    db.refresh(app)
    
    # Return plaintext just this once; also include the hint for display
    return {"app_id": app.app_id, "app_secret": new_secret, "app_secret_hint": "****" + new_secret[-4:]}
