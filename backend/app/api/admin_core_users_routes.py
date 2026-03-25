from app.api import admin_core as core

for _name, _value in core.__dict__.items():
    if not _name.startswith("__"):
        globals()[_name] = _value

@router.get("/users", response_model=dict)
def list_users(
    search: Optional[str] = None,
    app_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(default=50, le=100),
    offset: int = 0,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """List all users within the admin's tenant"""
    query = db.query(User).filter(User.tenant_id == admin.tenant_id)
    
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))
    if app_id:
        query = query.filter(User.app_id == app_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    online_map = get_online_status_map([user.id for user in users], admin.tenant_id)
    
    return {
        "total": total,
        "users": [{
            "id": user.id,
            "email": user.email,
            "app_id": user.app_id,
            "tenant_id": user.tenant_id,
            "is_active": user.is_active,
            "is_online": bool(online_map.get(user.id)),
            "created_at": user.created_at.isoformat() if user.created_at else None
        } for user in users]
    }

@router.post("/users", response_model=dict)
def create_user(
    request: UserCreateRequest,
    http_request: Request = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create a new user within the admin's tenant and send a set-password invite email"""
    if not request.app_id:
        raise HTTPException(status_code=400, detail="app_id is required")
    
    # Validate app belongs to the admin's tenant
    app = db.query(App).filter(
        App.app_id == request.app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=400, detail="App not found in your tenant")
    
    # Check if user already exists in this app (same email can exist in different apps)
    existing = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == admin.tenant_id,
        User.app_id == request.app_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists in this app")
    
    user = User(
        email=request.email,
        app_id=request.app_id,
        tenant_id=admin.tenant_id,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate a reset token and send set-password email
    invite_sent = False
    try:
        token = generate_reset_token(user.email, request.app_id)
        base_url = str(http_request.base_url).rstrip("/") if http_request else ""
        reset_link = f"{base_url}/reset-password?token={token}&email={user.email}&app_id={request.app_id}"
        app_name = app.name or "Application"
        send_set_password_email(user.email, reset_link, app_name, app.logo_url)
        invite_sent = True
    except Exception as e:
        logger.warning(f"Failed to send set-password email to {user.email}: {e}")
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "invite_sent": invite_sent,
        "message": "User created successfully" + (" and invite email sent" if invite_sent else " (invite email failed)")
    }

@router.post("/users/bulk-action")
def bulk_user_action(
    request: BulkActionRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Perform a bulk action on multiple users (scoped to admin's tenant)"""
    if request.action not in ("delete", "force-logout", "set-inactive"):
        raise HTTPException(status_code=400, detail="Invalid action. Must be: delete, force-logout, or set-inactive")

    if not request.user_ids:
        raise HTTPException(status_code=400, detail="No user IDs provided")

    # Fetch all matching users scoped to the admin's tenant
    target_users = db.query(User).filter(
        User.id.in_(request.user_ids),
        User.tenant_id == admin.tenant_id
    ).all()

    if not target_users:
        raise HTTPException(status_code=404, detail="No matching users found in your tenant")

    results = {"processed": 0, "skipped": 0, "emails_sent": 0}

    if request.action == "delete":
        for user in target_users:
            # Revoke session only when the user is currently online.
            if is_user_online(user.id, admin.tenant_id):
                force_user_offline(user.id, admin.tenant_id)
            db.query(PasskeyCredential).filter(
                PasskeyCredential.user_id == user.id,
                PasskeyCredential.tenant_id == admin.tenant_id
            ).delete()
            db.delete(user)
            results["processed"] += 1
        db.commit()

    elif request.action == "force-logout":
        for user in target_users:
            force_user_offline(user.id, admin.tenant_id)
            results["processed"] += 1
            # Send notification email if enabled
            try:
                app_name = "Auth Platform"
                app_logo_url = None
                send_email = False
                if user.app_id:
                    app_obj = db.query(App).filter(App.app_id == user.app_id).first()
                    if app_obj:
                        if app_obj.name:
                            app_name = app_obj.name
                        app_logo_url = app_obj.logo_url
                        send_email = app_obj.force_logout_notification_enabled
                if send_email:
                    if send_force_logout_email(user.email, app_name, app_logo_url):
                        results["emails_sent"] += 1
            except Exception:
                pass

    elif request.action == "set-inactive":
        for user in target_users:
            user.is_active = False
            results["processed"] += 1
        db.commit()

    return {
        "message": f"Bulk {request.action} completed",
        "action": request.action,
        **results,
        "total_requested": len(request.user_ids)
    }


@router.get("/users/{user_id}", response_model=dict)
def get_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get a specific user by ID (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    }

@router.put("/users/{user_id}", response_model=dict)
def update_user(
    user_id: int,
    request: UserUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update a user's properties (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.is_active is not None:
        user.is_active = request.is_active
    if request.app_id is not None:
        # Validate the target app belongs to the same tenant
        app = db.query(App).filter(
            App.app_id == request.app_id,
            App.tenant_id == admin.tenant_id
        ).first()
        if not app:
            raise HTTPException(status_code=400, detail="Target app not found in your tenant")
        user.app_id = request.app_id
    
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "message": "User updated successfully"
    }

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete a user (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Revoke active sessions before deleting user data only if user is online.
    if is_user_online(user.id, admin.tenant_id):
        force_user_offline(user.id, admin.tenant_id)
    
    # Delete user's passkey credentials
    db.query(PasskeyCredential).filter(
        PasskeyCredential.user_id == user.id,
        PasskeyCredential.tenant_id == admin.tenant_id
    ).delete()
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}


@router.post("/users/{user_id}/force-logout")
def force_logout_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Force a user offline – invalidates their session immediately and sends a notification email"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    force_user_offline(user.id, admin.tenant_id)

    # Send notification email if enabled for this app (non-blocking, best-effort)
    email_sent = False
    try:
        app_name = "Auth Platform"
        app_logo_url = None
        send_email = False
        if user.app_id:
            app_obj = db.query(App).filter(App.app_id == user.app_id).first()
            if app_obj:
                if app_obj.name:
                    app_name = app_obj.name
                app_logo_url = app_obj.logo_url
                send_email = app_obj.force_logout_notification_enabled
        if send_email:
            email_sent = send_force_logout_email(user.email, app_name, app_logo_url)
    except Exception as e:
        logger.warning(f"Failed to send force-logout email to {user.email}: {e}")
    
    return {
        "message": f"User {user.email} has been forced offline",
        "user_id": user.id,
        "is_online": False,
        "email_sent": email_sent
    }
