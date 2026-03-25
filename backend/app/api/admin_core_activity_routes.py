from app.api import admin_core as core

for _name, _value in core.__dict__.items():
    if not _name.startswith("__"):
        globals()[_name] = _value

@router.get("/my-auth-activity/sessions")
def list_my_admin_sessions(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """List active sessions for the current identity across admin console and client apps."""
    now = _utc_now()
    current_session_id = getattr(request.state, "admin_session_id", None)

    admin_sessions = db.query(AdminSession).filter(
        AdminSession.admin_id == admin.id,
        AdminSession.is_revoked == False,
        or_(AdminSession.expires_at.is_(None), AdminSession.expires_at >= now),
    ).order_by(AdminSession.login_at.desc()).all()

    payload_sessions = []
    for s in admin_sessions:
        login_dt = _to_utc_naive(s.login_at) or datetime.min
        payload_sessions.append({
            "session_id": s.session_id,
            "session_type": "admin_console",
            "source_label": "Admin Console",
            "app_id": None,
            "app_name": "Admin Console",
            "device": s.device or "Unknown",
            "browser": s.browser or "Unknown",
            "ip_address": s.ip_address or "Unknown",
            "city": s.city,
            "region": s.region,
            "country": s.country,
            "location": _format_location(s.city, s.region, s.country),
            "login_at": s.login_at.isoformat() if s.login_at else None,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "is_current": s.session_id == current_session_id,
            "_sort_key": login_dt,
        })

    # Also include currently active client-app sessions linked to this admin identity.
    related_users = _related_identity_users(db, admin, active_only=True)
    if related_users:
        user_ids = [u.id for u in related_users]
        latest_by_user = _latest_login_events_by_user_id(db, admin.tenant_id, user_ids)
        tenant_apps = db.query(App).filter(App.tenant_id == admin.tenant_id).all()
        app_name_by_id = {app.app_id: (app.name or app.app_id) for app in tenant_apps}

        for user in related_users:
            if not user.app_id:
                continue
            if not is_user_online(user.id, admin.tenant_id):
                continue

            event = latest_by_user.get(user.id)
            event_created = _to_utc_naive(event.created_at) if event and event.created_at else None
            payload_sessions.append({
                "session_id": _build_client_session_id(user.id, user.app_id),
                "session_type": "client_app",
                "source_label": "Client App",
                "app_id": user.app_id,
                "app_name": app_name_by_id.get(user.app_id, user.app_id),
                "device": (event.device if event else None) or "Unknown",
                "browser": (event.browser if event else None) or "Unknown",
                "ip_address": (event.ip_address if event else None) or "Unknown",
                "city": event.city if event else None,
                "region": event.region if event else None,
                "country": event.country if event else None,
                "location": _format_location(
                    event.city if event else None,
                    event.region if event else None,
                    event.country if event else None,
                ),
                "login_at": event.created_at.isoformat() if event and event.created_at else None,
                "last_seen_at": event.created_at.isoformat() if event and event.created_at else None,
                "expires_at": None,
                "is_current": False,
                "_sort_key": event_created or datetime.min,
            })

    payload_sessions.sort(key=lambda row: row.get("_sort_key") or datetime.min, reverse=True)
    for row in payload_sessions:
        row.pop("_sort_key", None)

    return {
        "current_session_id": current_session_id,
        "sessions": payload_sessions,
    }


@router.delete("/my-auth-activity/sessions/{session_id}")
def revoke_my_admin_session(
    session_id: str,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Revoke one specific active session for the current identity."""
    client_session_ref = _parse_client_session_id(session_id)
    if client_session_ref:
        user_id, app_id = client_session_ref
        linked_user = db.query(User).filter(
            User.id == user_id,
            User.tenant_id == admin.tenant_id,
            _admin_identity_filter(admin),
            User.is_active == True,
        ).first()
        if not linked_user or (app_id and linked_user.app_id != app_id):
            raise HTTPException(status_code=404, detail="Client app session not found")

        force_user_offline(linked_user.id, admin.tenant_id)
        current_session_id = getattr(request.state, "admin_session_id", None)
        app = db.query(App).filter(
            App.app_id == linked_user.app_id,
            App.tenant_id == admin.tenant_id,
        ).first()
        app_label = app.name if app and app.name else (linked_user.app_id or "Unknown App")
        log_admin_activity(
            db=db,
            admin=admin,
            request=request,
            event_type="session_revoke",
            session_id=current_session_id,
            resource=f"/admin/my-auth-activity/sessions/{session_id}",
            method="DELETE",
            details=f"Revoked client app session for {app_label}",
        )
        response = JSONResponse(content={
            "message": "Client app session revoked successfully",
            "session_id": session_id,
            "session_type": "client_app",
            "app_id": linked_user.app_id,
            "app_name": app_label,
            "current_session_revoked": False,
        })
        # Clear OAuth SSO cookie so the browser cannot silently continue this app session.
        response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
        return response

    did_revoke = revoke_admin_session(db, admin.id, session_id, reason="manual_revoke")
    if not did_revoke:
        raise HTTPException(status_code=404, detail="Session not found or already revoked")

    current_session_id = getattr(request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type="session_revoke",
        session_id=current_session_id,
        resource=f"/admin/my-auth-activity/sessions/{session_id}",
        method="DELETE",
        details=f"Revoked session {session_id}",
    )

    response = JSONResponse(content={
        "message": "Session revoked successfully",
        "session_id": session_id,
        "current_session_revoked": session_id == current_session_id,
    })
    if session_id == current_session_id:
        response.delete_cookie(key=ADMIN_TOKEN_COOKIE, path="/")
        response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    return response


@router.post("/my-auth-activity/sessions/revoke-all")
def revoke_all_my_admin_sessions(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Revoke all active sessions for this identity across admin console and client apps."""
    current_session_id = getattr(request.state, "admin_session_id", None)
    revoked_admin_count = revoke_all_admin_sessions(db, admin.id, reason="manual_revoke_all")

    revoked_client_count = 0
    revoked_client_apps = set()
    related_users = _related_identity_users(db, admin, active_only=True)
    for user in related_users:
        if not user.app_id:
            continue
        if not is_user_online(user.id, admin.tenant_id):
            continue
        force_user_offline(user.id, admin.tenant_id)
        revoked_client_count += 1
        revoked_client_apps.add(user.app_id)

    revoked_count = revoked_admin_count + revoked_client_count

    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type="session_revoke_all",
        session_id=current_session_id,
        resource="/admin/my-auth-activity/sessions/revoke-all",
        method="POST",
        details=(
            f"Revoked {revoked_count} sessions "
            f"(admin={revoked_admin_count}, client={revoked_client_count})"
        ),
    )

    response = JSONResponse(content={
        "message": "All sessions revoked",
        "revoked_count": revoked_count,
        "revoked_admin_sessions": revoked_admin_count,
        "revoked_client_sessions": revoked_client_count,
        "affected_client_apps": len(revoked_client_apps),
    })
    if current_session_id:
        response.delete_cookie(key=ADMIN_TOKEN_COOKIE, path="/")
    response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    return response


@router.get("/my-auth-activity/history")
def get_my_auth_activity_history(
    page: int = 1,
    per_page: int = Query(default=50, ge=1, le=200),
    event_type: Optional[str] = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """List global login-centric auth activity for the current admin identity."""
    safe_page = max(page, 1)
    wanted_type = (event_type or "").strip().lower() or None

    tenant_apps = db.query(App).filter(App.tenant_id == admin.tenant_id).all()
    app_name_by_id = {app.app_id: (app.name or app.app_id) for app in tenant_apps}

    merged_events = []

    # 1) Admin console auth events (login-centric by default, access only on explicit filter)
    admin_events_query = db.query(AdminActivityEvent).filter(
        AdminActivityEvent.admin_id == admin.id,
        AdminActivityEvent.tenant_id == admin.tenant_id,
    )
    if wanted_type:
        admin_events_query = admin_events_query.filter(AdminActivityEvent.event_type == wanted_type)
    else:
        admin_events_query = admin_events_query.filter(
            AdminActivityEvent.event_type.in_((
                "login",
                "logout",
                "session_revoke",
                "session_revoke_all",
                "oauth_consent_revoke",
                "oauth_consent_revoke_all",
            ))
        )

    for row in admin_events_query.all():
        created_dt = _to_utc_naive(row.created_at) or datetime.min
        merged_events.append({
            "id": f"admin-{row.id}",
            "session_id": row.session_id,
            "event_type": row.event_type,
            "method": row.method,
            "resource": row.resource,
            "details": row.details,
            "browser": row.browser,
            "device": row.device,
            "ip_address": row.ip_address,
            "city": row.city,
            "region": row.region,
            "country": row.country,
            "location": _format_location(row.city, row.region, row.country),
            "source": "admin_console",
            "source_label": "Admin Console",
            "app_id": None,
            "app_name": "Admin Console",
            "email": admin.email,
            "created_at": created_dt.isoformat() if row.created_at else None,
            "_sort_key": created_dt,
        })

    # 2) App-level activity for the same active email identity across tenant apps
    related_users = _related_identity_users(db, admin, active_only=True)
    related_user_ids = [u.id for u in related_users]
    related_users_by_id = {u.id: u for u in related_users}
    related_app_ids = {u.app_id for u in related_users if u.app_id}
    consent_from_login_pairs = set()

    if related_user_ids:
        app_login_query = db.query(LoginEvent).filter(
            LoginEvent.tenant_id == admin.tenant_id,
            LoginEvent.user_id.in_(related_user_ids),
        )
        if wanted_type:
            app_login_query = app_login_query.filter(LoginEvent.event_type == wanted_type)
        else:
            app_login_query = app_login_query.filter(
                LoginEvent.event_type.in_(_LOGIN_ACTIVITY_EVENT_TYPES)
            )

        for row in app_login_query.all():
            if row.event_type == "oauth_consent_granted":
                consent_from_login_pairs.add((row.user_id, row.app_id))

            created_dt = _to_utc_naive(row.created_at) or datetime.min
            linked_user = related_users_by_id.get(row.user_id)
            event_app_id = row.app_id or (linked_user.app_id if linked_user else None)
            merged_events.append({
                "id": f"login-{row.id}",
                "session_id": None,
                "event_type": row.event_type,
                "method": "AUTH",
                "resource": event_app_id or "Auth Platform",
                "details": "OAuth consent granted" if row.event_type == "oauth_consent_granted" else (
                    "OAuth silent sign-in successful" if row.event_type == "oauth_silent_login" else (
                    "OAuth login successful" if row.event_type == "oauth_login" else (
                        "OAuth token exchange successful" if row.event_type == "oauth_token_exchange" else "Email login successful"
                    )
                    )
                ),
                "browser": row.browser,
                "device": row.device,
                "ip_address": row.ip_address,
                "city": row.city,
                "region": row.region,
                "country": row.country,
                "location": _format_location(row.city, row.region, row.country),
                "source": "client_app_login",
                "source_label": "Client App Login",
                "app_id": event_app_id,
                "app_name": app_name_by_id.get(event_app_id, event_app_id or "Unknown App"),
                "email": admin.email,
                "created_at": created_dt.isoformat() if row.created_at else None,
                "_sort_key": created_dt,
            })

    # 3) Consent fallback from persisted consent records (avoid duplicates if login event already captured)
    if related_user_ids and (wanted_type in (None, "oauth_consent_granted")):
        consent_query = db.query(OAuthConsent).filter(
            OAuthConsent.tenant_id == admin.tenant_id,
            OAuthConsent.user_id.in_(related_user_ids),
            OAuthConsent.granted == True,
        )
        if related_app_ids:
            consent_query = consent_query.filter(OAuthConsent.client_id.in_(tuple(related_app_ids)))

        for row in consent_query.all():
            pair = (row.user_id, row.client_id)
            if pair in consent_from_login_pairs:
                continue
            created_raw = row.granted_at or row.updated_at
            created_dt = _to_utc_naive(created_raw) or datetime.min
            merged_events.append({
                "id": f"consent-{row.id}",
                "session_id": None,
                "event_type": "oauth_consent_granted",
                "method": "AUTH",
                "resource": row.client_id,
                "details": "OAuth consent granted (email scope)",
                "browser": None,
                "device": None,
                "ip_address": None,
                "city": None,
                "region": None,
                "country": None,
                "location": "Unknown",
                "source": "oauth_consent",
                "source_label": "OAuth Consent",
                "app_id": row.client_id,
                "app_name": app_name_by_id.get(row.client_id, row.client_id or "Unknown App"),
                "email": admin.email,
                "created_at": created_dt.isoformat() if created_raw else None,
                "_sort_key": created_dt,
            })

    merged_events.sort(key=lambda item: item.get("_sort_key") or datetime.min, reverse=True)
    total = len(merged_events)
    start = (safe_page - 1) * per_page
    end = start + per_page
    sliced = merged_events[start:end]

    for item in sliced:
        item.pop("_sort_key", None)

    return {
        "total": total,
        "page": safe_page,
        "per_page": per_page,
        "events": sliced,
    }


# ============== Admin Connected Apps (OAuth Consents) ==============

@router.get("/my-auth-activity/connected-apps")
def list_my_connected_apps(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """List all apps where the admin has granted OAuth consent."""
    # Find all user records for this admin's email in their tenant
    users = _related_identity_users(db, admin, active_only=True)

    if not users:
        return {"connected_apps": []}

    user_ids = [u.id for u in users]

    # Find all consents
    consents = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == admin.tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.granted == True,
    ).all()

    client_ids = sorted({consent.client_id for consent in consents if consent.client_id})
    apps_by_id = {}
    if client_ids:
        apps_by_id = {
            app.app_id: app
            for app in db.query(App).filter(App.app_id.in_(client_ids)).all()
        }

    login_counts: dict[tuple[int, str], int] = {}
    last_login_map: dict[tuple[int, str], Optional[datetime]] = {}
    if consents and client_ids:
        aggregate_rows = db.query(
            LoginEvent.user_id,
            LoginEvent.app_id,
            func.count(LoginEvent.id).label("login_count"),
            func.max(LoginEvent.created_at).label("last_login_at"),
        ).filter(
            LoginEvent.tenant_id == admin.tenant_id,
            LoginEvent.user_id.in_(user_ids),
            LoginEvent.app_id.in_(client_ids),
        ).group_by(
            LoginEvent.user_id,
            LoginEvent.app_id,
        ).all()

        for row in aggregate_rows:
            if row.user_id is None or row.app_id is None:
                continue
            key = (int(row.user_id), str(row.app_id))
            login_counts[key] = int(row.login_count or 0)
            last_login_map[key] = row.last_login_at

    result = []
    for consent in consents:
        app = apps_by_id.get(consent.client_id)
        key = (consent.user_id, consent.client_id)
        login_count = login_counts.get(key, 0)
        last_login_at = last_login_map.get(key)

        result.append({
            "consent_id": consent.id,
            "client_id": consent.client_id,
            "app_name": app.name if app else consent.client_id,
            "app_logo_url": app.logo_url if app else None,
            "scope": consent.scope,
            "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
            "login_count": login_count,
            "last_login_at": last_login_at.isoformat() if last_login_at else None,
        })

    return {"connected_apps": result}


@router.delete("/my-auth-activity/connected-apps/{client_id}")
def revoke_my_connected_app(
    client_id: str,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Revoke OAuth consent for a specific app."""
    # Find user records for this admin's email in their tenant
    users = _related_identity_users(db, admin, active_only=True)

    if not users:
        raise HTTPException(status_code=404, detail="No user records found")

    user_ids = [u.id for u in users]

    # Find and revoke consent(s)
    consents = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == admin.tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.client_id == client_id,
        OAuthConsent.granted == True,
    ).all()

    if not consents:
        raise HTTPException(status_code=404, detail="Consent not found or already revoked")

    affected_user_ids = set()
    for consent in consents:
        consent.granted = False
        affected_user_ids.add(consent.user_id)
    db.commit()

    for uid in affected_user_ids:
        force_user_offline(uid, admin.tenant_id)

    current_session_id = getattr(request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type="oauth_consent_revoke",
        session_id=current_session_id,
        resource=f"/admin/my-auth-activity/connected-apps/{client_id}",
        method="DELETE",
        details=f"Revoked OAuth consent for app: {client_id} (sessions ended={len(affected_user_ids)})",
    )

    app = db.query(App).filter(App.app_id == client_id).first()
    response = JSONResponse(content={
        "message": "Connected app access revoked successfully",
        "client_id": client_id,
        "app_name": app.name if app else client_id,
        "revoked_count": len(consents),
        "revoked_sessions_count": len(affected_user_ids),
    })
    # Clear browser-side OAuth SSO cookie to prevent immediate silent reuse.
    response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    return response


@router.post("/my-auth-activity/connected-apps/revoke-all")
def revoke_all_my_connected_apps(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Revoke all OAuth consents for the admin's account."""
    # Find all user records for this admin's email in their tenant
    users = _related_identity_users(db, admin, active_only=True)

    if not users:
        return {"message": "No connected apps to revoke", "revoked_count": 0}

    user_ids = [u.id for u in users]

    # Revoke all active consents and invalidate corresponding sessions.
    consents = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == admin.tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.granted == True,
    ).all()

    if not consents:
        return {"message": "No connected apps to revoke", "revoked_count": 0}

    affected_user_ids = set()
    for consent in consents:
        consent.granted = False
        affected_user_ids.add(consent.user_id)

    db.commit()

    for uid in affected_user_ids:
        force_user_offline(uid, admin.tenant_id)

    revoked_count = len(consents)

    current_session_id = getattr(request.state, "admin_session_id", None)
    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type="oauth_consent_revoke_all",
        session_id=current_session_id,
        resource="/admin/my-auth-activity/connected-apps/revoke-all",
        method="POST",
        details=(
            f"Revoked all OAuth consents ({revoked_count} apps, "
            f"sessions ended={len(affected_user_ids)})"
        ),
    )

    response = JSONResponse(content={
        "message": "All connected apps access revoked successfully",
        "revoked_count": revoked_count,
        "revoked_sessions_count": len(affected_user_ids),
    })
    response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    return response


# ============== Dashboard Stats ==============

@router.get("/stats")
def get_stats(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics for the admin's tenant"""
    total_apps = db.query(App).filter(App.tenant_id == admin.tenant_id).count()
    total_users = db.query(User).filter(User.tenant_id == admin.tenant_id).count()
    active_users = db.query(User).filter(
        User.tenant_id == admin.tenant_id,
        User.is_active == True
    ).count()

    # Count online users via Redis in batch.
    user_ids = [
        user_id for (user_id,) in db.query(User.id).filter(User.tenant_id == admin.tenant_id).all()
    ]
    online_count = count_online_users(user_ids, admin.tenant_id)
    
    return {
        "total_apps": total_apps,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "online_users": online_count
    }


@router.get("/login-events")
def get_login_events(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
    event_type: str = None,
    app_id: str = None,
):
    """Get login events for the admin's tenant (paginated, with optional filters)"""
    from app.models.login_event import LoginEvent

    query = db.query(LoginEvent).filter(LoginEvent.tenant_id == admin.tenant_id)

    if event_type:
        query = query.filter(LoginEvent.event_type == event_type)
    if app_id:
        query = query.filter(LoginEvent.app_id == app_id)

    total = query.count()
    events = (
        query.order_by(LoginEvent.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "events": [
            {
                "id": e.id,
                "user_id": e.user_id,
                "app_id": e.app_id,
                "event_type": e.event_type,
                "ip_address": e.ip_address,
                "city": e.city,
                "region": e.region,
                "country": e.country,
                "lat": e.lat,
                "lon": e.lon,
                "isp": e.isp,
                "created_at": str(e.created_at) if e.created_at else None,
            }
            for e in events
        ],
    }
