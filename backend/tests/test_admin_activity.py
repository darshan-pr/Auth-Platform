from datetime import timedelta

from app.models.oauth_consent import OAuthConsent
from app.models.user import User
from app.services.jwt_service import create_access_token


def _login_admin(client):
    response = client.post(
        "/admin/login",
        json={"email": "admin@test.com", "password": "TestPass123!"},
    )
    assert response.status_code == 200
    return response


def _extract_cookie_value(response, cookie_name: str) -> str:
    for raw in response.headers.get_list("set-cookie"):
        marker = f"{cookie_name}="
        if marker in raw:
            return raw.split(marker, 1)[1].split(";", 1)[0]
    return ""


def _csrf_headers(client) -> dict:
    csrf = client.cookies.get("csrf_token")
    if not csrf:
        return {}
    return {"X-CSRF-Token": csrf}


def _create_app_for_admin_identity(client):
    response = client.post(
        "/admin/apps",
        json={
            "name": "Identity Tracking App",
            "description": "Tracks admin email logins",
            "oauth_enabled": True,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )
    assert response.status_code == 200
    return response.json()


def _set_platform_sso_cookie(client, email: str, tenant_id: int):
    token = create_access_token(
        {
            "sub": email,
            "tenant_id": tenant_id,
            "source_app_id": "tests",
            "type": "platform_sso",
        },
        timedelta(days=1),
    )
    client.cookies.set("platform_sso", token)


def _signup_and_login_identity_user(client, app: dict) -> dict:
    signup_res = client.post(
        "/auth/signup",
        json={
            "email": "admin@test.com",
            "password": "AppLoginPass1!",
            "app_id": app["app_id"],
            "app_secret": app["app_secret"],
        },
    )
    assert signup_res.status_code == 200

    login_res = client.post(
        "/auth/login",
        json={
            "email": "admin@test.com",
            "password": "AppLoginPass1!",
            "app_id": app["app_id"],
            "app_secret": app["app_secret"],
        },
    )
    assert login_res.status_code == 200
    return login_res.json()


def test_my_auth_activity_shows_personal_sessions_and_history(client, admin_token):
    _login_admin(client)

    sessions_res = client.get("/admin/my-auth-activity/sessions")
    assert sessions_res.status_code == 200
    sessions_data = sessions_res.json()

    assert "sessions" in sessions_data
    assert len(sessions_data["sessions"]) >= 1
    assert any(session.get("is_current") for session in sessions_data["sessions"])

    history_res = client.get("/admin/my-auth-activity/history")
    assert history_res.status_code == 200
    history_data = history_res.json()

    assert "events" in history_data
    assert history_data["total"] >= 1
    assert any(event.get("event_type") == "login" for event in history_data["events"])


def test_my_auth_activity_includes_app_login_for_same_active_email(client, admin_token):
    _login_admin(client)
    app = _create_app_for_admin_identity(client)

    _signup_and_login_identity_user(client, app)

    history_res = client.get("/admin/my-auth-activity/history")
    assert history_res.status_code == 200
    events = history_res.json()["events"]
    matched = [
        event for event in events
        if event.get("source") == "client_app_login"
        and event.get("app_id") == app["app_id"]
        and event.get("event_type") in ("login", "oauth_login")
    ]
    assert matched, "Expected app-level login activity tied to admin email identity"


def test_my_auth_activity_includes_oauth_consent_grants(client, admin_token):
    _login_admin(client)
    app = _create_app_for_admin_identity(client)
    _set_platform_sso_cookie(client, email="admin@test.com", tenant_id=admin_token["tenant_id"])

    authorize_res = client.get(
        "/oauth/authorize",
        params={
            "client_id": app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "history-consent",
            "code_challenge": "challenge123",
            "code_challenge_method": "plain",
        },
        follow_redirects=False,
    )
    assert authorize_res.status_code in (302, 307)
    consent_location = authorize_res.headers.get("location", "")
    assert consent_location.startswith("/oauth/consent?session_id=")
    assert f"client_id={app['app_id']}" in consent_location
    session_id = consent_location.split("session_id=", 1)[1].split("&", 1)[0]

    consent_res = client.post(
        "/oauth/consent",
        json={"session_id": session_id, "decision": "approve"},
    )
    assert consent_res.status_code == 200

    history_res = client.get("/admin/my-auth-activity/history")
    assert history_res.status_code == 200
    events = history_res.json()["events"]
    assert any(
        event.get("event_type") == "oauth_consent_granted" and event.get("app_id") == app["app_id"]
        for event in events
    )


def test_my_auth_activity_sessions_include_client_app_session(client, admin_token):
    _login_admin(client)
    app = _create_app_for_admin_identity(client)
    _signup_and_login_identity_user(client, app)

    sessions_res = client.get("/admin/my-auth-activity/sessions")
    assert sessions_res.status_code == 200
    sessions = sessions_res.json().get("sessions", [])
    assert any(
        s.get("session_type") == "client_app" and s.get("app_id") == app["app_id"]
        for s in sessions
    ), "Expected active client app session in My Auth Activity sessions"


def test_revoke_client_app_session_invalidates_token_immediately(client, admin_token):
    _login_admin(client)
    app = _create_app_for_admin_identity(client)
    login_data = _signup_and_login_identity_user(client, app)
    access_token = login_data.get("access_token")
    assert access_token

    sessions_res = client.get("/admin/my-auth-activity/sessions")
    assert sessions_res.status_code == 200
    sessions = sessions_res.json().get("sessions", [])
    client_session = next(
        (
            s for s in sessions
            if s.get("session_type") == "client_app" and s.get("app_id") == app["app_id"]
        ),
        None,
    )
    assert client_session is not None

    revoke_res = client.delete(
        f"/admin/my-auth-activity/sessions/{client_session['session_id']}",
        headers=_csrf_headers(client),
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json().get("session_type") == "client_app"

    verify_res = client.post("/token/verify", json={"token": access_token})
    assert verify_res.status_code == 401


def test_revoke_connected_app_revokes_consent_and_active_tokens(client, admin_token, db):
    _login_admin(client)
    app = _create_app_for_admin_identity(client)
    login_data = _signup_and_login_identity_user(client, app)
    access_token = login_data.get("access_token")
    assert access_token

    linked_user = db.query(User).filter(
        User.email == "admin@test.com",
        User.tenant_id == admin_token["tenant_id"],
        User.app_id == app["app_id"],
    ).first()
    assert linked_user is not None

    db.add(OAuthConsent(
        tenant_id=admin_token["tenant_id"],
        user_id=linked_user.id,
        client_id=app["app_id"],
        scope="email",
        granted=True,
    ))
    db.commit()

    connected_res = client.get("/admin/my-auth-activity/connected-apps")
    assert connected_res.status_code == 200
    assert any(item.get("client_id") == app["app_id"] for item in connected_res.json().get("connected_apps", []))

    revoke_res = client.delete(
        f"/admin/my-auth-activity/connected-apps/{app['app_id']}",
        headers=_csrf_headers(client),
    )
    assert revoke_res.status_code == 200
    body = revoke_res.json()
    assert body.get("client_id") == app["app_id"]
    assert body.get("revoked_sessions_count", 0) >= 1

    verify_res = client.post("/token/verify", json={"token": access_token})
    assert verify_res.status_code == 401


def test_revoking_current_admin_session_invalidates_token_immediately(client, admin_token):
    login_res = _login_admin(client)
    token = _extract_cookie_value(login_res, "admin_token")
    assert token

    sessions_res = client.get("/admin/my-auth-activity/sessions")
    assert sessions_res.status_code == 200
    sessions = sessions_res.json()["sessions"]
    current = next((s for s in sessions if s.get("is_current")), None)
    assert current is not None

    revoke_res = client.delete(
        f"/admin/my-auth-activity/sessions/{current['session_id']}",
        headers=_csrf_headers(client),
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json().get("current_session_revoked") is True

    # Cookie-based access should fail because the current session was revoked and cookie cleared.
    tenant_after_cookie = client.get("/admin/tenant")
    assert tenant_after_cookie.status_code == 401

    # Header-based access with the old token should also fail immediately.
    tenant_after_header = client.get(
        "/admin/tenant",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert tenant_after_header.status_code == 401


def test_revoke_all_admin_sessions_revokes_every_active_session(client, admin_token):
    first_login = _login_admin(client)
    first_token = _extract_cookie_value(first_login, "admin_token")
    assert first_token

    second_login = _login_admin(client)
    second_token = _extract_cookie_value(second_login, "admin_token")
    assert second_token

    sessions_before = client.get("/admin/my-auth-activity/sessions")
    assert sessions_before.status_code == 200
    assert len(sessions_before.json()["sessions"]) >= 2

    revoke_all = client.post(
        "/admin/my-auth-activity/sessions/revoke-all",
        json={},
        headers=_csrf_headers(client),
    )
    assert revoke_all.status_code == 200
    assert revoke_all.json().get("revoked_count", 0) >= 2

    tenant_first = client.get("/admin/tenant", headers={"Authorization": f"Bearer {first_token}"})
    tenant_second = client.get("/admin/tenant", headers={"Authorization": f"Bearer {second_token}"})
    assert tenant_first.status_code == 401
    assert tenant_second.status_code == 401
