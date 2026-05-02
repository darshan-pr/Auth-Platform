import re

from app.models.user import User
from app.services.jwt_service import create_access_token
from app.services.password_service import hash_password
from datetime import timedelta
from urllib.parse import parse_qs, urlparse
from tests.conftest import mock_redis_store


def _extract_oauth_session_id_from_html(html: str) -> str | None:
    # Legacy template pattern:
    #   const SESSION_ID = "..."
    legacy_match = re.search(r'const SESSION_ID = "([^"]+)"', html)
    if legacy_match:
        return legacy_match.group(1)

    # Current runtime-config pattern:
    #   SESSION_ID: "..."
    runtime_match = re.search(r'SESSION_ID:\s*"([^"]+)"', html)
    if runtime_match:
        return runtime_match.group(1)

    return None


def _login_admin_session(client):
    response = client.post(
        "/admin/login",
        json={"email": "admin@test.com", "password": "TestPass123!"},
    )
    assert response.status_code == 200
    return response


def _create_app(client, payload: dict):
    response = client.post("/admin/apps", json=payload)
    assert response.status_code == 200
    return response.json()


def _set_platform_sso_cookie(client, email: str, tenant_id: int, source_app_id: str = "tests"):
    token = create_access_token(
        {
            "sub": email,
            "email": email,
            "tenant_id": tenant_id,
            "source_app_id": source_app_id,
            "type": "platform_sso",
        },
        timedelta(days=1),
    )
    client.cookies.set("platform_sso", token)


def test_admin_can_toggle_oauth_per_app(client, admin_token):
    _login_admin_session(client)

    created = _create_app(
        client,
        {
            "name": "OAuth Toggle App",
            "description": "Toggle test",
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )
    assert created["oauth_enabled"] is True

    app_id = created["app_id"]
    update_res = client.put(
        f"/admin/apps/{app_id}",
        json={"oauth_enabled": False},
    )
    assert update_res.status_code == 200
    assert update_res.json()["oauth_enabled"] is False

    get_res = client.get(f"/admin/apps/{app_id}")
    assert get_res.status_code == 200
    assert get_res.json()["oauth_enabled"] is False


def test_oauth_authorize_shows_explicit_login_when_sso_disabled(client, admin_token):
    _login_admin_session(client)

    app_id = _create_app(
        client,
        {
            "name": "Disabled OAuth App",
            "description": "OAuth disabled",
            "oauth_enabled": False,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )["app_id"]

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": app_id,
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "state123",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
    )

    assert response.status_code == 200
    assert 'id="loginSection"' in response.text
    assert "OAuth is disabled for this application" not in response.text


def test_oauth_disabled_app_login_completes_without_consent_screen(client, admin_token, db):
    _login_admin_session(client)

    app_id = _create_app(
        client,
        {
            "name": "OAuth Disabled No Consent",
            "description": "Consent must stay off when OAuth is disabled",
            "oauth_enabled": False,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )["app_id"]

    user = User(
        email="admin@test.com",
        tenant_id=admin_token["tenant_id"],
        app_id=app_id,
        password_hash=hash_password("TestPass123!"),
        is_active=True,
    )
    db.add(user)
    db.commit()

    authorize = client.get(
        "/oauth/authorize",
        params={
            "client_id": app_id,
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "disabled-direct",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 200

    session_id = _extract_oauth_session_id_from_html(authorize.text)
    assert session_id, "Expected OAuth session_id in hosted login page"

    login = client.post(
        "/oauth/authenticate",
        json={
            "session_id": session_id,
            "action": "login",
            "email": "admin@test.com",
            "password": "TestPass123!",
        },
    )
    assert login.status_code == 200
    payload = login.json()
    assert payload["action"] == "redirect"
    assert payload["redirect_url"].startswith("http://localhost:3000/callback")
    assert "code=" in payload["redirect_url"]
    assert "state=disabled-direct" in payload["redirect_url"]
    assert "/oauth/consent" not in payload["redirect_url"]


def test_admin_login_does_not_issue_platform_sso_cookie(client, admin_token):
    login_res = _login_admin_session(client)
    all_set_cookie = " ".join(login_res.headers.get_list("set-cookie"))
    assert "platform_sso=" not in all_set_cookie


def test_admin_login_page_renders_oauth_retry_warning(client):
    response = client.get("/login", params={"oauth_warning": "retry_oauth"})
    assert response.status_code == 200
    assert "Sign in to Auth Platform first, then return to your app and try OAuth again." in response.text


def test_oauth_authorize_with_only_admin_cookie_bootstraps_oauth_session(client, admin_token):
    _login_admin_session(client)
    app = _create_app(
        client,
        {
            "name": "No Silent Admin Cookie",
            "description": "Should bootstrap OAuth SSO from admin dashboard session",
            "oauth_enabled": True,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "show-login",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    bootstrap_location = response.headers.get("location", "")
    assert bootstrap_location.startswith("/oauth/session/bootstrap?session_id=")
    assert f"client_id={app['app_id']}" in bootstrap_location

    bootstrap = client.get(bootstrap_location, follow_redirects=False)
    assert bootstrap.status_code in (302, 307)
    after_bootstrap = bootstrap.headers.get("location", "")
    assert after_bootstrap.startswith("/oauth/consent?session_id=")
    assert f"client_id={app['app_id']}" in after_bootstrap
    session_id = after_bootstrap.split("session_id=", 1)[1]
    session_id = session_id.split("&", 1)[0]
    all_set_cookie = " ".join(bootstrap.headers.get_list("set-cookie"))
    assert "platform_sso=" not in all_set_cookie

    approve = client.post(
        "/oauth/consent",
        json={"session_id": session_id, "decision": "approve"},
    )
    assert approve.status_code == 200
    approve_set_cookie = " ".join(approve.headers.get_list("set-cookie"))
    assert "platform_sso=" in approve_set_cookie


def test_oauth_prompt_consent_keeps_sso_identity_but_forces_consent_ui(client, admin_token):
    _login_admin_session(client)
    app = _create_app(
        client,
        {
            "name": "Prompt Consent App",
            "description": "prompt=consent should not force login",
            "oauth_enabled": True,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "prompt-consent",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "prompt": "consent",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    bootstrap_location = response.headers.get("location", "")
    assert bootstrap_location.startswith("/oauth/session/bootstrap?session_id=")

    bootstrap = client.get(bootstrap_location, follow_redirects=False)
    assert bootstrap.status_code in (302, 307)
    consent_location = bootstrap.headers.get("location", "")
    assert consent_location.startswith("/oauth/consent?session_id=")
    assert f"client_id={app['app_id']}" in consent_location


def test_oauth_authorize_ignores_legacy_admin_portal_sso_cookie(client, admin_token):
    _login_admin_session(client)
    app = _create_app(
        client,
        {
            "name": "Ignore Legacy SSO",
            "description": "Legacy admin portal cookie must not trigger silent login",
            "oauth_enabled": True,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )
    _set_platform_sso_cookie(client, email="admin@test.com", tenant_id=admin_token["tenant_id"], source_app_id="admin_portal")
    # Remove admin cookie so only legacy platform_sso remains (must not trigger silent auth).
    client.cookies.pop("admin_token", None)

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "legacy-cookie",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    location = response.headers.get("location", "")
    parsed = urlparse(location)
    assert parsed.path.endswith("/login")
    assert parse_qs(parsed.query).get("oauth_warning") == ["retry_oauth"]


def test_oauth_authorize_with_platform_sso_goes_to_consent_then_silent_after_approval(
    client,
    admin_token,
    db,
):
    _login_admin_session(client)

    test_app = _create_app(
        client,
        {
            "name": "Silent SSO App",
            "description": "Silent SSO test app",
            "oauth_enabled": True,
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )
    _set_platform_sso_cookie(client, email="admin@test.com", tenant_id=admin_token["tenant_id"])

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": test_app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "silent-state",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )

    assert response.status_code in (302, 307)
    consent_location = response.headers.get("location", "")
    assert consent_location.startswith("/oauth/consent?session_id=")
    assert f"client_id={test_app['app_id']}" in consent_location
    session_id = consent_location.split("session_id=", 1)[1].split("&", 1)[0]

    approve = client.post(
        "/oauth/consent",
        json={"session_id": session_id, "decision": "approve"},
    )
    assert approve.status_code == 200
    approve_data = approve.json()
    assert approve_data["action"] == "redirect"
    assert approve_data["redirect_url"].startswith("http://localhost:3000/callback")
    assert "code=" in approve_data["redirect_url"]
    assert "state=silent-state" in approve_data["redirect_url"]

    user = db.query(User).filter(
        User.email == "admin@test.com",
        User.tenant_id == admin_token["tenant_id"],
        User.app_id == test_app["app_id"],
    ).first()
    assert user is not None

    # Even after consent is stored, this flow still shows explicit consent UI.
    second = client.get(
        "/oauth/authorize",
        params={
            "client_id": test_app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "silent-state-2",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert second.status_code in (302, 307)
    second_location = second.headers.get("location", "")
    assert second_location.startswith("/oauth/consent?session_id=")
    assert f"client_id={test_app['app_id']}" in second_location

    # prompt=consent should force consent UI even with valid platform_sso + existing consent.
    forced_consent = client.get(
        "/oauth/authorize",
        params={
            "client_id": test_app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "silent-state-3",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "prompt": "consent",
        },
        follow_redirects=False,
    )
    assert forced_consent.status_code in (302, 307)
    assert forced_consent.headers.get("location", "").startswith("/oauth/consent?session_id=")


def test_oauth_forgot_password_sends_reset_otp_for_passwordless_user(client, admin_token, db):
    _login_admin_session(client)

    app_id = _create_app(
        client,
        {
            "name": "Passwordless Forgot Password",
            "description": "Ensure OTP is sent even if password is not set yet",
            "oauth_enabled": True,
            "otp_enabled": True,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )["app_id"]

    user = User(
        email="nopassword@test.com",
        tenant_id=admin_token["tenant_id"],
        app_id=app_id,
        password_hash=None,
        is_active=True,
    )
    db.add(user)
    db.commit()

    authorize = client.get(
        "/oauth/authorize",
        params={
            "client_id": app_id,
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "forgot-pwd",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 200
    session_id = _extract_oauth_session_id_from_html(authorize.text)
    assert session_id

    response = client.post(
        "/oauth/authenticate",
        json={
            "session_id": session_id,
            "action": "forgot_password",
            "email": "nopassword@test.com",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "show_reset_otp"
    assert "sent" in payload.get("message", "").lower()

    redis_key = f"password_reset_otp:nopassword@test.com:{app_id}"
    assert mock_redis_store.get(redis_key) is not None


def test_oauth_login_passwordless_user_shows_reset_password_guidance(client, admin_token, db):
    _login_admin_session(client)

    app_id = _create_app(
        client,
        {
            "name": "Passwordless Login Warning",
            "description": "Ensure login warning guides users to password reset",
            "oauth_enabled": True,
            "otp_enabled": True,
            "redirect_uris": "http://localhost:3000/callback",
        },
    )["app_id"]

    user = User(
        email="needreset@test.com",
        tenant_id=admin_token["tenant_id"],
        app_id=app_id,
        password_hash=None,
        is_active=True,
    )
    db.add(user)
    db.commit()

    authorize = client.get(
        "/oauth/authorize",
        params={
            "client_id": app_id,
            "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code",
            "state": "login-warning",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 200
    session_id = _extract_oauth_session_id_from_html(authorize.text)
    assert session_id

    login = client.post(
        "/oauth/authenticate",
        json={
            "session_id": session_id,
            "action": "login",
            "email": "needreset@test.com",
            "password": "DoesNotMatter123!",
        },
    )
    assert login.status_code == 400
    detail = login.json().get("detail", "").lower()
    assert "reset your password" in detail
