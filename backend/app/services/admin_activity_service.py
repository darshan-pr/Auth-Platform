from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import Request

from app.models.admin import Admin
from app.models.admin_session import AdminSession
from app.models.admin_activity_event import AdminActivityEvent
from app.services.geo_service import get_client_ip, get_location


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _as_utc_naive(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def parse_user_agent(user_agent: Optional[str]) -> tuple[str, str]:
    ua = (user_agent or "").lower()

    if "edg/" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "chrome/" in ua and "safari/" in ua:
        browser = "Chrome"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    elif "firefox/" in ua:
        browser = "Firefox"
    else:
        browser = "Unknown"

    if "iphone" in ua:
        device = "iPhone"
    elif "ipad" in ua:
        device = "iPad"
    elif "android" in ua:
        device = "Android"
    elif "windows" in ua:
        device = "Windows"
    elif "mac os x" in ua or "macintosh" in ua:
        device = "Mac"
    elif "linux" in ua:
        device = "Linux"
    else:
        device = "Unknown"

    return browser, device


def _request_metadata(request: Optional[Request]) -> dict:
    if not request:
        return {
            "ip_address": None,
            "city": None,
            "region": None,
            "country": None,
            "isp": None,
            "user_agent": None,
            "browser": "Unknown",
            "device": "Unknown",
        }

    user_agent = request.headers.get("user-agent", "")
    browser, device = parse_user_agent(user_agent)
    ip = get_client_ip(request)
    geo = get_location(ip)
    return {
        "ip_address": ip,
        "city": geo.get("city"),
        "region": geo.get("region"),
        "country": geo.get("country"),
        "isp": geo.get("isp"),
        "user_agent": user_agent,
        "browser": browser,
        "device": device,
    }


def log_admin_activity(
    db,
    admin: Admin,
    request: Optional[Request],
    event_type: str,
    session_id: Optional[str] = None,
    resource: Optional[str] = None,
    method: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    try:
        meta = _request_metadata(request)
        event = AdminActivityEvent(
            admin_id=admin.id,
            tenant_id=admin.tenant_id,
            session_id=session_id,
            event_type=event_type,
            resource=resource,
            method=method,
            details=details,
            user_agent=meta["user_agent"],
            browser=meta["browser"],
            device=meta["device"],
            ip_address=meta["ip_address"],
            city=meta["city"],
            region=meta["region"],
            country=meta["country"],
            isp=meta["isp"],
        )
        db.add(event)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def create_admin_session(
    db,
    admin: Admin,
    session_id: str,
    request: Optional[Request],
    expires_at: Optional[datetime],
) -> Optional[AdminSession]:
    try:
        meta = _request_metadata(request)
        session = AdminSession(
            session_id=session_id,
            admin_id=admin.id,
            tenant_id=admin.tenant_id,
            user_agent=meta["user_agent"],
            browser=meta["browser"],
            device=meta["device"],
            ip_address=meta["ip_address"],
            city=meta["city"],
            region=meta["region"],
            country=meta["country"],
            isp=meta["isp"],
            expires_at=expires_at,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return None


def touch_admin_session(db, admin_id: int, session_id: str) -> None:
    try:
        session = db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.session_id == session_id,
        ).first()
        if not session:
            return
        session.last_seen_at = _utc_now_naive()
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def is_admin_session_active(db, admin_id: int, session_id: str) -> bool:
    now = _utc_now_naive()
    session = db.query(AdminSession).filter(
        AdminSession.admin_id == admin_id,
        AdminSession.session_id == session_id,
    ).first()
    if not session:
        return False
    if session.is_revoked:
        return False
    session_exp = _as_utc_naive(session.expires_at)
    if session_exp and session_exp < now:
        return False
    return True


def revoke_admin_session(db, admin_id: int, session_id: str, reason: str = "manual_revoke") -> bool:
    try:
        session = db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.session_id == session_id,
            AdminSession.is_revoked == False,
        ).first()
        if not session:
            return False
        session.is_revoked = True
        session.revoked_at = _utc_now_naive()
        session.revoked_reason = reason
        db.commit()
        return True
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return False


def revoke_all_admin_sessions(db, admin_id: int, reason: str = "manual_revoke_all") -> int:
    try:
        now = _utc_now_naive()
        sessions = db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.is_revoked == False,
        ).all()
        count = 0
        for s in sessions:
            s.is_revoked = True
            s.revoked_at = now
            s.revoked_reason = reason
            count += 1
        db.commit()
        return count
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return 0
