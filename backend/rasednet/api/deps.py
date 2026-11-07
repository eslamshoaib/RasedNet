"""Shared API dependencies: DB session, authentication, CSRF, RBAC and audit logging."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.config import Settings
from rasednet.models import AuditLog, User, UserSession, utcnow

SESSION_COOKIE = "rasednet_session"
CSRF_COOKIE = "rasednet_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    """Request-scoped session. Endpoints commit explicitly; anything uncommitted is rolled back."""
    session: Session = request.app.state.db.session_factory()
    try:
        yield session
    finally:
        session.close()


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: UserSession
    permissions: frozenset[str]

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def audit(
    db: Session,
    request: Request,
    action: str,
    *,
    auth: AuthContext | None = None,
    actor: User | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: object | None = None,
    success: bool = True,
    details: dict[str, Any] | None = None,
) -> None:
    user = auth.user if auth else actor
    db.add(
        AuditLog(
            actor_id=user.id if user else None,
            actor_username=(user.username if user else actor_username),
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            success=success,
            client_ip=client_ip(request),
            details=details or {},
            created_at=utcnow(),
        )
    )


def _t(ar: str, en: str) -> str:
    from rasednet.i18n import tr
    return tr(ar, en)


def current_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _t("يجب تسجيل الدخول للمتابعة", "You must sign in to continue"))
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    now = utcnow()
    if (
        sess is None
        or sess.revoked_at is not None
        or sess.expires_at <= now
        or now - sess.last_seen_at > timedelta(minutes=settings.session_idle_minutes)
        or not sess.user.is_active
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _t("انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً", "Your session has expired, please sign in again"))

    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied, sess.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, _t("رمز الحماية من تزوير الطلبات (CSRF) غير صالح أو مفقود", "The anti-CSRF token is missing or invalid"))

    if now - sess.last_seen_at > timedelta(seconds=30):
        sess.last_seen_at = now
        db.commit()

    permissions = frozenset(p.code for p in sess.user.role.permissions)
    return AuthContext(user=sess.user, session=sess, permissions=permissions)


def require(permission: str) -> Callable[..., AuthContext]:
    def dependency(
        request: Request, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)
    ) -> AuthContext:
        if auth.user.must_change_password:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                _t("يجب تغيير كلمة المرور قبل متابعة استخدام النظام", "You must change your password before using the system"),
            )
        if not auth.can(permission):
            audit(
                db, request, "authorization.denied", auth=auth, success=False,
                details={"permission": permission, "path": request.url.path, "method": request.method},
            )
            db.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, _t("ليست لديك صلاحية لتنفيذ هذا الإجراء", "You do not have permission to perform this action"))
        return auth

    return dependency


# Arabic nouns passed by call sites → their English counterpart, so not_found() is
# bilingual without editing every caller.
_ENTITY_EN: dict[str, str] = {
    "العنصر": "item", "الجهاز": "device", "التنبيه": "alert", "المستخدم": "user", "العرض": "view",
    "الفحص": "scan", "الإجراء": "action", "ملف الفحص": "scan profile", "الحساب": "account",
    "الخدمة": "service", "الأمر": "command", "المفتاح": "key", "النطاق": "scope",
}


def not_found(entity_ar: str = "العنصر") -> HTTPException:
    from rasednet.i18n import get_lang
    if get_lang() == "en":
        return HTTPException(status.HTTP_404_NOT_FOUND, f"{_ENTITY_EN.get(entity_ar, 'item').capitalize()} not found")
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{entity_ar} غير موجود")


def like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
