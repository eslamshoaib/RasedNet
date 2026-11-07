"""Login / logout / session introspection / password change, and user administration."""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from rasednet.api.deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    AuthContext,
    audit,
    client_ip,
    current_auth,
    get_db,
    hash_token,
    not_found,
    require,
)
from rasednet.api.schemas import (
    ChangePasswordIn,
    LoginIn,
    MeOut,
    RoleOut,
    UserCreateIn,
    UserOut,
    UserUpdateIn,
)
from rasednet.config import Settings
from rasednet.models import Role, User, UserSession, utcnow
from rasednet.i18n import get_lang, tr
from rasednet.security.passwords import (
    hash_password,
    needs_rehash,
    password_policy_errors,
    verify_password,
)

router = APIRouter(prefix="/api", tags=["auth"])

def LOGIN_FAILED() -> str:
    return tr("تعذر تسجيل الدخول. تحقق من اسم المستخدم وكلمة المرور، وإن تكررت المحاولات الفاشلة فانتظر قليلاً ثم أعد المحاولة", "Sign-in failed. Check your username and password; if failed attempts repeat, wait a moment and try again")


def _set_cookies(response: Response, settings: Settings, token: str, csrf: str) -> None:
    max_age = settings.session_absolute_minutes * 60
    common = {"secure": settings.cookie_secure, "samesite": "strict", "path": "/", "max_age": max_age}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **common)  # type: ignore[arg-type]
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)  # type: ignore[arg-type]


def _clear_cookies(response: Response, settings: Settings) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=settings.cookie_secure, samesite="strict")


def _me(auth_user: User, csrf: str) -> MeOut:
    return MeOut(
        user=UserOut.model_validate(auth_user),
        permissions=sorted(p.code for p in auth_user.role.permissions),
        csrf_token=csrf,
    )


@router.post("/auth/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> MeOut:
    settings: Settings = request.app.state.settings
    ip = client_ip(request) or "unknown"
    if not request.app.state.login_limiter.allow(ip):
        audit(db, request, "auth.login", actor_username=body.username[:64], success=False, details={"reason": "rate_limited"})
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, tr("محاولات تسجيل دخول كثيرة. يرجى الانتظار دقيقة ثم إعادة المحاولة", "Too many sign-in attempts. Please wait a minute and try again"))

    username = body.username.strip().lower()
    user = db.scalar(select(User).where(User.username == username))
    now = utcnow()
    password_ok = verify_password(user.password_hash if user else None, body.password)

    if user is None or not user.is_active:
        audit(db, request, "auth.login", actor_username=username, success=False,
              details={"reason": "unknown_user" if user is None else "inactive"})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, LOGIN_FAILED())

    if user.locked_until is not None and user.locked_until > now:
        audit(db, request, "auth.login", actor=user, success=False, details={"reason": "locked"})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, LOGIN_FAILED())

    if not password_ok:
        user.failed_login_count += 1
        details: dict[str, object] = {"reason": "bad_password", "failures": user.failed_login_count}
        if user.failed_login_count >= settings.login_max_failures:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_login_count = 0
            details["locked_until"] = user.locked_until.isoformat()
        audit(db, request, "auth.login", actor=user, success=False, details=details)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, LOGIN_FAILED())

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            csrf_token=csrf,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(minutes=settings.session_absolute_minutes),
            client_ip=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:256],
        )
    )
    audit(db, request, "auth.login", actor=user, success=True)
    db.commit()
    _set_cookies(response, settings, token, csrf)
    return _me(user, csrf)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    auth.session.revoked_at = utcnow()
    db.add(auth.session)
    audit(db, request, "auth.logout", auth=auth)
    db.commit()
    resp = Response(status_code=204)
    _clear_cookies(resp, request.app.state.settings)
    return resp


@router.get("/auth/me", response_model=MeOut)
def me(auth: AuthContext = Depends(current_auth)) -> MeOut:
    return _me(auth.user, auth.session.csrf_token)


@router.post("/auth/change-password", status_code=204)
def change_password(
    body: ChangePasswordIn, request: Request, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)
) -> Response:
    settings: Settings = request.app.state.settings
    user = auth.user
    if not verify_password(user.password_hash, body.current_password):
        audit(db, request, "auth.change_password", auth=auth, success=False, details={"reason": "bad_current"})
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, tr("كلمة المرور الحالية غير صحيحة", "The current password is incorrect"))
    errors = password_policy_errors(body.new_password, user.username, settings.password_min_length)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, ("; " if get_lang()=="en" else "؛ ").join(errors))
    now = utcnow()
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = now
    user.must_change_password = False
    db.add(user)
    # Revoke every other session of this user.
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.id != auth.session.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    audit(db, request, "auth.change_password", auth=auth)
    db.commit()
    return Response(status_code=204)


# --- user administration --------------------------------------------------------------------


@router.get("/roles", response_model=list[RoleOut])
def list_roles(_: AuthContext = Depends(require("user:manage")), db: Session = Depends(get_db)) -> list[Role]:
    return list(db.scalars(select(Role).order_by(Role.id)))


@router.get("/users", response_model=list[UserOut])
def list_users(_: AuthContext = Depends(require("user:manage")), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


def _role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("الدور غير موجود", "The role was not found"))
    return role


def _active_admin_count(db: Session, excluding_user_id: int | None = None) -> int:
    q = select(func.count()).select_from(User).join(Role).where(Role.name == "admin", User.is_active.is_(True))
    if excluding_user_id is not None:
        q = q.where(User.id != excluding_user_id)
    return int(db.scalar(q) or 0)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreateIn, request: Request, auth: AuthContext = Depends(require("user:manage")), db: Session = Depends(get_db)
) -> User:
    settings: Settings = request.app.state.settings
    username = body.username.lower()
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("اسم المستخدم مستخدم بالفعل", "The username is already taken"))
    errors = password_policy_errors(body.password, username, settings.password_min_length)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, ("; " if get_lang()=="en" else "؛ ").join(errors))
    user = User(
        username=username,
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
        role=_role(db, body.role),
        is_active=True,
        failed_login_count=0,
        password_changed_at=utcnow(),
        created_at=utcnow(),
    )
    db.add(user)
    db.flush()
    audit(db, request, "user.create", auth=auth, target_type="user", target_id=user.id, details={"username": username, "role": body.role})
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, body: UserUpdateIn, request: Request,
    auth: AuthContext = Depends(require("user:manage")), db: Session = Depends(get_db),
) -> User:
    settings: Settings = request.app.state.settings
    user = db.get(User, user_id)
    if user is None:
        raise not_found("المستخدم")
    changes: dict[str, object] = {}
    removing_admin = (body.role is not None and body.role != "admin") or body.is_active is False
    if removing_admin and user.role.name == "admin" and _active_admin_count(db, excluding_user_id=user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يمكن إزالة آخر مسؤول نشط في النظام", "The last active administrator cannot be removed"))
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
        changes["display_name"] = user.display_name
    if body.role is not None:
        user.role = _role(db, body.role)
        changes["role"] = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.unlock:
        user.locked_until = None
        user.failed_login_count = 0
        changes["unlock"] = True
    if body.password is not None:
        errors = password_policy_errors(body.password, user.username, settings.password_min_length)
        if errors:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, ("; " if get_lang()=="en" else "؛ ").join(errors))
        user.password_hash = hash_password(body.password)
        user.password_changed_at = utcnow()
        changes["password"] = "reset"
    if body.is_active is False or body.password is not None or body.role is not None:
        db.execute(
            update(UserSession)
            .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None), UserSession.id != auth.session.id)
            .values(revoked_at=utcnow())
        )
    audit(db, request, "user.update", auth=auth, target_type="user", target_id=user.id, details=changes)
    db.commit()
    return user
