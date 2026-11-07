"""Custom scan profiles (built-in profiles are read-only and re-seeded at start-up)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, not_found, require
from rasednet.i18n import get_lang, tr
from rasednet.api.schemas import ProfileIn, ProfileOut
from rasednet.models import ScanJob, ScanProfile

router = APIRouter(prefix="/api", tags=["profiles"])


def _apply(profile: ScanProfile, body: ProfileIn) -> None:
    for field, value in body.model_dump().items():
        setattr(profile, field, value)
    profile.is_intrusive = False  # intrusive testing is never available through profiles


def _unique_name(db: Session, name: str, exclude_id: int | None = None) -> None:
    q = select(ScanProfile.id).where(ScanProfile.name_ar == name)
    if exclude_id is not None:
        q = q.where(ScanProfile.id != exclude_id)
    if db.scalar(q) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("يوجد ملف فحص آخر بنفس الاسم", "Another scan profile with this name exists"))


@router.post("/profiles", response_model=ProfileOut, status_code=201)
def create_profile(body: ProfileIn, request: Request, auth: AuthContext = Depends(require("profile:manage")),
                   db: Session = Depends(get_db)) -> ScanProfile:
    _unique_name(db, body.name_ar.strip())
    profile = ScanProfile(code="custom_pending", is_builtin=False)
    _apply(profile, body)
    db.add(profile)
    db.flush()
    profile.code = f"custom_{profile.id}"
    audit(db, request, "profile.create", auth=auth, target_type="profile", target_id=profile.id, details=body.model_dump())
    db.commit()
    return profile


def _editable(db: Session, profile_id: int) -> ScanProfile:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise not_found("ملف الفحص")
    if profile.is_builtin:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("ملفات الفحص الأساسية لا تُعدل؛ أنشئ نسخة منها وعدّلها", "Built-in scan profiles cannot be edited; make a copy and edit it"))
    return profile


@router.put("/profiles/{profile_id}", response_model=ProfileOut)
def update_profile(profile_id: int, body: ProfileIn, request: Request,
                   auth: AuthContext = Depends(require("profile:manage")), db: Session = Depends(get_db)) -> ScanProfile:
    profile = _editable(db, profile_id)
    _unique_name(db, body.name_ar.strip(), exclude_id=profile.id)
    _apply(profile, body)
    audit(db, request, "profile.update", auth=auth, target_type="profile", target_id=profile.id, details=body.model_dump())
    db.commit()
    return profile


@router.delete("/profiles/{profile_id}", status_code=204)
def delete_profile(profile_id: int, request: Request, auth: AuthContext = Depends(require("profile:manage")),
                   db: Session = Depends(get_db)) -> Response:
    profile = _editable(db, profile_id)
    if db.scalar(select(ScanJob.id).where(ScanJob.profile_id == profile.id).limit(1)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("هذا الملف مستخدم في سجل الفحوصات ولا يمكن حذفه؛ يمكنك تعديله بدلاً من ذلك", "This profile is used in scan history and cannot be deleted; you can edit it instead"))
    audit(db, request, "profile.delete", auth=auth, target_type="profile", target_id=profile.id, details={"name": profile.name_ar})
    db.delete(profile)
    db.commit()
    return Response(status_code=204)
