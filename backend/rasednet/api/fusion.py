"""Fusion Tables API: query, CSV export and saved views."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, not_found, require
from rasednet.i18n import get_lang, tr
from rasednet.fusion import COLUMN_LABELS_AR, FusionQuery, export_csv, run_query
from rasednet.models import FusionView, utcnow

router = APIRouter(prefix="/api/fusion", tags=["fusion"])


@router.get("/columns")
def columns(_: AuthContext = Depends(require("asset:read"))) -> dict[str, str]:
    return COLUMN_LABELS_AR


@router.post("/query")
def query(body: FusionQuery, _: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return run_query(db, body)


@router.post("/export")
def export(body: FusionQuery, request: Request, auth: AuthContext = Depends(require("asset:read")),
           db: Session = Depends(get_db)) -> Response:
    text, count = export_csv(db, body)
    audit(db, request, "fusion.export", auth=auth, details={"rows": count, "filters": body.filters.model_dump(exclude_defaults=True)})
    db.commit()
    return Response(
        content=text.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="rasednet-fusion.csv"'},
    )


class ViewIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    definition: FusionQuery
    is_shared: bool = False


class ViewOut(BaseModel):
    id: int
    name: str
    definition: dict[str, Any]
    is_shared: bool
    owner_id: int
    is_mine: bool


def _out(view: FusionView, user_id: int) -> ViewOut:
    return ViewOut(id=view.id, name=view.name, definition=view.definition, is_shared=view.is_shared,
                   owner_id=view.owner_id, is_mine=view.owner_id == user_id)


@router.get("/views", response_model=list[ViewOut])
def list_views(auth: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db)) -> list[ViewOut]:
    rows = db.scalars(
        select(FusionView).where(or_(FusionView.owner_id == auth.user.id, FusionView.is_shared.is_(True))).order_by(FusionView.name)
    )
    return [_out(v, auth.user.id) for v in rows]


@router.post("/views", response_model=ViewOut, status_code=201)
def save_view(body: ViewIn, request: Request, auth: AuthContext = Depends(require("asset:read")),
              db: Session = Depends(get_db)) -> ViewOut:
    name = body.name.strip()
    view = db.scalar(select(FusionView).where(FusionView.owner_id == auth.user.id, FusionView.name == name))
    now = utcnow()
    if view is None:
        view = FusionView(owner_id=auth.user.id, name=name, created_at=now)
        db.add(view)
    view.definition = body.definition.model_dump(mode="json")
    view.is_shared = body.is_shared
    view.updated_at = now
    db.flush()
    audit(db, request, "fusion.save_view", auth=auth, target_type="fusion_view", target_id=view.id, details={"name": name})
    db.commit()
    return _out(view, auth.user.id)


@router.delete("/views/{view_id}", status_code=204)
def delete_view(view_id: int, request: Request, auth: AuthContext = Depends(require("asset:read")),
                db: Session = Depends(get_db)) -> Response:
    view = db.get(FusionView, view_id)
    if view is None:
        raise not_found("العرض")
    if view.owner_id != auth.user.id and auth.user.role.name != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, tr("لا يمكنك حذف عرض يملكه مستخدم آخر", "You cannot delete a view owned by another user"))
    audit(db, request, "fusion.delete_view", auth=auth, target_type="fusion_view", target_id=view.id)
    db.delete(view)
    db.commit()
    return Response(status_code=204)
