from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from csg.config import Settings, get_settings
from csg.db.session import get_session


def settings_dependency() -> Settings:
    return get_settings()


def db_dependency() -> Generator[Session]:
    yield from get_session()


def require_probe_token(
    authorization: str | None = Header(default=None),
    x_csg_token: str | None = Header(default=None),
    settings: Settings = Depends(settings_dependency),
) -> None:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if x_csg_token:
        token = x_csg_token
    if token != settings.lab_shared_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid CyberStateGuardian lab token",
        )
