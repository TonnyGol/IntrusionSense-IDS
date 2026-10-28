from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from intrusionsense.server.security import (
    REQUIRED_CLIENT_HEADER,
    REQUIRED_CLIENT_HEADER_VALUE,
    Permission,
    permissions_for,
)
from intrusionsense.server.services import Services
from intrusionsense.storage.models import AuditLog, User

SESSION_USER_KEY = "user_id"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class CurrentUser:
    user_id: int
    username: str
    role: str
    permissions: frozenset[Permission]


def get_services(request: Request) -> Services:
    return request.app.state.services


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_client_header(request: Request) -> None:
    """CSRF guard: a cross-site form or fetch cannot add this header without a CORS preflight we refuse."""
    if request.method in SAFE_METHODS:
        return
    if request.headers.get(REQUIRED_CLIENT_HEADER) != REQUIRED_CLIENT_HEADER_VALUE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing client header")


def current_user(request: Request, services: Annotated[Services, Depends(get_services)]) -> CurrentUser:
    user_id = request.session.get(SESSION_USER_KEY)
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required")
    # read from the DB on every request, so a changed role or deleted user takes effect at once
    with services.session_factory() as session:
        user = session.get(User, user_id)
    if user is None:
        request.session.clear()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required")
    return CurrentUser(user.UserID, user.Username, user.Role, frozenset(permissions_for(user.Role)))


def require(permission: Permission):
    def check(user: Annotated[CurrentUser, Depends(current_user)]) -> CurrentUser:
        if permission not in user.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role cannot do this")
        return user

    return check


def write_audit(
    services: Services, request: Request, username: str | None, action: str, detail: str = ""
) -> None:
    with services.session_factory() as session:
        session.add(AuditLog(Username=username, Action=action, Detail=detail, ClientIP=client_ip(request)))
        session.commit()


Authenticated = Annotated[CurrentUser, Depends(current_user)]
ServicesDep = Annotated[Services, Depends(get_services)]
