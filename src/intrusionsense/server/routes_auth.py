from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from intrusionsense.server.deps import (
    SESSION_USER_KEY,
    Authenticated,
    ServicesDep,
    client_ip,
    require_client_header,
    write_audit,
)
from intrusionsense.server.security import (
    MAX_PASSWORD_LENGTH,
    Role,
    hash_password,
    password_problem,
    permissions_for,
    verify_password,
)
from intrusionsense.storage.models import User

MAX_USERNAME_LENGTH = 50
BAD_CREDENTIALS = "Wrong username or password."

router = APIRouter(prefix="/api", dependencies=[Depends(require_client_header)])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=MAX_USERNAME_LENGTH)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=MAX_USERNAME_LENGTH)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


def _user_summary(user_id: int, username: str, role: str, permissions) -> dict:
    return {"id": user_id, "username": username, "role": role, "permissions": sorted(permissions)}


@router.get("/setup")
def setup_status(services: ServicesDep):
    with services.session_factory() as session:
        return {"needed": session.query(User).first() is None}


@router.post("/setup")
def create_first_admin(body: SetupRequest, request: Request, services: ServicesDep):
    """Works only while no user exists; the first visitor becomes admin."""
    if (problem := password_problem(body.password)) is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, problem)
    with services.session_factory() as session:
        if session.query(User).first() is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already done.")
        session.add(
            User(Username=body.username, PasswordHash=hash_password(body.password), Role=Role.ADMIN.value)
        )
        session.commit()
    write_audit(services, request, body.username, "setup", "first admin created")
    return {"created": True}


@router.post("/login")
def login(body: LoginRequest, request: Request, services: ServicesDep):
    ip = client_ip(request)
    if services.login_throttle.is_blocked(ip, body.username):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed sign-ins. Try again in a few minutes."
        )

    with services.session_factory() as session:
        user = session.query(User).filter_by(Username=body.username).first()
        stored_hash = user.PasswordHash if user else None
        valid = verify_password(stored_hash, body.password)
        details = (user.UserID, user.Username, user.Role) if user else None

    if not valid or details is None:
        services.login_throttle.record_failure(ip, body.username)
        write_audit(services, request, body.username, "login_failed")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_CREDENTIALS)

    services.login_throttle.reset(ip, body.username)
    request.session.clear()  # new session on sign-in, never reuse one from before
    request.session[SESSION_USER_KEY] = details[0]
    write_audit(services, request, details[1], "login")
    return _user_summary(*details, permissions_for(details[2]))


@router.post("/logout")
def logout(request: Request, services: ServicesDep):
    username = None
    if (user_id := request.session.get(SESSION_USER_KEY)) is not None:
        with services.session_factory() as session:
            user = session.get(User, user_id)
            username = user.Username if user else None
    request.session.clear()
    write_audit(services, request, username, "logout")
    return {"signed_out": True}


@router.get("/me")
def me(user: Authenticated):
    return _user_summary(user.user_id, user.username, user.role, user.permissions)
