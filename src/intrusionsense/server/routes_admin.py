from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from intrusionsense.rules import RuleAction, parse_rule
from intrusionsense.server.deps import (
    Authenticated,
    CurrentUser,
    ServicesDep,
    require,
    require_client_header,
    write_audit,
)
from intrusionsense.server.security import (
    MAX_PASSWORD_LENGTH,
    Permission,
    Role,
    hash_password,
    password_problem,
)
from intrusionsense.server.serialize import iso_utc, rule_to_dict, sensor_to_dict
from intrusionsense.storage.models import AuditLog, Rule, Sensor, User, utc_now
from intrusionsense.storage.sensors import create_sensor

MAX_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 1000
MAX_CONDITION_LENGTH = 1000
MAX_USERNAME_LENGTH = 50
AUDIT_PAGE_SIZE = 200

router = APIRouter(prefix="/api", dependencies=[Depends(require_client_header)])
ManageRules = Annotated[CurrentUser, Depends(require(Permission.MANAGE_RULES))]
ManageSensors = Annotated[CurrentUser, Depends(require(Permission.MANAGE_SENSORS))]
ManageUsers = Annotated[CurrentUser, Depends(require(Permission.MANAGE_USERS))]
ViewAudit = Annotated[CurrentUser, Depends(require(Permission.VIEW_AUDIT))]


# ---- rules ----------------------------------------------------------------------------------------------


class RuleBody(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    description: str = Field(default="", max_length=MAX_DESCRIPTION_LENGTH)
    condition: str = Field(min_length=1, max_length=MAX_CONDITION_LENGTH)
    action: RuleAction
    active: bool = True


def _check_rule_is_usable(body: RuleBody) -> None:
    # the same parser the detector uses, so a rule saved here is guaranteed to load
    if parse_rule(None, body.name, body.condition, body.action.value) is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "The condition is not valid for this rule."
        )


@router.get("/rules")
def list_rules(user: Authenticated, services: ServicesDep):
    with services.session_factory() as session:
        return [rule_to_dict(r) for r in session.query(Rule).order_by(Rule.RuleID).all()]


@router.post("/rules", status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleBody, request: Request, user: ManageRules, services: ServicesDep):
    _check_rule_is_usable(body)
    with services.session_factory() as session:
        rule = Rule(
            RuleName=body.name,
            Description=body.description,
            ConditionText=body.condition,
            Severity=body.action.value,
            IsActive=body.active,
            CreatedBy=user.user_id,
        )
        session.add(rule)
        session.commit()
        result = rule_to_dict(rule)
    services.reload_rules()
    write_audit(services, request, user.username, "rule_created", body.name)
    return result


@router.put("/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleBody, request: Request, user: ManageRules, services: ServicesDep):
    _check_rule_is_usable(body)
    with services.session_factory() as session:
        rule = session.get(Rule, rule_id)
        if rule is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
        rule.RuleName, rule.Description = body.name, body.description
        rule.ConditionText, rule.Severity, rule.IsActive = body.condition, body.action.value, body.active
        session.commit()
        result = rule_to_dict(rule)
    services.reload_rules()
    write_audit(services, request, user.username, "rule_updated", f"{rule_id} {body.name}")
    return result


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request, user: ManageRules, services: ServicesDep):
    with services.session_factory() as session:
        rule = session.get(Rule, rule_id)
        if rule is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
        name = rule.RuleName
        session.delete(rule)
        session.commit()
    services.reload_rules()
    write_audit(services, request, user.username, "rule_deleted", f"{rule_id} {name}")
    return {"deleted": True}


# ---- sensors --------------------------------------------------------------------------------------------


class SensorBody(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)


@router.get("/sensors")
def list_sensors(user: Authenticated, services: ServicesDep):
    now = utc_now()
    with services.session_factory() as session:
        return [sensor_to_dict(s, now) for s in session.query(Sensor).order_by(Sensor.SensorID).all()]


@router.post("/sensors", status_code=status.HTTP_201_CREATED)
def register_sensor(body: SensorBody, request: Request, user: ManageSensors, services: ServicesDep):
    with services.session_factory() as session:
        if session.query(Sensor).filter_by(Name=body.name).first() is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "A sensor with this name already exists.")
        token = create_sensor(session, body.name)
    write_audit(services, request, user.username, "sensor_created", body.name)
    return {"name": body.name, "token": token}  # the only time the token is shown


@router.delete("/sensors/{sensor_id}")
def revoke_sensor(sensor_id: int, request: Request, user: ManageSensors, services: ServicesDep):
    with services.session_factory() as session:
        sensor = session.get(Sensor, sensor_id)
        if sensor is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Sensor not found")
        sensor.IsActive = False
        session.commit()
        name = sensor.Name
    write_audit(services, request, user.username, "sensor_revoked", name)
    return {"revoked": True}


# ---- users ----------------------------------------------------------------------------------------------


class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=MAX_USERNAME_LENGTH)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    role: Role
    email: str | None = Field(default=None, max_length=120)


class UserChange(BaseModel):
    role: Role | None = None
    password: str | None = Field(default=None, max_length=MAX_PASSWORD_LENGTH)


def _user_dict(user: User) -> dict:
    return {
        "id": user.UserID,
        "username": user.Username,
        "email": user.Email,
        "role": user.Role,
        "created": iso_utc(user.CreatedAt),
    }


def _admin_count(session) -> int:
    return session.query(User).filter_by(Role=Role.ADMIN.value).count()


@router.get("/users")
def list_users(user: ManageUsers, services: ServicesDep):
    with services.session_factory() as session:
        return [_user_dict(u) for u in session.query(User).order_by(User.UserID).all()]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(body: NewUser, request: Request, user: ManageUsers, services: ServicesDep):
    if (problem := password_problem(body.password)) is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, problem)
    with services.session_factory() as session:
        if session.query(User).filter_by(Username=body.username).first() is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "This username is taken.")
        new_user = User(
            Username=body.username,
            Email=body.email,
            PasswordHash=hash_password(body.password),
            Role=body.role.value,
        )
        session.add(new_user)
        session.commit()
        result = _user_dict(new_user)
    write_audit(services, request, user.username, "user_created", f"{body.username} as {body.role.value}")
    return result


@router.patch("/users/{user_id}")
def change_user(user_id: int, body: UserChange, request: Request, user: ManageUsers, services: ServicesDep):
    if body.password is not None and (problem := password_problem(body.password)) is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, problem)
    with services.session_factory() as session:
        target = session.get(User, user_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        if (
            body.role
            and target.Role == Role.ADMIN.value
            and body.role is not Role.ADMIN
            and _admin_count(session) <= 1
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "There must be at least one admin.")
        if body.role:
            target.Role = body.role.value
        if body.password is not None:
            target.PasswordHash = hash_password(body.password)
        session.commit()
        result = _user_dict(target)
    changed = [
        name for name, value in (("role", body.role), ("password", body.password)) if value is not None
    ]
    write_audit(
        services, request, user.username, "user_changed", f"{result['username']}: {', '.join(changed)}"
    )
    return result


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, user: ManageUsers, services: ServicesDep):
    if user_id == user.user_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "You cannot delete your own account.")
    with services.session_factory() as session:
        target = session.get(User, user_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        if target.Role == Role.ADMIN.value and _admin_count(session) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "There must be at least one admin.")
        name = target.Username
        session.delete(target)
        session.commit()
    write_audit(services, request, user.username, "user_deleted", name)
    return {"deleted": True}


# ---- audit ----------------------------------------------------------------------------------------------


@router.get("/audit")
def audit_log(user: ViewAudit, services: ServicesDep):
    with services.session_factory() as session:
        entries = session.query(AuditLog).order_by(AuditLog.AuditID.desc()).limit(AUDIT_PAGE_SIZE).all()
        return [
            {
                "time": iso_utc(e.At),
                "user": e.Username,
                "action": e.Action,
                "detail": e.Detail,
                "ip": e.ClientIP,
            }
            for e in entries
        ]
