from datetime import timedelta
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload

from intrusionsense.labels import Severity
from intrusionsense.server.deps import (
    Authenticated,
    CurrentUser,
    ServicesDep,
    require,
    require_client_header,
    write_audit,
)
from intrusionsense.server.security import Permission
from intrusionsense.server.serialize import alert_to_dict, iso_utc, sensor_to_dict
from intrusionsense.storage.models import Alert, Sensor, TrafficLog, utc_now

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_SEARCH_LENGTH = 100
STATS_HOURS = 24
TOP_ENTRIES = 5

router = APIRouter(prefix="/api", dependencies=[Depends(require_client_header)])


class AlertStatus(StrEnum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class StatusUpdate(BaseModel):
    status: AlertStatus


def _alert_query(session):
    return session.query(Alert).options(
        joinedload(Alert.associated_log), joinedload(Alert.sensor), joinedload(Alert.triggered_rule)
    )


@router.get("/alerts")
def list_alerts(
    user: Authenticated,
    services: ServicesDep,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    search: Annotated[str | None, Query(max_length=MAX_SEARCH_LENGTH)] = None,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
):
    """Newest first. Pass the last id you received as before_id to get the next page."""
    with services.session_factory() as session:
        query = _alert_query(session).join(Alert.associated_log)
        if status_filter:
            query = query.filter(Alert.Status == status_filter.value)
        if severity:
            query = query.filter(Alert.Severity == severity.value)
        if before_id:
            query = query.filter(Alert.AlertID < before_id)
        if search:
            like = f"%{search}%"
            query = query.filter(
                or_(Alert.AttackType.like(like), TrafficLog.SourceIP.like(like), TrafficLog.DestIP.like(like))
            )
        alerts = query.order_by(Alert.AlertID.desc()).limit(limit).all()
        return {"alerts": [alert_to_dict(a) for a in alerts], "has_more": len(alerts) == limit}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, user: Authenticated, services: ServicesDep):
    with services.session_factory() as session:
        alert = _alert_query(session).filter(Alert.AlertID == alert_id).first()
        if alert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
        return alert_to_dict(alert, with_payloads=True)


@router.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    body: StatusUpdate,
    request: Request,
    user: Annotated[CurrentUser, Depends(require(Permission.TRIAGE_ALERTS))],
    services: ServicesDep,
):
    with services.session_factory() as session:
        alert = _alert_query(session).filter(Alert.AlertID == alert_id).first()
        if alert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
        alert.Status = body.status.value
        alert.AssignedID = user.user_id
        session.commit()
        result = alert_to_dict(alert)
    write_audit(services, request, user.username, "alert_status", f"alert {alert_id} -> {body.status.value}")
    services.hub.publish({"type": "alert_updated", "alert": result})
    return result


@router.get("/stats")
def stats(user: Authenticated, services: ServicesDep):
    now = utc_now()
    since = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=STATS_HOURS - 1)
    with services.session_factory() as session:
        recent = session.query(Alert.Timestamp, Alert.Severity).filter(Alert.Timestamp >= since).all()
        hours = [
            {"start": iso_utc(since + timedelta(hours=h)), **{s.value: 0 for s in Severity}}
            for h in range(STATS_HOURS)
        ]
        for timestamp, severity in recent:
            index = int((timestamp - since).total_seconds() // 3600)
            if 0 <= index < STATS_HOURS and severity in hours[index]:
                hours[index][severity] += 1

        open_by_severity = dict(
            session.query(Alert.Severity, func.count())
            .filter(Alert.Status == AlertStatus.ACTIVE.value)
            .group_by(Alert.Severity)
            .all()
        )
        top_types = (
            session.query(Alert.AttackType, func.count().label("n"))
            .filter(Alert.Timestamp >= since)
            .group_by(Alert.AttackType)
            .order_by(func.count().desc())
            .limit(TOP_ENTRIES)
            .all()
        )
        top_sources = (
            session.query(TrafficLog.SourceIP, func.count().label("n"))
            .join(Alert, Alert.AssociatedLogID == TrafficLog.LogID)
            .filter(Alert.Timestamp >= since)
            .group_by(TrafficLog.SourceIP)
            .order_by(func.count().desc())
            .limit(TOP_ENTRIES)
            .all()
        )
        sensors = [sensor_to_dict(s, now) for s in session.query(Sensor).filter_by(IsActive=True).all()]
    return {
        "hours": hours,
        "open_by_severity": {s.value: open_by_severity.get(s.value, 0) for s in Severity},
        "top_attack_types": [{"name": name, "count": n} for name, n in top_types],
        "top_sources": [{"ip": ip, "count": n} for ip, n in top_sources],
        "sensors_online": sum(1 for s in sensors if s["online"]),
        "sensors_total": len(sensors),
    }
