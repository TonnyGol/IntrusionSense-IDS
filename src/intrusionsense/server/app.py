import logging
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from intrusionsense.records import FlowBatch
from intrusionsense.server.services import Services
from intrusionsense.storage.models import Sensor
from intrusionsense.storage.sensors import authenticate_sensor

log = logging.getLogger(__name__)

MAX_BATCH_BYTES = 4 * 1024 * 1024
BEARER_PREFIX = "Bearer "
SENSOR_INGEST_PATH = "/api/sensor/flows"


def _services(request: Request) -> Services:
    return request.app.state.services


async def _limit_ingest_body_size(request: Request, call_next):
    """Reject oversized sensor batches before the body is read: uvicorn itself has no body limit."""
    if request.url.path == SENSOR_INGEST_PATH:
        declared = request.headers.get("content-length")
        # requiring Content-Length rules out unbounded chunked bodies; uvicorn enforces the declared size
        if declared is None or not declared.isdigit():
            return JSONResponse({"detail": "Content-Length required"}, status.HTTP_411_LENGTH_REQUIRED)
        if int(declared) > MAX_BATCH_BYTES:
            return JSONResponse({"detail": "Batch too large"}, status.HTTP_413_CONTENT_TOO_LARGE)
    return await call_next(request)


def _authenticated_sensor(
    services: Annotated[Services, Depends(_services)],
    authorization: Annotated[str | None, Header()] = None,
) -> Sensor:
    if not authorization or not authorization.startswith(BEARER_PREFIX):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sensor token required")
    with services.session_factory() as session:
        sensor = authenticate_sensor(session, authorization.removeprefix(BEARER_PREFIX))
    if sensor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked sensor token")
    return sensor


def create_app(services: Services) -> FastAPI:
    app = FastAPI(title="IntrusionSense", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = services
    app.middleware("http")(_limit_ingest_body_size)

    @app.get("/api/health")
    def health(services: Annotated[Services, Depends(_services)]):
        try:
            with services.session_factory() as session:
                session.execute(text("SELECT 1"))
        except Exception as exc:
            log.error("Health check: database unavailable: %s", exc)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from exc
        return {"status": "ok"}

    @app.post(SENSOR_INGEST_PATH)
    def ingest_flows(
        batch: FlowBatch,
        sensor: Annotated[Sensor, Depends(_authenticated_sensor)],
        services: Annotated[Services, Depends(_services)],
    ):
        new_alerts = 0
        for record in batch.records:
            detection = services.detector.analyze(record)
            if detection is None:
                continue
            alert_id, is_new = services.alert_store.save(detection, sensor.SensorID)
            if is_new:
                new_alerts += 1
                log.warning(
                    "ALERT %d %s (%s) %s:%d -> %s:%d via %s",
                    alert_id,
                    detection.label,
                    detection.severity.value,
                    record.src_ip,
                    record.src_port,
                    record.dst_ip,
                    record.dst_port,
                    sensor.Name,
                )
        return {"accepted": len(batch.records), "new_alerts": new_alerts}

    return app
