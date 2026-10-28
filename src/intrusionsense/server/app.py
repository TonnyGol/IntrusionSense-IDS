import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from intrusionsense.records import FlowBatch
from intrusionsense.server import routes_admin, routes_alerts, routes_auth
from intrusionsense.server.deps import SESSION_USER_KEY, get_services
from intrusionsense.server.serialize import alert_to_dict
from intrusionsense.server.services import Services
from intrusionsense.storage.models import Alert, Sensor
from intrusionsense.storage.sensors import authenticate_sensor

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BATCH_BYTES = 4 * 1024 * 1024
BEARER_PREFIX = "Bearer "
SENSOR_INGEST_PATH = "/api/sensor/flows"
SESSION_COOKIE_NAME = "intrusionsense_session"
SESSION_LIFETIME_SECONDS = 8 * 60 * 60
WEBSOCKET_POLICY_VIOLATION = 1008

# no inline script or style and no third-party origins: a payload that reaches the page cannot run
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


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


async def _add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"  # alert data must not sit in a shared cache
    return response


def _authenticated_sensor(
    services: Annotated[Services, Depends(get_services)],
    authorization: Annotated[str | None, Header()] = None,
) -> Sensor:
    if not authorization or not authorization.startswith(BEARER_PREFIX):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sensor token required")
    with services.session_factory() as session:
        sensor = authenticate_sensor(session, authorization.removeprefix(BEARER_PREFIX))
    if sensor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked sensor token")
    return sensor


def _same_origin(websocket: WebSocket) -> bool:
    """Browsers always send Origin on WebSocket handshakes; another site's page must not ride our cookie."""
    origin = websocket.headers.get("origin")
    return origin is not None and urlparse(origin).netloc == websocket.headers.get("host")


def create_app(services: Services, session_secret: str, secure_cookies: bool = False) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app):
        services.hub.attach_to_running_loop()
        yield

    app = FastAPI(title="IntrusionSense", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.services = services
    # each middleware wraps the ones added before it, so the security headers end up outermost
    app.middleware("http")(_limit_ingest_body_size)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie=SESSION_COOKIE_NAME,
        max_age=SESSION_LIFETIME_SECONDS,
        same_site="strict",
        https_only=secure_cookies,
    )
    app.middleware("http")(_add_security_headers)

    app.include_router(routes_auth.router)
    app.include_router(routes_alerts.router)
    app.include_router(routes_admin.router)

    @app.get("/api/health")
    def health(services: Annotated[Services, Depends(get_services)]):
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
        services: Annotated[Services, Depends(get_services)],
    ):
        new_alerts = 0
        for record in batch.records:
            detection = services.detector.analyze(record)
            if detection is None:
                continue
            alert_id, is_new = services.alert_store.save(detection, sensor.SensorID)
            _publish_alert(services, alert_id, is_new)
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

    @app.websocket("/ws")
    async def live_alerts(websocket: WebSocket):
        if not _same_origin(websocket) or websocket.session.get(SESSION_USER_KEY) is None:
            await websocket.close(code=WEBSOCKET_POLICY_VIOLATION)
            return
        await websocket.accept()
        await services.hub.connect(websocket)
        try:
            while True:
                await websocket.receive_text()  # the browser never sends; this only notices a disconnect
        except WebSocketDisconnect:
            services.hub.disconnect(websocket)

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def _publish_alert(services: Services, alert_id: int, is_new: bool) -> None:
    with services.session_factory() as session:
        alert = session.get(Alert, alert_id)
        event = {"type": "alert" if is_new else "alert_updated", "alert": alert_to_dict(alert)}
    services.hub.publish(event)
