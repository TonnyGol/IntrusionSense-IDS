import asyncio
import logging

from fastapi import WebSocket

log = logging.getLogger(__name__)


class AlertHub:
    """Pushes events to every connected browser. publish() is safe to call from worker threads."""

    def __init__(self):
        self._connections: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def attach_to_running_loop(self) -> None:
        self._loop = asyncio.get_running_loop()

    async def connect(self, websocket: WebSocket) -> None:
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    def publish(self, event: dict) -> None:
        if self._loop is None or not self._connections:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(event), self._loop)

    async def _broadcast(self, event: dict) -> None:
        for websocket in list(self._connections):
            try:
                await websocket.send_json(event)
            except Exception:  # a dead socket must not stop delivery to the others
                self._connections.discard(websocket)
                log.debug("Dropped a closed websocket")
