import logging
import queue
import threading
import time
from collections import defaultdict, deque

import requests

from intrusionsense.capture import LiveCapture, read_pcap
from intrusionsense.flows import FlowKey, FlowReport, FlowTable
from intrusionsense.packets import parse_packet
from intrusionsense.records import MAX_RECORDS_PER_BATCH, record_from_report

log = logging.getLogger(__name__)

CONNECTION_WINDOW_SECONDS = 60.0
INGEST_PATH = "/api/sensor/flows"
MAX_BUFFERED_RECORDS = 20_000
MAX_UPLOAD_BYTES = 3 * 1024 * 1024  # under the server's 4 MB batch limit
UPLOAD_INTERVAL_SECONDS = 1.0
# the server shows a sensor as online if it was heard from in the last two minutes
HEARTBEAT_SECONDS = 30.0
MAX_RETRY_DELAY_SECONDS = 30.0
REQUEST_TIMEOUT_SECONDS = 10.0
DRAIN_TIMEOUT_SECONDS = 15.0
QUEUE_POLL_SECONDS = 0.5
EXPIRE_EVERY_SECONDS = 1.0
STATS_EVERY_SECONDS = 60.0


class ConnectionCounter:
    """New flows per source address over the last minute, in capture time."""

    def __init__(self):
        self._starts: dict[str, deque[float]] = defaultdict(deque)

    def on_new_flow(self, key: FlowKey, timestamp: float) -> None:
        self._starts[key[0]].append(timestamp)

    def count(self, src_ip: str, now: float) -> int:
        starts = self._starts.get(src_ip)
        if not starts:
            return 0
        while starts and starts[0] < now - CONNECTION_WINDOW_SECONDS:
            starts.popleft()
        return len(starts)

    def forget_quiet_sources(self, now: float) -> None:
        cutoff = now - CONNECTION_WINDOW_SECONDS
        for src_ip in [ip for ip, starts in self._starts.items() if not starts or starts[-1] < cutoff]:
            del self._starts[src_ip]


class FlowUploader:
    """Buffers serialized flow records and posts them to the server in size-limited batches."""

    def __init__(self, server_url: str, token: str, max_buffered: int = MAX_BUFFERED_RECORDS):
        self.url = server_url.rstrip("/") + INGEST_PATH
        self.records_sent = 0
        self.records_dropped = 0
        self._buffer: deque[str] = deque()
        self._max_buffered = max_buffered
        self._lock = threading.Lock()
        self._http = requests.Session()
        self._http.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def __len__(self) -> int:
        return len(self._buffer)

    def enqueue(self, record_json: str) -> None:
        with self._lock:
            if len(self._buffer) >= self._max_buffered:
                self._buffer.popleft()  # keep the newest records during a long outage
                self.records_dropped += 1
            self._buffer.append(record_json)

    def send_batch(self) -> bool:
        """Post one batch. True when the buffer made progress (sent or discarded), False to retry later."""
        with self._lock:
            batch = _take_batch(self._buffer)
        body = '{"records":[' + ",".join(batch) + "]}"
        try:
            response = self._http.post(self.url, data=body.encode(), timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            log.warning("Upload failed, will retry: %s", exc)
            self._put_back(batch)
            return False
        if response.ok:
            self.records_sent += len(batch)
            return True
        if response.status_code in (401, 403) or response.status_code >= 500:
            log.error("Server refused upload (%d %s), will retry", response.status_code, response.text[:200])
            self._put_back(batch)
            return False
        # any other 4xx means the data itself was rejected: resending the same bytes cannot succeed
        log.error("Server rejected %d records (%d %s)", len(batch), response.status_code, response.text[:200])
        self.records_dropped += len(batch)
        return True

    def run(self, stop: threading.Event) -> None:
        delay = UPLOAD_INTERVAL_SECONDS
        last_contact = time.monotonic()
        while not stop.is_set():
            if len(self) or time.monotonic() - last_contact >= HEARTBEAT_SECONDS:
                ok = (
                    self.send_batch()
                )  # with nothing buffered this is an empty batch: it only says "still here"
                last_contact = time.monotonic() if ok else last_contact
                delay = UPLOAD_INTERVAL_SECONDS if ok else min(delay * 2, MAX_RETRY_DELAY_SECONDS)
                stop.wait(0 if ok and len(self) else delay)
            else:
                stop.wait(UPLOAD_INTERVAL_SECONDS)

    def drain(self, timeout: float = DRAIN_TIMEOUT_SECONDS) -> None:
        deadline = time.monotonic() + timeout
        while len(self) and time.monotonic() < deadline:
            if not self.send_batch():
                break
        if len(self):
            log.warning("%d records were not uploaded before shutdown", len(self))

    def _put_back(self, batch: list[str]) -> None:
        with self._lock:
            self._buffer.extendleft(reversed(batch))


def _take_batch(buffer: deque[str]) -> list[str]:
    batch, size = [], 0
    while buffer and len(batch) < MAX_RECORDS_PER_BATCH:
        if batch and size + len(buffer[0]) > MAX_UPLOAD_BYTES:
            break
        record_json = buffer.popleft()
        batch.append(record_json)
        size += len(record_json) + 1
    return batch


class Sensor:
    """Packets -> flows -> flow records -> uploader."""

    def __init__(self, uploader: FlowUploader):
        self.uploader = uploader
        self.connections = ConnectionCounter()
        self.flows = FlowTable(on_new_flow=self.connections.on_new_flow)
        self.packets_seen = 0
        self.packets_skipped = 0  # not IPv4 TCP/UDP, or unparseable

    def process_packet(self, raw_packet) -> None:
        self.packets_seen += 1
        try:
            packet = parse_packet(raw_packet)
        except Exception as exc:  # one malformed packet must not stop the sensor
            self.packets_skipped += 1
            log.debug("Could not parse packet: %s", exc)
            return
        if packet is None:
            self.packets_skipped += 1
            return
        self._send(self.flows.add_packet(packet))

    def expire(self, now: float) -> None:
        self._send(self.flows.expire_idle(now))
        self.connections.forget_quiet_sources(now)

    def close_all(self) -> None:
        self._send(self.flows.close_all())

    def _send(self, reports: list[FlowReport]) -> None:
        for report in reports:
            src_ip = report.flow.key[0]
            connections = self.connections.count(src_ip, report.flow.last_packet_time)
            self.uploader.enqueue(record_from_report(report, connections).model_dump_json())

    def run_live(self, capture: LiveCapture, stop: threading.Event) -> None:
        capture.start()
        last_expire = last_stats = time.time()
        try:
            while not stop.is_set():
                if capture.error is not None:
                    raise RuntimeError(f"capture stopped: {capture.error}") from capture.error
                try:
                    self.process_packet(capture.packets.get(timeout=QUEUE_POLL_SECONDS))
                except queue.Empty:
                    pass
                now = time.time()
                if now - last_expire >= EXPIRE_EVERY_SECONDS:
                    self.expire(now)
                    last_expire = now
                if now - last_stats >= STATS_EVERY_SECONDS:
                    self.log_stats(capture.dropped)
                    last_stats = now
        finally:
            capture.stop()
            self.close_all()

    def run_pcap(self, path: str) -> None:
        last_expire = None
        for raw_packet in read_pcap(path):
            self.process_packet(raw_packet)
            # replay runs on the file's clock, not the wall clock
            packet_time = float(raw_packet.time)
            if last_expire is None or packet_time - last_expire >= EXPIRE_EVERY_SECONDS:
                self.expire(packet_time)
                last_expire = packet_time
        self.close_all()

    def log_stats(self, dropped: int) -> None:
        log.info(
            "packets seen=%d skipped=%d dropped=%d | flows=%d | records sent=%d buffered=%d dropped=%d",
            self.packets_seen,
            self.packets_skipped,
            dropped,
            len(self.flows),
            self.uploader.records_sent,
            len(self.uploader),
            self.uploader.records_dropped,
        )
