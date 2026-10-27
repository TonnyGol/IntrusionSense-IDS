from collections import deque

import requests
from conftest import ATTACKER, START_TIME, VICTIM, tcp_packet
from scapy.utils import wrpcap

from intrusionsense.records import FlowRecord
from intrusionsense.sensor import (
    MAX_UPLOAD_BYTES,
    ConnectionCounter,
    FlowUploader,
    Sensor,
    _take_batch,
)


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = ""


class FakeHttp:
    """Stands in for requests.Session: replies with the given status codes in order."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.bodies = []

    def post(self, url, data, timeout):
        self.bodies.append(data)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


def uploader_with(*outcomes):
    uploader = FlowUploader("http://server", "token")
    uploader._http = FakeHttp(*outcomes)
    return uploader


def test_connection_counter_only_counts_the_last_minute():
    counter = ConnectionCounter()
    for offset in (0, 30, 59):
        counter.on_new_flow((ATTACKER, VICTIM, 1, 2, 6), START_TIME + offset)

    assert counter.count(ATTACKER, START_TIME + 59) == 3
    assert counter.count(ATTACKER, START_TIME + 80) == 2  # window starts at +20 s
    assert counter.count(ATTACKER, START_TIME + 100) == 1


def test_batches_stay_under_the_byte_limit():
    big_record = "x" * (MAX_UPLOAD_BYTES // 2)
    buffer = deque([big_record] * 3)

    assert len(_take_batch(buffer)) == 1
    assert len(buffer) == 2


def test_successful_upload_empties_the_buffer():
    uploader = uploader_with(200)
    uploader.enqueue("{}")

    assert uploader.send_batch()
    assert len(uploader) == 0 and uploader.records_sent == 1


def test_network_errors_and_auth_failures_keep_records_for_retry():
    uploader = uploader_with(requests.ConnectionError("down"), 401, 503)
    uploader.enqueue("{}")

    assert not uploader.send_batch()
    assert not uploader.send_batch()
    assert not uploader.send_batch()
    assert len(uploader) == 1


def test_rejected_data_is_dropped_so_it_cannot_block_the_queue():
    uploader = uploader_with(422)
    uploader.enqueue("{}")

    assert uploader.send_batch()
    assert len(uploader) == 0 and uploader.records_dropped == 1


def test_full_buffer_drops_the_oldest_record():
    uploader = FlowUploader("http://server", "token", max_buffered=2)
    for record_json in ("a", "b", "c"):
        uploader.enqueue(record_json)

    assert list(uploader._buffer) == ["b", "c"]
    assert uploader.records_dropped == 1


def test_pcap_replay_turns_a_port_scan_into_flow_records(tmp_path):
    # SYN to 20 ports, each answered by RST: 20 two-packet flows
    packets = []
    for port in range(1000, 1020):
        at = START_TIME + (port - 1000) * 0.01
        packets.append(tcp_packet(dport=port, flags="S", at=at))
        packets.append(
            tcp_packet(src=VICTIM, dst=ATTACKER, sport=port, dport=40000, flags="RA", at=at + 0.001)
        )
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), packets)

    uploader = FlowUploader("http://server", "token")
    Sensor(uploader).run_pcap(str(pcap))

    records = [FlowRecord.model_validate_json(r) for r in uploader._buffer]
    assert len(records) == 20
    assert {r.dst_port for r in records} == set(range(1000, 1020))
    assert records[-1].src_connections_last_minute == 20
