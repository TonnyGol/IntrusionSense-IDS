"""How long does it take from a flow closing to a detection decision? Measured, not claimed."""

import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from intrusionsense.detection import Detector
from intrusionsense.engine import IDSEngine
from intrusionsense.flows import FlowTable
from intrusionsense.packets import PacketInfo
from intrusionsense.records import FlowBatch, record_from_report
from intrusionsense.rules import RuleEngine

PACKETS_PER_FLOW = 12
PACKET_GAP_SECONDS = 0.01
BASE_TIME = 1_700_000_000.0
MILLISECONDS = 1000.0
PERCENTILES = (50, 95, 99)
NOT_USED = -1


@dataclass(frozen=True)
class LatencyResult:
    flows: int
    percentiles_ms: dict[int, float]
    mean_ms: float


def _flow_packets(flow_number: int, rng: np.random.Generator) -> list[PacketInfo]:
    """One TCP flow of mixed small and large packets that ends with a FIN."""
    src, dst = f"10.1.{flow_number // 250}.{flow_number % 250 + 1}", "10.9.0.1"
    start = BASE_TIME + flow_number * 0.001
    packets = []
    for i in range(PACKETS_PER_FLOW):
        is_last = i == PACKETS_PER_FLOW - 1
        size = int(rng.integers(0, 1400))
        packets.append(
            PacketInfo(
                timestamp=start + i * PACKET_GAP_SECONDS,
                src_ip=src if i % 2 == 0 else dst,
                dst_ip=dst if i % 2 == 0 else src,
                src_port=40000 + flow_number % 20000 if i % 2 == 0 else 443,
                dst_port=443 if i % 2 == 0 else 40000 + flow_number % 20000,
                protocol=6,
                payload_length=size,
                payload=b"",
                tcp_flags="FA" if is_last else "A",
            )
        )
    return packets


def measure_latency(model_dir: Path, l1_threshold: float, flows: int, seed: int = 42) -> LatencyResult:
    """Per flow: features, record serialization, parsing on the server side, rules and both model layers.

    Network transfer and the database write are not included; they depend on the deployment.
    """
    rng = np.random.default_rng(seed)
    detector = Detector(IDSEngine(model_dir, l1_threshold), RuleEngine([]))
    table = FlowTable()
    durations = []
    for number in range(flows):
        reports = []
        for packet in _flow_packets(number, rng):
            reports += table.add_packet(packet)
        for report in reports:
            started = time.perf_counter()
            body = '{"records":[' + record_from_report(report, 0).model_dump_json() + "]}"
            for record in FlowBatch.model_validate_json(body).records:
                detector.analyze(record)
            durations.append((time.perf_counter() - started) * MILLISECONDS)
    values = np.array(durations)
    return LatencyResult(
        flows=len(values),
        percentiles_ms={p: float(np.percentile(values, p)) for p in PERCENTILES},
        mean_ms=float(values.mean()),
    )
