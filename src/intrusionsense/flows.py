from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from intrusionsense.packets import PacketInfo

# CICFlowMeter's activity timeout: a gap this long splits active and idle periods
ACTIVITY_TIMEOUT_SECONDS = 5.0
# CICFlowMeter's flow timeout: longer flows are cut and a new flow starts
MAX_FLOW_DURATION_SECONDS = 120.0
# a flow with no packets for this long is finished (shorter than CICFlowMeter, to free memory sooner)
IDLE_FLOW_TIMEOUT_SECONDS = 15.0
# long-lived flows are also analysed mid-way, so a slow DoS alerts before the flow ends
ANALYZE_EVERY_N_PACKETS = 50
MIN_PACKETS_TO_ANALYZE = 2
MAX_ACTIVE_FLOWS = 100_000
MAX_PAYLOAD_SAMPLES = 5

FlowKey = tuple[str, str, int, int, int]  # src_ip, dst_ip, src_port, dst_port, protocol (initiator first)


class FlowEvent(Enum):
    UPDATE = "update"  # periodic mid-flow report, flow keeps running
    FINISHED = "finished"  # FIN/RST seen
    TIMEOUT = "timeout"  # idle, too long, or evicted


@dataclass
class Flow:
    key: FlowKey
    start_time: float
    last_packet_time: float
    fwd_timestamps: list[float] = field(default_factory=list)
    bwd_timestamps: list[float] = field(default_factory=list)
    fwd_lengths: list[int] = field(default_factory=list)
    bwd_lengths: list[int] = field(default_factory=list)
    fin_flag: int = 0
    psh_flag: int = 0
    ack_flag: int = 0
    syn_flag: int = 0
    act_data_pkt_fwd: int = 0
    idle_times: list[float] = field(default_factory=list)
    active_times: list[float] = field(default_factory=list)
    last_active_start: float = 0.0
    packets_at_last_report: int = 0
    payload_samples: list[bytes] = field(default_factory=list)

    @property
    def packet_count(self) -> int:
        return len(self.fwd_lengths) + len(self.bwd_lengths)

    def add_packet(self, packet: PacketInfo, is_forward: bool) -> None:
        gap = packet.timestamp - self.last_packet_time
        if self.packet_count and gap > ACTIVITY_TIMEOUT_SECONDS:
            self.idle_times.append(gap)
            self.active_times.append(self.last_packet_time - self.last_active_start)
            self.last_active_start = packet.timestamp
        self.last_packet_time = packet.timestamp

        if is_forward:
            self.fwd_timestamps.append(packet.timestamp)
            self.fwd_lengths.append(packet.payload_length)
            if packet.payload_length > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.bwd_timestamps.append(packet.timestamp)
            self.bwd_lengths.append(packet.payload_length)

        if packet.payload and len(self.payload_samples) < MAX_PAYLOAD_SAMPLES:
            self.payload_samples.append(packet.payload)

        # CICFlowMeter-style booleans: was the flag ever seen in this flow
        flags = packet.tcp_flags
        self.fin_flag |= "F" in flags
        self.psh_flag |= "P" in flags
        self.ack_flag |= "A" in flags
        self.syn_flag |= "S" in flags


@dataclass(frozen=True, slots=True)
class FlowReport:
    flow: Flow
    event: FlowEvent


class FlowTable:
    """Groups packets into bidirectional flows and says when each flow is ready to analyse."""

    def __init__(
        self, max_flows: int = MAX_ACTIVE_FLOWS, on_new_flow: Callable[[FlowKey, float], None] | None = None
    ):
        self.max_flows = max_flows
        self.on_new_flow = on_new_flow
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()  # least recently seen first

    def __len__(self) -> int:
        return len(self._flows)

    def add_packet(self, packet: PacketInfo) -> list[FlowReport]:
        reports = []
        forward_key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        backward_key = (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.protocol)

        if forward_key in self._flows:
            key, is_forward = forward_key, True
        elif backward_key in self._flows:
            key, is_forward = backward_key, False
        else:
            key, is_forward = forward_key, True
            reports += self._make_room()
            self._start_flow(key, packet.timestamp)

        flow = self._flows[key]
        if packet.timestamp - flow.start_time > MAX_FLOW_DURATION_SECONDS:
            reports += self._close(key, FlowEvent.TIMEOUT)
            flow = self._start_flow(key, packet.timestamp)

        flow.add_packet(packet, is_forward)
        self._flows.move_to_end(key)

        if "F" in packet.tcp_flags or "R" in packet.tcp_flags:
            reports += self._close(key, FlowEvent.FINISHED)
        elif flow.packet_count - flow.packets_at_last_report >= ANALYZE_EVERY_N_PACKETS:
            flow.packets_at_last_report = flow.packet_count
            reports.append(FlowReport(flow, FlowEvent.UPDATE))
        return reports

    def expire_idle(self, now: float) -> list[FlowReport]:
        """Close flows without packets for IDLE_FLOW_TIMEOUT_SECONDS. `now` is in capture time."""
        reports = []
        while self._flows:
            key, oldest = next(iter(self._flows.items()))
            if now - oldest.last_packet_time <= IDLE_FLOW_TIMEOUT_SECONDS:
                break
            reports += self._close(key, FlowEvent.TIMEOUT)
        return reports

    def close_all(self) -> list[FlowReport]:
        reports = []
        for key in list(self._flows):
            reports += self._close(key, FlowEvent.TIMEOUT)
        return reports

    def _start_flow(self, key: FlowKey, timestamp: float) -> Flow:
        flow = Flow(key=key, start_time=timestamp, last_packet_time=timestamp, last_active_start=timestamp)
        self._flows[key] = flow
        if self.on_new_flow:
            self.on_new_flow(key, timestamp)
        return flow

    def _make_room(self) -> list[FlowReport]:
        reports = []
        while len(self._flows) >= self.max_flows:
            reports += self._close(next(iter(self._flows)), FlowEvent.TIMEOUT)
        return reports

    def _close(self, key: FlowKey, event: FlowEvent) -> list[FlowReport]:
        flow = self._flows.pop(key)
        if flow.packet_count < MIN_PACKETS_TO_ANALYZE:
            return []
        return [FlowReport(flow, event)]
