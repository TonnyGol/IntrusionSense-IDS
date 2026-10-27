"""The flow record a sensor sends to the server: everything detection needs, no raw packets."""

import base64
from typing import Annotated

from pydantic import Base64Bytes, BaseModel, Field, IPvAnyAddress

from intrusionsense.features import compute_features
from intrusionsense.flows import MAX_PAYLOAD_SAMPLES, FlowEvent, FlowReport

MAX_PAYLOAD_SAMPLE_BYTES = 4096
MAX_FEATURES_PER_RECORD = 100
MAX_RECORDS_PER_BATCH = 500
MAX_PORT = 65535
MAX_IP_PROTOCOL = 255

Port = Annotated[int, Field(ge=0, le=MAX_PORT)]


class FlowRecord(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: Port
    dst_port: Port
    protocol: Annotated[int, Field(ge=0, le=MAX_IP_PROTOCOL)]
    start_time: float
    end_time: float
    packet_count: Annotated[int, Field(ge=0)]
    event: FlowEvent
    features: Annotated[dict[str, float], Field(max_length=MAX_FEATURES_PER_RECORD)]
    # base64 on the wire, bytes in Python; the sensor cuts each to MAX_PAYLOAD_SAMPLE_BYTES
    payload_samples: Annotated[list[Base64Bytes], Field(max_length=MAX_PAYLOAD_SAMPLES)] = []
    # new flows this source opened in the last minute, counted by the sensor because it sees
    # single-packet flows (unanswered SYNs) that are never sent as records
    src_connections_last_minute: Annotated[int, Field(ge=0)] = 0


class FlowBatch(BaseModel):
    records: Annotated[list[FlowRecord], Field(max_length=MAX_RECORDS_PER_BATCH)]


def record_from_report(report: FlowReport, src_connections_last_minute: int) -> FlowRecord:
    flow = report.flow
    src_ip, dst_ip, src_port, dst_port, protocol = flow.key
    return FlowRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        start_time=flow.start_time,
        end_time=flow.last_packet_time,
        packet_count=flow.packet_count,
        event=report.event,
        features=compute_features(flow),
        payload_samples=[
            base64.b64encode(payload[:MAX_PAYLOAD_SAMPLE_BYTES]) for payload in flow.payload_samples
        ],
        src_connections_last_minute=src_connections_last_minute,
    )
