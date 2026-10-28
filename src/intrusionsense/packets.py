from dataclasses import dataclass
from enum import IntEnum

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


class Protocol(IntEnum):
    TCP = 6
    UDP = 17


def protocol_name(protocol: int) -> str:
    return Protocol(protocol).name if protocol in Protocol._value2member_map_ else str(protocol)


@dataclass(frozen=True, slots=True)
class PacketInfo:
    """The parts of a captured packet the flow builder needs."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_length: int
    payload: bytes
    tcp_flags: str


def parse_packet(packet) -> PacketInfo | None:
    """Scapy packet -> PacketInfo, or None for anything that is not IPv4 TCP/UDP."""
    if not packet.haslayer(IP):
        return None
    if packet.haslayer(TCP):
        transport, flags = packet[TCP], str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        transport, flags = packet[UDP], ""
    else:
        return None
    ip = packet[IP]
    return PacketInfo(
        timestamp=float(packet.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=int(ip.proto),
        # transport payload only, the length CICFlowMeter (the training data's tool) counts
        payload_length=len(transport.payload),
        payload=bytes(packet[Raw].load) if packet.haslayer(Raw) else b"",
        tcp_flags=flags,
    )
