import ipaddress
import logging
import queue
import socket
from urllib.parse import urlparse

import psutil
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

log = logging.getLogger(__name__)

BASE_BPF_FILTER = "ip and (tcp or udp)"
MAX_QUEUED_PACKETS = 50_000
# no packet is sent: connecting a UDP socket only asks the OS which interface routes to the internet
ROUTE_PROBE_ADDRESS = ("8.8.8.8", 80)
DEFAULT_HTTP_PORTS = {"http": 80, "https": 443}


def default_interface() -> str | None:
    """Name of the interface that carries the default route."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(ROUTE_PROBE_ADDRESS)
        except OSError:
            return None
        local_ip = probe.getsockname()[0]
    for name, addresses in psutil.net_if_addrs().items():
        if any(a.family == socket.AF_INET and a.address == local_ip for a in addresses):
            return name
    return None


def bpf_filter_excluding(server_url: str) -> str:
    """Capture filter that skips the sensor's own uploads, which would otherwise become flows to report."""
    url = urlparse(server_url)
    host_ip = socket.gethostbyname(url.hostname)
    if ipaddress.ip_address(host_ip).is_loopback:
        return BASE_BPF_FILTER  # loopback traffic never reaches the capture interface
    port = url.port or DEFAULT_HTTP_PORTS.get(url.scheme, 80)
    return f"{BASE_BPF_FILTER} and not (host {host_ip} and tcp port {port})"


class LiveCapture:
    """Sniffs on a background thread into a bounded queue; packets that do not fit are counted."""

    def __init__(self, interface: str, bpf_filter: str, max_queued: int = MAX_QUEUED_PACKETS):
        self.packets: queue.Queue = queue.Queue(maxsize=max_queued)
        self.dropped = 0
        self._sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=self._enqueue, store=False)

    def start(self) -> None:
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer.running:
            self._sniffer.stop()

    @property
    def error(self) -> Exception | None:
        """The exception that ended the capture thread, if it died."""
        return self._sniffer.exception

    def _enqueue(self, packet) -> None:
        try:
            self.packets.put_nowait(packet)
        except queue.Full:
            # never block the capture thread: a stalled sniffer loses far more packets
            self.dropped += 1


def read_pcap(path: str):
    with PcapReader(path) as reader:
        yield from reader
