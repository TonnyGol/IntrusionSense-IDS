"""Sensor entry points. Kept apart from cli.py so the packaged sensor program stays small:
it must not pull in the web server or the machine-learning libraries."""

import argparse
import logging
import os
import signal
import sys
import threading

from intrusionsense.sensor_config import (
    CONFIG_FILE_NAME,
    SensorConfig,
    ask_and_save,
    config_path,
    load_config,
    wait_before_window_closes,
)

log = logging.getLogger("intrusionsense")

SECONDS_PER_MINUTE = 60
DEFAULT_RECORD_MINUTES = 30
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
TOKEN_ENV_VAR = "INTRUSIONSENSE_SENSOR_TOKEN"
INTERFACE_ENV_VAR = "SENSOR_INTERFACE"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(level: str) -> None:
    # stdout only: Docker, systemd and Windows services all collect it
    logging.basicConfig(level=level.upper(), format=LOG_FORMAT, stream=sys.stdout)


def exit_with_message(message: str) -> None:
    print(message, file=sys.stderr)
    wait_before_window_closes()
    sys.exit(1)


def resolve_config(args) -> SensorConfig:
    """Token: environment, sensor.conf, then asked for. Server: --server, sensor.conf, then the default."""
    path = config_path()
    stored = load_config(path)
    token = os.environ.get(TOKEN_ENV_VAR) or stored.token
    server = args.server or stored.server
    if not token and sys.stdin and sys.stdin.isatty():
        asked = ask_and_save(path, server or DEFAULT_SERVER_URL)
        token, server = asked.token, args.server or asked.server
    return SensorConfig(server=server or DEFAULT_SERVER_URL, token=token)


def run_sensor(args) -> None:
    from intrusionsense.capture import LiveCapture, bpf_filter_excluding, default_interface
    from intrusionsense.sensor import FlowUploader, Sensor

    configure_logging(args.log_level)
    if args.list_interfaces:
        from intrusionsense.capture import list_interfaces

        print("\n".join(list_interfaces()))
        return
    config = resolve_config(args)
    if not config.token:
        exit_with_message(
            f"No sensor token. Register a sensor in the dashboard and save its {CONFIG_FILE_NAME} "
            f"next to this program, or set {TOKEN_ENV_VAR}."
        )

    uploader = FlowUploader(config.server, config.token)
    sensor = Sensor(uploader)
    stop = threading.Event()
    upload_thread = threading.Thread(target=uploader.run, args=(stop,), name="uploader", daemon=True)
    upload_thread.start()

    capture = None
    if args.pcap:
        log.info("Replaying %s to %s", args.pcap, config.server)
        sensor.run_pcap(args.pcap)
    else:
        interface = args.iface or os.environ.get(INTERFACE_ENV_VAR) or default_interface()
        if interface is None:
            exit_with_message("Could not find the network interface; pass --iface.")
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
        log.info("Capturing on %s, sending to %s", interface, config.server)
        capture = LiveCapture(interface, bpf_filter_excluding(config.server))
        try:
            sensor.run_live(capture, stop)
        except (PermissionError, RuntimeError) as exc:
            log.error("%s (capture needs root, or CAP_NET_RAW on Linux, or Npcap on Windows)", exc)
            _shut_down(sensor, upload_thread, stop, capture)
            exit_with_message("Capture failed; see the message above.")
    _shut_down(sensor, upload_thread, stop, capture)


def _shut_down(sensor, upload_thread: threading.Thread, stop: threading.Event, capture) -> None:
    stop.set()
    upload_thread.join()
    sensor.uploader.drain()
    sensor.log_stats(capture.dropped if capture else 0)


def record_traffic(args) -> None:
    """Save flow features as labelled training rows instead of sending them to a server."""
    from intrusionsense.capture import BASE_BPF_FILTER, LiveCapture, default_interface
    from intrusionsense.recorder import CsvRecorder
    from intrusionsense.sensor import Sensor

    configure_logging("INFO")
    recorder = CsvRecorder(args.out, args.label)
    sensor = Sensor(recorder)
    if args.pcap:
        sensor.run_pcap(args.pcap)
    else:
        interface = args.iface or default_interface()
        if interface is None:
            sys.exit("Could not find the network interface; pass --iface.")
        stop = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
        threading.Timer(args.minutes * SECONDS_PER_MINUTE, stop.set).start()
        log.info(
            "Recording %d minutes on %s as '%s'. Use the network normally; Ctrl+C stops early.",
            args.minutes,
            interface,
            args.label,
        )
        sensor.run_live(LiveCapture(interface, BASE_BPF_FILTER), stop)
    recorder.close()
    print(f"Wrote {recorder.records_sent} flows to {args.out}")


def add_sensor_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server",
        help=f"server URL (default: from {CONFIG_FILE_NAME}, else {DEFAULT_SERVER_URL})",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--iface", help="interface to capture on (default: the one with the default route)")
    source.add_argument("--pcap", help="replay a capture file instead of sniffing")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--list-interfaces", action="store_true", help="show the names --iface accepts, then exit"
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="intrusionsense-sensor",
        description=f"Capture traffic and send flows to the server ({TOKEN_ENV_VAR})",
    )
    add_sensor_arguments(parser)
    run_sensor(parser.parse_args(argv))


if __name__ == "__main__":
    main()
