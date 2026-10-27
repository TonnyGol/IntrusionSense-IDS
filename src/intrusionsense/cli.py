import argparse
import getpass
import logging
import os
import signal
import sys
import threading

from intrusionsense.config import ServerSettings

log = logging.getLogger("intrusionsense")

MIN_PASSWORD_LENGTH = 12
ADMIN_ROLE = "Admin"
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
TOKEN_ENV_VAR = "INTRUSIONSENSE_SENSOR_TOKEN"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _configure_logging(level: str) -> None:
    # stdout only: Docker, systemd and Windows services all collect it
    logging.basicConfig(level=level.upper(), format=LOG_FORMAT, stream=sys.stdout)


def _session_factory(settings: ServerSettings):
    from intrusionsense.storage.db import create_db_engine, init_db, mysql_url

    return init_db(create_db_engine(mysql_url(settings)))


def serve(args) -> None:
    import uvicorn

    from intrusionsense.server.app import create_app
    from intrusionsense.server.services import build_services

    settings = ServerSettings()
    _configure_logging(settings.log_level)
    app = create_app(build_services(settings))
    uvicorn.run(app, host=args.host or settings.web_host, port=args.port or settings.web_port)


def run_sensor(args) -> None:
    from intrusionsense.capture import LiveCapture, bpf_filter_excluding, default_interface
    from intrusionsense.sensor import FlowUploader, Sensor

    _configure_logging(args.log_level)
    token = os.environ.get(TOKEN_ENV_VAR)
    if not token:
        sys.exit(f"Set {TOKEN_ENV_VAR} to the token from 'intrusionsense create-sensor'.")

    uploader = FlowUploader(args.server, token)
    sensor = Sensor(uploader)
    stop = threading.Event()
    upload_thread = threading.Thread(target=uploader.run, args=(stop,), name="uploader", daemon=True)
    upload_thread.start()

    capture = None
    if args.pcap:
        log.info("Replaying %s to %s", args.pcap, args.server)
        sensor.run_pcap(args.pcap)
    else:
        interface = args.iface or default_interface()
        if interface is None:
            sys.exit("Could not find the network interface; pass --iface.")
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
        log.info("Capturing on %s, sending to %s", interface, args.server)
        capture = LiveCapture(interface, bpf_filter_excluding(args.server))
        try:
            sensor.run_live(capture, stop)
        except (PermissionError, RuntimeError) as exc:
            log.error("%s (capture needs root, or CAP_NET_RAW on Linux, or Npcap on Windows)", exc)
            _shut_down(sensor, upload_thread, stop, capture)
            sys.exit(1)
    _shut_down(sensor, upload_thread, stop, capture)


def _shut_down(sensor, upload_thread: threading.Thread, stop: threading.Event, capture) -> None:
    stop.set()
    upload_thread.join()
    sensor.uploader.drain()
    sensor.log_stats(capture.dropped if capture else 0)


def create_admin(args) -> None:
    from argon2 import PasswordHasher

    from intrusionsense.storage.models import User

    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")

    password_hash = PasswordHasher().hash(password)
    with _session_factory(ServerSettings())() as session:
        user = session.query(User).filter_by(Username=args.username).first()
        if user:
            user.PasswordHash, user.Role = password_hash, ADMIN_ROLE
            action = "Password reset for"
        else:
            session.add(
                User(Username=args.username, Email=args.email, PasswordHash=password_hash, Role=ADMIN_ROLE)
            )
            action = "Created"
        session.commit()
    print(f"{action} admin user '{args.username}'.")


def create_sensor(args) -> None:
    from intrusionsense.storage.sensors import create_sensor as register_sensor

    with _session_factory(ServerSettings())() as session:
        token = register_sensor(session, args.name)
    print(f"Sensor '{args.name}' registered. Its token is shown only once:\n\n  {token}\n")
    print(f"Run the sensor with {TOKEN_ENV_VAR} set to this token.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="intrusionsense", description="IntrusionSense IDS")
    commands = parser.add_subparsers(dest="command", required=True)

    serve_cmd = commands.add_parser("serve", help="run the web server and detection API")
    serve_cmd.add_argument("--host", help="bind address (default WEB_HOST, 127.0.0.1)")
    serve_cmd.add_argument("--port", type=int, help="port (default WEB_PORT, 8000)")
    serve_cmd.set_defaults(handler=serve)

    sensor_cmd = commands.add_parser(
        "sensor", help=f"capture traffic and send flows to the server ({TOKEN_ENV_VAR})"
    )
    sensor_cmd.add_argument(
        "--server", default=DEFAULT_SERVER_URL, help=f"server URL (default {DEFAULT_SERVER_URL})"
    )
    source = sensor_cmd.add_mutually_exclusive_group()
    source.add_argument("--iface", help="interface to capture on (default: the one with the default route)")
    source.add_argument("--pcap", help="replay a capture file instead of sniffing")
    sensor_cmd.add_argument("--log-level", default="INFO")
    sensor_cmd.set_defaults(handler=run_sensor)

    admin_cmd = commands.add_parser("create-admin", help="create an admin or reset its password")
    admin_cmd.add_argument("--username", default="admin")
    admin_cmd.add_argument("--email")
    admin_cmd.set_defaults(handler=create_admin)

    register_cmd = commands.add_parser("create-sensor", help="register a sensor and print its token")
    register_cmd.add_argument("name")
    register_cmd.set_defaults(handler=create_sensor)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.handler(args)


if __name__ == "__main__":
    main()
