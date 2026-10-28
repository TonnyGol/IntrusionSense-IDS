import argparse
import getpass
import logging
import secrets
import sys
from pathlib import Path

from intrusionsense.config import DEFAULT_MODEL_DIR, ServerSettings
from intrusionsense.sensor_cli import (
    DEFAULT_RECORD_MINUTES,
    TOKEN_ENV_VAR,
    add_sensor_arguments,
    configure_logging,
    record_traffic,
    run_sensor,
)

log = logging.getLogger("intrusionsense")

SESSION_SECRET_BYTES = 32
DEFAULT_RAW_DIR = "data/raw"
DEFAULT_BENCH_FLOWS = 2000
DEFAULT_RECORDINGS_DIR = "data/recordings"
ADMIN_ROLE = "Admin"


def _session_factory(settings: ServerSettings):
    from intrusionsense.storage.db import create_db_engine, init_db, mysql_url

    return init_db(create_db_engine(mysql_url(settings)))


def serve(args) -> None:
    import uvicorn

    from intrusionsense.server.app import create_app
    from intrusionsense.server.services import build_services

    settings = ServerSettings()
    configure_logging(settings.log_level)
    session_secret = settings.session_secret
    if not session_secret:
        log.warning("SESSION_SECRET is not set: using a random one, so every restart signs everyone out")
        session_secret = secrets.token_urlsafe(SESSION_SECRET_BYTES)
    app = create_app(build_services(settings), session_secret, settings.session_cookie_secure)
    uvicorn.run(app, host=args.host or settings.web_host, port=args.port or settings.web_port)


def train_models(args) -> None:
    from intrusionsense.training import train

    configure_logging("INFO")
    details = train(Path(args.raw), Path(args.recordings) if args.recordings else None, Path(args.out))
    print(f"Models written to {args.out} ({details['rows_kept']} flows after cleaning).")


def evaluate_models(args) -> None:
    from intrusionsense.evaluation import build_report

    configure_logging("INFO")
    report = build_report(Path(args.raw), Path(args.recordings) if args.recordings else None)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(report)
    print(f"Wrote {args.out}")


def bench_latency(args) -> None:
    from intrusionsense.benchmark import measure_latency

    settings = ServerSettings()
    result = measure_latency(settings.model_dir, settings.l1_threshold, args.flows)
    print(f"{result.flows} flows, from flow closed to detection decision (network and database excluded):")
    for percentile, milliseconds in result.percentiles_ms.items():
        print(f"  p{percentile}: {milliseconds:.2f} ms")
    print(f"  mean: {result.mean_ms:.2f} ms")


def create_admin(args) -> None:
    from intrusionsense.server.security import hash_password, password_problem
    from intrusionsense.storage.models import User

    password = getpass.getpass("Password: ")
    if (problem := password_problem(password)) is not None:
        sys.exit(problem)
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")

    password_hash = hash_password(password)
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
    add_sensor_arguments(sensor_cmd)
    sensor_cmd.set_defaults(handler=run_sensor)

    record_cmd = commands.add_parser("record", help="record flow features as labelled training data")
    record_cmd.add_argument("--out", required=True, help="CSV file to append to")
    record_cmd.add_argument(
        "--label", default="Normal Traffic", help="label for every flow (default Normal Traffic)"
    )
    record_cmd.add_argument("--minutes", type=int, default=DEFAULT_RECORD_MINUTES)
    record_source = record_cmd.add_mutually_exclusive_group()
    record_source.add_argument(
        "--iface", help="interface to capture on (default: the one with the default route)"
    )
    record_source.add_argument("--pcap", help="label the flows of a capture file instead of sniffing")
    record_cmd.set_defaults(handler=record_traffic)

    train_cmd = commands.add_parser("train", help="train the models from the raw CICIDS2017 day files")
    train_cmd.add_argument(
        "--raw", default=DEFAULT_RAW_DIR, help=f"folder of CICIDS2017 CSVs (default {DEFAULT_RAW_DIR})"
    )
    train_cmd.add_argument(
        "--recordings", default=DEFAULT_RECORDINGS_DIR, help="folder of recorded normal traffic CSVs"
    )
    train_cmd.add_argument("--out", default=str(DEFAULT_MODEL_DIR), help="where to write the model files")
    train_cmd.set_defaults(handler=train_models)

    evaluate_cmd = commands.add_parser("evaluate", help="measure the models and write a results report")
    evaluate_cmd.add_argument("--raw", default=DEFAULT_RAW_DIR)
    evaluate_cmd.add_argument("--recordings", default=DEFAULT_RECORDINGS_DIR)
    evaluate_cmd.add_argument("--out", default="docs/results.md")
    evaluate_cmd.set_defaults(handler=evaluate_models)

    bench_cmd = commands.add_parser(
        "bench", help="measure how fast a closed flow becomes a detection decision"
    )
    bench_cmd.add_argument("--flows", type=int, default=DEFAULT_BENCH_FLOWS)
    bench_cmd.set_defaults(handler=bench_latency)

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
