import secrets
import time
from collections import defaultdict, deque
from enum import StrEnum

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256  # argon2 cost grows with input size; bound it at the trust boundary
MAX_LOGIN_FAILURES = 5
LOGIN_FAILURE_WINDOW_SECONDS = 300.0
MAX_TRACKED_LOGIN_KEYS = 10_000
REQUIRED_CLIENT_HEADER = "x-requested-with"
REQUIRED_CLIENT_HEADER_VALUE = "IntrusionSense"

_hasher = PasswordHasher()
# verified against when the username does not exist, so a missing user costs the same time as a wrong password
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


class Role(StrEnum):
    ADMIN = "Admin"
    MANAGER = "Manager"
    ANALYST = "SOC Analyst"


class Permission(StrEnum):
    TRIAGE_ALERTS = "triage_alerts"
    MANAGE_RULES = "manage_rules"
    VIEW_AUDIT = "view_audit"
    MANAGE_SENSORS = "manage_sensors"
    MANAGE_USERS = "manage_users"


PERMISSIONS_BY_ROLE = {
    Role.ANALYST: {Permission.TRIAGE_ALERTS},
    Role.MANAGER: {Permission.TRIAGE_ALERTS, Permission.MANAGE_RULES, Permission.VIEW_AUDIT},
    Role.ADMIN: set(Permission),
}


def permissions_for(role: str) -> set[Permission]:
    try:
        return PERMISSIONS_BY_ROLE[Role(role)]
    except ValueError:
        return set()  # an unknown role in the DB gets nothing


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    return None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """False for a wrong password, an unknown user (stored_hash None) or a legacy non-argon2 hash."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


class LoginThrottle:
    """Blocks a client+username after repeated failures. In memory: it resets when the server restarts."""

    def __init__(self, max_failures: int = MAX_LOGIN_FAILURES, window: float = LOGIN_FAILURE_WINDOW_SECONDS):
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def is_blocked(self, client_ip: str, username: str) -> bool:
        return len(self._recent(client_ip, username)) >= self.max_failures

    def record_failure(self, client_ip: str, username: str) -> None:
        if len(self._failures) >= MAX_TRACKED_LOGIN_KEYS:
            self._failures = defaultdict(
                deque,
                {k: v for k, v in self._failures.items() if v and v[-1] > time.monotonic() - self.window},
            )
        self._recent(client_ip, username).append(time.monotonic())

    def reset(self, client_ip: str, username: str) -> None:
        self._failures.pop((client_ip, username.lower()), None)

    def _recent(self, client_ip: str, username: str) -> deque[float]:
        failures = self._failures[(client_ip, username.lower())]
        while failures and failures[0] < time.monotonic() - self.window:
            failures.popleft()
        return failures
