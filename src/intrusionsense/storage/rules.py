import logging

from sqlalchemy.orm import Session

from intrusionsense.rules import RuleAction, RuleEngine, RuleField, parse_rule
from intrusionsense.storage.models import Rule

log = logging.getLogger(__name__)

WEB_ATTACK_PATTERN = r"(?i)(union\s+(all\s+)?select|<script\b|\.\./\.\./|'\s*or\s*'1'\s*=\s*'1)"

# Behaviour rules installed on first start, so scans and floods are caught even where the ML misses
# them. Thresholds are deliberately high: a browser alone opens dozens of connections per page.
DEFAULT_RULES = [
    (
        "Port scan",
        "One source probed many ports on one host within 10 seconds.",
        f"{RuleField.UNIQUE_PORTS_PER_10S.value} 15",
        RuleAction.ALERT_MEDIUM,
    ),
    (
        "Connection flood",
        "One source opened an unusually high number of connections in a minute (brute force or SYN flood).",
        f"{RuleField.CONNECTIONS_PER_MINUTE.value} 150",
        RuleAction.ALERT_HIGH,
    ),
    (
        "Web attack signature",
        "Request payload contains a common SQL injection, XSS or path traversal pattern.",
        f"{RuleField.PAYLOAD_REGEX.value} {WEB_ATTACK_PATTERN}",
        RuleAction.ALERT_MEDIUM,
    ),
    (
        "Service flood",
        "A single service port received an unusually high number of flows within 10 seconds (DoS).",
        f"{RuleField.PACKETS_TO_DEST_PORT_PER_10S.value} 300",
        RuleAction.ALERT_HIGH,
    ),
]


def seed_default_rules(session: Session) -> None:
    """Install DEFAULT_RULES into an empty rules table. Existing installs keep their own rules."""
    if session.query(Rule).first() is not None:
        return
    for name, description, condition, action in DEFAULT_RULES:
        session.add(
            Rule(RuleName=name, Description=description, ConditionText=condition, Severity=action.value)
        )
    session.commit()
    log.info("Installed %d default detection rules", len(DEFAULT_RULES))


def load_rule_engine(session: Session) -> RuleEngine:
    rows = session.query(Rule).filter_by(IsActive=True).all()
    parsed = (parse_rule(row.RuleID, row.RuleName, row.ConditionText, row.Severity) for row in rows)
    return RuleEngine([rule for rule in parsed if rule is not None])
