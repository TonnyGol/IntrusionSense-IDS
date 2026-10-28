from enum import StrEnum

# Layer 2 class ids, as encoded at training time
ATTACK_LABELS = {
    0: "Bots",
    1: "Brute Force",
    2: "DDoS",
    3: "DoS",
    4: "Port Scanning",
    5: "Web Attacks",
}

ENGINE_ERROR_LABEL = "Engine Error"


class Severity(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


SEVERITY_BY_LABEL = {
    "DDoS": Severity.HIGH,
    "DoS": Severity.HIGH,
    "Bots": Severity.HIGH,
    "Brute Force": Severity.MEDIUM,
    "Port Scanning": Severity.MEDIUM,
    "Web Attacks": Severity.LOW,
}
DEFAULT_SEVERITY = Severity.MEDIUM


def severity_for_label(label: str) -> Severity:
    return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)
