"""Tables. Timestamps are naive UTC (MySQL DATETIME has no time zone); the UI converts to local time."""

from datetime import UTC, datetime

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

# SQLite (used by the tests) only auto-increments a column declared exactly INTEGER PRIMARY KEY
BigIntegerId = BigInteger().with_variant(Integer, "sqlite")


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def utc_from_timestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    UserID = Column(Integer, primary_key=True, autoincrement=True)
    Username = Column(String(50), nullable=False, unique=True)
    Email = Column(String(120), nullable=True)
    PasswordHash = Column(String(255), nullable=False)
    Role = Column(String(50), default="Analyst")
    CreatedAt = Column(DateTime, default=utc_now)

    # Relationships
    rules_created = relationship("Rule", back_populates="creator")
    alerts_assigned = relationship("Alert", back_populates="assignee")


class Rule(Base):
    __tablename__ = "rules"

    RuleID = Column(Integer, primary_key=True, autoincrement=True)
    RuleName = Column(String(100), nullable=False)
    Description = Column(Text, nullable=True)
    ConditionText = Column(Text, nullable=False)
    Severity = Column(String(50), nullable=False)  # holds the rule action, e.g. "Alert High"
    CreatedBy = Column(Integer, ForeignKey("users.UserID", ondelete="SET NULL"), nullable=True)
    IsActive = Column(Boolean, default=True)

    # Relationships
    creator = relationship("User", back_populates="rules_created")
    alerts = relationship("Alert", back_populates="triggered_rule")


class Sensor(Base):
    __tablename__ = "sensors"

    SensorID = Column(Integer, primary_key=True, autoincrement=True)
    Name = Column(String(100), nullable=False, unique=True)
    TokenHash = Column(String(64), nullable=False, unique=True)
    IsActive = Column(Boolean, default=True, nullable=False)
    CreatedAt = Column(DateTime, default=utc_now)
    LastSeenAt = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="sensor")


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    LogID = Column(BigIntegerId, primary_key=True, autoincrement=True)
    SourceIP = Column(String(45), nullable=False)
    DestIP = Column(String(45), nullable=False)
    Protocol = Column(String(20), nullable=True)
    SrcPort = Column(Integer, nullable=True)
    DstPort = Column(Integer, nullable=True)
    PacketCount = Column(Integer, nullable=True)
    PacketSize = Column(Integer, nullable=True)  # mean payload bytes per packet
    CapturedAt = Column(DateTime, default=utc_now)

    # Relationships
    alerts = relationship("Alert", back_populates="associated_log", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    AlertID = Column(BigIntegerId, primary_key=True, autoincrement=True)
    AssociatedLogID = Column(BigInteger, ForeignKey("traffic_logs.LogID", ondelete="CASCADE"), nullable=False)
    TriggeredRuleID = Column(Integer, ForeignKey("rules.RuleID", ondelete="SET NULL"), nullable=True)
    SensorID = Column(Integer, ForeignKey("sensors.SensorID", ondelete="SET NULL"), nullable=True)
    Status = Column(String(50), default="active")
    Timestamp = Column(DateTime, default=utc_now)
    LastSeenAt = Column(DateTime, default=utc_now)
    RepeatCount = Column(Integer, default=1, nullable=False)
    AssignedID = Column(Integer, ForeignKey("users.UserID", ondelete="SET NULL"), nullable=True)

    AttackType = Column(String(100), nullable=False)
    Severity = Column(String(50), nullable=False)
    Detection = Column(String(20), nullable=False)  # rule, model or engine_error
    Confidence = Column(Float, nullable=True)  # model probability; NULL for rule matches
    Layer = Column(Integer, nullable=True)
    Error = Column(Text, nullable=True)
    PayloadSamples = Column(Text, nullable=True)  # JSON list of base64 strings

    # Relationships
    associated_log = relationship("TrafficLog", back_populates="alerts")
    triggered_rule = relationship("Rule", back_populates="alerts")
    assignee = relationship("User", back_populates="alerts_assigned")
    sensor = relationship("Sensor", back_populates="alerts")


class AuditLog(Base):
    """Who did what: logins, rule and user changes, alert triage."""

    __tablename__ = "audit_log"

    AuditID = Column(BigIntegerId, primary_key=True, autoincrement=True)
    At = Column(DateTime, default=utc_now, nullable=False)
    Username = Column(String(50), nullable=True)  # kept as text so the entry survives user deletion
    Action = Column(String(60), nullable=False)
    Detail = Column(Text, nullable=True)
    ClientIP = Column(String(45), nullable=True)
