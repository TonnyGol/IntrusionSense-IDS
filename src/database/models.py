from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime

# Import Base from connection
from database.connection import Base

class User(Base):
    __tablename__ = 'users'

    UserID = Column(Integer, primary_key=True, autoincrement=True)
    Username = Column(String(50), nullable=False, unique=True)
    Email = Column(String(120), nullable=True)
    PasswordHash = Column(String(255), nullable=False)
    Role = Column(String(50), default='Analyst')
    CreatedAt = Column(DateTime, default=datetime.now)

    # Relationships
    rules_created = relationship("Rule", back_populates="creator")
    alerts_assigned = relationship("Alert", back_populates="assignee")

class Rule(Base):
    __tablename__ = 'rules'

    RuleID = Column(Integer, primary_key=True, autoincrement=True)
    RuleName = Column(String(100), nullable=False)
    Description = Column(Text, nullable=True)
    ConditionText = Column(Text, nullable=False)
    Severity = Column(String(50), nullable=False)
    CreatedBy = Column(Integer, ForeignKey('users.UserID', ondelete="SET NULL"), nullable=True)
    IsActive = Column(Boolean, default=True)

    # Relationships
    creator = relationship("User", back_populates="rules_created")
    alerts = relationship("Alert", back_populates="triggered_rule")

class TrafficLog(Base):
    __tablename__ = 'traffic_logs'

    LogID = Column(BigInteger, primary_key=True, autoincrement=True)
    SourceIP = Column(String(45), nullable=False)
    DestIP = Column(String(45), nullable=False)
    Protocol = Column(String(20), nullable=True)
    DstPort = Column(Integer, nullable=True)
    PacketSize = Column(Integer, nullable=True)
    CapturedAt = Column(DateTime, default=datetime.now)

    # Relationships
    alerts = relationship("Alert", back_populates="associated_log", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = 'alerts'

    AlertID = Column(BigInteger, primary_key=True, autoincrement=True)
    AssociatedLogID = Column(BigInteger, ForeignKey('traffic_logs.LogID', ondelete="CASCADE"), nullable=False)
    TriggeredRuleID = Column(Integer, ForeignKey('rules.RuleID', ondelete="SET NULL"), nullable=True)
    Status = Column(String(50), default='active')
    Timestamp = Column(DateTime, default=datetime.now)
    AssignedID = Column(Integer, ForeignKey('users.UserID', ondelete="SET NULL"), nullable=True)
    
    # Extra fields imported from historical_logs functionality
    AttackType = Column(String(100), nullable=False)
    Severity = Column(String(50), nullable=False)
    Confidence = Column(String(50), nullable=False)

    # Relationships
    associated_log = relationship("TrafficLog", back_populates="alerts")
    triggered_rule = relationship("Rule", back_populates="alerts")
    assignee = relationship("User", back_populates="alerts_assigned")
