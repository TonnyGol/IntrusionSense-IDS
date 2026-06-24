from database.connection import session
from database.models import User, Rule, TrafficLog, Alert

def get_all_alerts_with_details():
    """
    Example: How to get all alerts with their associated traffic log and triggered rule.
    """
    alerts = session.query(Alert).join(TrafficLog).outerjoin(Rule).all()
    for alert in alerts:
        log = alert.associated_log
        rule_name = alert.triggered_rule.RuleName if alert.triggered_rule else "ML Anomaly"
        print(f"Alert ID: {alert.AlertID} | Type: {alert.AttackType} | Severity: {alert.Severity}")
        print(f"  Source IP: {log.SourceIP} | Dest IP: {log.DestIP}")
        print(f"  Triggered By: {rule_name}")
    return alerts

def get_active_rules():
    """
    Example: Fetch all active detection rules.
    """
    return session.query(Rule).filter(Rule.IsActive == True).all()

def add_new_user(username, email, password_hash, role="Analyst"):
    """
    Example: How to add a new user.
    """
    new_user = User(Username=username, Email=email, PasswordHash=password_hash, Role=role)
    session.add(new_user)
    session.commit()
    return new_user

def log_traffic_and_alert(src_ip, dst_ip, attack_type, severity, confidence, rule_id=None):
    """
    Example: How to log a new packet and create an alert for it.
    """
    # 1. Create the traffic log
    new_log = TrafficLog(SourceIP=src_ip, DestIP=dst_ip)
    session.add(new_log)
    session.flush() 

    # 2. Create the associated alert
    new_alert = Alert(
        AssociatedLogID=new_log.LogID,
        TriggeredRuleID=rule_id,
        AttackType=attack_type,
        Severity=severity,
        Confidence=confidence
    )
    session.add(new_alert)
    session.commit()
    return new_alert

if __name__ == "__main__":
    # This file contains example queries. Call functions to test them.
    pass