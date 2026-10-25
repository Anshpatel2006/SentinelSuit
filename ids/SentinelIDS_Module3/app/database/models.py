from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class FlowRecord(Base):
    """Corresponds to FlowData in Slide 31 Class Diagram"""
    __tablename__ = "flow_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, default=datetime.utcnow)
    packet_count = Column(Integer, default=1)
    byte_count = Column(Integer, default=0)
    
    # Statistical / CICFlowMeter feature payload
    features = Column(JSON, nullable=True)
    
    # ML Classification
    ml_prediction = Column(String(50), default="BENIGN")
    ml_probability = Column(Float, default=0.0)
    
    # Rule engine match
    rule_matched = Column(String(255), nullable=True)
    is_anomaly = Column(Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "ml_prediction": self.ml_prediction,
            "ml_probability": self.ml_probability,
            "rule_matched": self.rule_matched,
            "is_anomaly": self.is_anomaly
        }


class AlertRecord(Base):
    """Corresponds to Alert in Slide 31 Class Diagram"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    attack_type = Column(String(100), nullable=False, index=True)  # DoS, PortScan, SQLi, BruteForce, etc.
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), nullable=False, index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String(10), default="TCP")
    risk_score = Column(Float, default=0.0)
    response_action = Column(String(50), default="LOG")  # LOG, MONITOR, SCAN, SCAN_AND_AI, BLOCK
    details = Column(Text, nullable=True)
    status = Column(String(30), default="NEW")  # NEW, INVESTIGATING, RESOLVED, DISMISSED
    
    # Automated investigations
    nmap_scan_id = Column(Integer, nullable=True)
    ai_summary = Column(Text, nullable=True)
    raw_evidence = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "attack_type": self.attack_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "risk_score": self.risk_score,
            "response_action": self.response_action,
            "details": self.details,
            "status": self.status,
            "nmap_scan_id": self.nmap_scan_id,
            "ai_summary": self.ai_summary,
            "raw_evidence": self.raw_evidence
        }


class ScanRecord(Base):
    """Bounded Nmap Scan results (Slide 10, 31, 34)"""
    __tablename__ = "nmap_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_ip = Column(String(50), nullable=False, index=True)
    command = Column(String(255), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String(30), default="COMPLETED")  # RUNNING, COMPLETED, FAILED, TIMEOUT
    open_ports = Column(JSON, default=list)
    raw_output = Column(Text, nullable=True)
    risk_assessment = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "command": self.command,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "open_ports": self.open_ports,
            "raw_output": self.raw_output,
            "risk_assessment": self.risk_assessment
        }
