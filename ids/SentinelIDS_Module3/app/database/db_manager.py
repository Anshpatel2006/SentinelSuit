from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings
from app.database.models import Base, FlowRecord, AlertRecord, ScanRecord

class DatabaseManager:
    """
    Corresponds directly to DatabaseManager in Slide 31 Class Diagram:
    - id: int
    - db_type: str
    - connection: str
    - status: str
    - save_scan()
    - save_alert()
    - get_history()
    - get_statistics()
    """
    def __init__(self, db_url: Optional[str] = None):
        self.id: int = 1
        self.connection: str = db_url or settings.DATABASE_URL
        self.db_type: str = "sqlite" if "sqlite" in self.connection else "postgresql"
        self.status: str = "INITIALIZING"
        
        # Engine configuration
        connect_args = {"check_same_thread": False} if self.db_type == "sqlite" else {}
        self.engine = create_engine(self.connection, connect_args=connect_args, pool_pre_ping=True)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Initialize tables
        self._init_db()

    def _init_db(self):
        try:
            Base.metadata.create_all(bind=self.engine)
            self.status = "CONNECTED"
        except Exception as e:
            self.status = f"ERROR: {str(e)}"

    def get_session(self) -> Session:
        return self.SessionLocal()

    def save_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save detected security alert to DB"""
        session = self.get_session()
        try:
            # Parse timestamp if string
            ts = alert_data.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = datetime.utcnow()
            elif not isinstance(ts, datetime):
                ts = datetime.utcnow()

            record = AlertRecord(
                timestamp=ts,
                severity=alert_data.get("severity", "LOW"),
                attack_type=alert_data.get("attack_type", "Unknown Anomaly"),
                src_ip=alert_data.get("src_ip", "0.0.0.0"),
                dst_ip=alert_data.get("dst_ip", "0.0.0.0"),
                src_port=alert_data.get("src_port", 0),
                dst_port=alert_data.get("dst_port", 0),
                protocol=alert_data.get("protocol", "TCP"),
                risk_score=float(alert_data.get("risk_score", 0.0)),
                response_action=alert_data.get("response_action", "LOG"),
                details=alert_data.get("details", ""),
                status=alert_data.get("status", "NEW"),
                nmap_scan_id=alert_data.get("nmap_scan_id"),
                ai_summary=alert_data.get("ai_summary"),
                raw_evidence=alert_data.get("raw_evidence")
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.to_dict()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def update_alert(self, alert_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        session = self.get_session()
        try:
            record = session.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
            if not record:
                return None
            for key, val in updates.items():
                if hasattr(record, key):
                    setattr(record, key, val)
            session.commit()
            session.refresh(record)
            return record.to_dict()
        finally:
            session.close()

    def save_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store flow record (Slide 31 FlowData / Slide 35 D2 Flow Data)"""
        session = self.get_session()
        try:
            record = FlowRecord(
                src_ip=flow_data.get("src_ip", "0.0.0.0"),
                dst_ip=flow_data.get("dst_ip", "0.0.0.0"),
                src_port=flow_data.get("src_port", 0),
                dst_port=flow_data.get("dst_port", 0),
                protocol=flow_data.get("protocol", "TCP"),
                start_time=flow_data.get("start_time", datetime.utcnow()),
                end_time=flow_data.get("end_time", datetime.utcnow()),
                packet_count=flow_data.get("packet_count", 1),
                byte_count=flow_data.get("byte_count", 0),
                features=flow_data.get("features"),
                ml_prediction=flow_data.get("ml_prediction", "BENIGN"),
                ml_probability=flow_data.get("ml_probability", 0.0),
                rule_matched=flow_data.get("rule_matched"),
                is_anomaly=flow_data.get("is_anomaly", False)
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.to_dict()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def save_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save bounded Nmap scan result to DB"""
        session = self.get_session()
        try:
            record = ScanRecord(
                target_ip=scan_data.get("target_ip", "127.0.0.1"),
                command=scan_data.get("command", ""),
                start_time=scan_data.get("start_time", datetime.utcnow()),
                end_time=scan_data.get("end_time", datetime.utcnow()),
                status=scan_data.get("status", "COMPLETED"),
                open_ports=scan_data.get("open_ports", []),
                raw_output=scan_data.get("raw_output", ""),
                risk_assessment=scan_data.get("risk_assessment", "")
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.to_dict()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_history(self, limit: int = 50, offset: int = 0, severity: Optional[str] = None, attack_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve paginated alert history"""
        session = self.get_session()
        try:
            query = session.query(AlertRecord)
            if severity:
                query = query.filter(AlertRecord.severity == severity.upper())
            if attack_type:
                query = query.filter(AlertRecord.attack_type.ilike(f"%{attack_type}%"))
            query = query.order_by(desc(AlertRecord.timestamp)).offset(offset).limit(limit)
            results = query.all()
            return [r.to_dict() for r in results]
        finally:
            session.close()

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        session = self.get_session()
        try:
            record = session.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
            return record.to_dict() if record else None
        finally:
            session.close()

    def get_statistics(self) -> Dict[str, Any]:
        """Calculates security metrics matching Slide 31, 36 (Dashboard metrics)"""
        session = self.get_session()
        try:
            total_alerts = session.query(func.count(AlertRecord.id)).scalar() or 0
            total_flows = session.query(func.count(FlowRecord.id)).scalar() or 0
            total_scans = session.query(func.count(ScanRecord.id)).scalar() or 0
            
            # Severity Breakdown
            severity_counts = dict(
                session.query(AlertRecord.severity, func.count(AlertRecord.id))
                .group_by(AlertRecord.severity)
                .all()
            )
            
            # Attack Type Breakdown
            attack_types = dict(
                session.query(AlertRecord.attack_type, func.count(AlertRecord.id))
                .group_by(AlertRecord.attack_type)
                .order_by(desc(func.count(AlertRecord.id)))
                .limit(10)
                .all()
            )
            
            # Top Attacking Source IPs
            top_sources = [
                {"ip": ip, "count": count}
                for ip, count in session.query(AlertRecord.src_ip, func.count(AlertRecord.id))
                .group_by(AlertRecord.src_ip)
                .order_by(desc(func.count(AlertRecord.id)))
                .limit(5)
                .all()
            ]

            # Recent 24h Alerts count
            yesterday = datetime.utcnow() - timedelta(days=1)
            alerts_24h = session.query(func.count(AlertRecord.id)).filter(AlertRecord.timestamp >= yesterday).scalar() or 0
            
            # Active/Unresolved alerts
            active_alerts = session.query(func.count(AlertRecord.id)).filter(AlertRecord.status.in_(["NEW", "INVESTIGATING"])).scalar() or 0

            return {
                "total_flows": total_flows,
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "alerts_last_24h": alerts_24h,
                "total_nmap_scans": total_scans,
                "severity_distribution": {
                    "LOW": severity_counts.get("LOW", 0),
                    "MEDIUM": severity_counts.get("MEDIUM", 0),
                    "HIGH": severity_counts.get("HIGH", 0),
                    "CRITICAL": severity_counts.get("CRITICAL", 0),
                },
                "attack_types": attack_types,
                "top_attackers": top_sources,
                "db_status": self.status
            }
        finally:
            session.close()

# Global database manager instance
db_manager = DatabaseManager()
