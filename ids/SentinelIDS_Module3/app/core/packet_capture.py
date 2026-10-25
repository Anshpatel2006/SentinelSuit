import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

try:
    from scapy.all import sniff, rdpcap, wrpcap, IP, IPv6, TCP, UDP, ICMP, Raw, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

from app.config import settings
from app.core.flow_extractor import FlowFeatureExtractor, FlowData
from app.core.detection_engine import DetectionEngine
from app.core.alert_manager import alert_manager
from app.database.db_manager import db_manager

logger = logging.getLogger("SentinelIDS.PacketCapture")

class PacketCapture:
    """
    Corresponds directly to PacketCapture in Slide 31 Class Diagram:
    - id: int
    - interface: str
    - filter: str
    - status: str
    - start_capture(interface, filter_str, duration)
    - stop_capture()
    - apply_filter(filter_str)
    - get_packets()
    
    Supports live Scapy capturing and offline PCAP uploads (Slides 29, 32, 35).
    """
    def __init__(
        self,
        detection_engine: Optional[DetectionEngine] = None,
        feature_extractor: Optional[FlowFeatureExtractor] = None
    ):
        self.id: int = 1
        self.interface: str = settings.DEFAULT_INTERFACE
        self.filter: str = ""
        self.status: str = "IDLE"  # IDLE, RUNNING, STOPPED, ERROR
        
        self.detection_engine = detection_engine or DetectionEngine()
        self.feature_extractor = feature_extractor or FlowFeatureExtractor(
            flow_timeout=settings.FLOW_TIMEOUT_SECONDS
        )
        
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.captured_packets_count: int = 0
        self.analyzed_flows_count: int = 0
        self.recent_packets: List[Dict[str, Any]] = []
        self._raw_packets_buffer = []
        self.current_capture_file: Optional[Path] = None

    def get_interfaces(self) -> List[str]:
        """Returns list of available network interfaces"""
        if SCAPY_AVAILABLE:
            try:
                return get_if_list()
            except Exception:
                return ["Default Network Interface"]
        return ["Loopback", "Ethernet", "Wi-Fi"]

    def apply_filter(self, filter_str: str):
        """Sets BPF packet filter (e.g., 'tcp', 'port 80', 'ip')"""
        self.filter = filter_str.strip()

    def start_capture(self, interface: str = "", filter_str: str = "", duration: Optional[int] = None) -> Dict[str, Any]:
        """
        Launches asynchronous packet capture worker thread.
        """
        if self.status == "RUNNING":
            return {"status": "ALREADY_RUNNING", "message": "Capture session is already in progress"}

        self.interface = interface or self.interface
        self.filter = filter_str.strip()

        self._stop_event.clear()
        self.captured_packets_count = 0
        self.analyzed_flows_count = 0
        self.recent_packets.clear()
        self._raw_packets_buffer.clear()
        
        # Prepare capture file
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.current_capture_file = settings.CAPTURES_DIR / f"capture_{timestamp_str}.pcap"

        self._thread = threading.Thread(
            target=self._capture_worker,
            args=(duration,),
            daemon=True
        )
        self.status = "RUNNING"
        self._thread.start()

        return {
            "status": "STARTED",
            "interface": self.interface or "ALL",
            "filter": self.filter,
            "duration": duration,
            "pcap_file": str(self.current_capture_file)
        }

    def stop_capture(self) -> Dict[str, Any]:
        """Stops live capture session and flushes pending flows"""
        if self.status != "RUNNING":
            return {"status": "NOT_RUNNING", "message": "Capture is not currently active"}

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        # Flush remaining flows
        self._flush_active_flows()

        # Save PCAP if packets were collected
        if self._raw_packets_buffer and SCAPY_AVAILABLE and self.current_capture_file:
            try:
                wrpcap(str(self.current_capture_file), self._raw_packets_buffer)
            except Exception as e:
                logger.error(f"Error saving PCAP file: {e}")

        self.status = "STOPPED"
        return {
            "status": "STOPPED",
            "total_packets": self.captured_packets_count,
            "total_flows": self.analyzed_flows_count,
            "pcap_file": str(self.current_capture_file) if self._raw_packets_buffer else None
        }

    def _capture_worker(self, duration: Optional[int]):
        start_time = time.time()
        
        def packet_handler(pkt):
            if self._stop_event.is_set():
                return
            self._process_single_packet(pkt)

        try:
            if not SCAPY_AVAILABLE:
                self.status = "ERROR: Scapy is not available"
                return

            kwargs = {
                "prn": packet_handler,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "store": False
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.filter:
                kwargs["filter"] = self.filter

            # Run sniff in chunks to monitor stop_event and timeouts
            while not self._stop_event.is_set():
                sniff(timeout=1.0, **kwargs)
                
                # Check expired flows periodically
                self._check_expired_flows()
                
                if duration and (time.time() - start_time) >= duration:
                    break

        except Exception as e:
            logger.error(f"Capture worker encountered exception: {e}")
            self.status = f"ERROR: {str(e)}"
        finally:
            if not self.status.startswith("ERROR"):
                self.status = "STOPPED"

    def _process_single_packet(self, pkt):
        """Extracts packet metadata and feeds to flow engine"""
        self.captured_packets_count += 1
        
        if len(self._raw_packets_buffer) < 10000:
            self._raw_packets_buffer.append(pkt)

        # Parse Scapy Packet
        meta = self._parse_scapy_packet(pkt)
        if not meta:
            return

        if len(self.recent_packets) >= 100:
            self.recent_packets.pop(0)
        self.recent_packets.append(meta)

        # Feed to flow feature extractor
        completed_flow, timed_out = self.feature_extractor.process_packet(meta)
        if timed_out and completed_flow:
            self._analyze_and_record_flow(completed_flow)

    def _parse_scapy_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """Parses IP/TCP/UDP/ICMP layers into clean metadata dictionary"""
        try:
            meta = {
                "timestamp": datetime.fromtimestamp(float(pkt.time)) if hasattr(pkt, "time") else datetime.utcnow(),
                "length": len(pkt),
                "src_ip": "0.0.0.0",
                "dst_ip": "0.0.0.0",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "OTHER",
                "syn": False, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False,
                "flags_val": 0,
                "payload": b""
            }

            if pkt.haslayer(IP):
                meta["src_ip"] = pkt[IP].src
                meta["dst_ip"] = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                meta["src_ip"] = pkt[IPv6].src
                meta["dst_ip"] = pkt[IPv6].dst
            else:
                return None

            if pkt.haslayer(TCP):
                meta["protocol"] = "TCP"
                meta["src_port"] = pkt[TCP].sport
                meta["dst_port"] = pkt[TCP].dport
                flags = pkt[TCP].flags
                meta["syn"] = bool(flags & 0x02)
                meta["ack"] = bool(flags & 0x10)
                meta["fin"] = bool(flags & 0x01)
                meta["rst"] = bool(flags & 0x04)
                meta["psh"] = bool(flags & 0x08)
                meta["urg"] = bool(flags & 0x20)
                meta["flags_val"] = int(flags)
            elif pkt.haslayer(UDP):
                meta["protocol"] = "UDP"
                meta["src_port"] = pkt[UDP].sport
                meta["dst_port"] = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                meta["protocol"] = "ICMP"

            if pkt.haslayer(Raw):
                meta["payload"] = bytes(pkt[Raw].load)

            return meta
        except Exception:
            return None

    def _analyze_and_record_flow(self, flow: FlowData):
        """Passes flow to detection engine and records in DB"""
        self.analyzed_flows_count += 1
        
        result = self.detection_engine.analyze_flow(flow)
        alert_dict = result.get("alert")
        ml_res = result.get("ml_result", {})
        rule_res = result.get("rule_match")

        # Save flow in DB
        db_manager.save_flow({
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "start_time": flow.start_time,
            "end_time": flow.end_time,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "features": result.get("features"),
            "ml_prediction": ml_res.get("prediction", "BENIGN"),
            "ml_probability": ml_res.get("anomaly_score", 0.0),
            "rule_matched": rule_res.get("msg") if rule_res else None,
            "is_anomaly": result["classification"]["is_threat"]
        })

        # If attack detected, trigger alert pipeline
        if alert_dict:
            alert_manager.send_alert(alert_dict)

    def _check_expired_flows(self):
        expired = self.feature_extractor.flush_expired_flows()
        for flow in expired:
            self._analyze_and_record_flow(flow)

    def _flush_active_flows(self):
        for flow in list(self.feature_extractor.active_flows.values()):
            self._analyze_and_record_flow(flow)
        self.feature_extractor.active_flows.clear()

    def process_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Processes an uploaded PCAP file offline (Slides 29, 32, 35).
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required to read PCAP files.")

        packets = rdpcap(pcap_path)
        pcap_extractor = FlowFeatureExtractor(flow_timeout=5)
        detected_threats = []
        flow_records = []

        for pkt in packets:
            meta = self._parse_scapy_packet(pkt)
            if not meta:
                continue
            flow, timed_out = pcap_extractor.process_packet(meta)
            if timed_out and flow:
                res = self.detection_engine.analyze_flow(flow)
                flow_records.append(res)
                if res.get("alert"):
                    saved = alert_manager.send_alert(res["alert"])
                    detected_threats.append(saved)

        # Flush trailing flows
        for flow in pcap_extractor.active_flows.values():
            res = self.detection_engine.analyze_flow(flow)
            flow_records.append(res)
            if res.get("alert"):
                saved = alert_manager.send_alert(res["alert"])
                detected_threats.append(saved)

        return {
            "total_packets": len(packets),
            "total_flows": len(flow_records),
            "threats_detected": len(detected_threats),
            "threat_details": detected_threats
        }

    def get_packets(self) -> List[Dict[str, Any]]:
        """Returns recent parsed packets metadata formatted safely for JSON serialization"""
        safe_packets = []
        for p in self.recent_packets:
            p_copy = dict(p)
            ts = p_copy.get("timestamp")
            if hasattr(ts, "isoformat"):
                p_copy["timestamp"] = ts.isoformat()
            payload = p_copy.get("payload")
            if isinstance(payload, bytes):
                p_copy["payload"] = payload.decode("utf-8", errors="replace")[:100]
            safe_packets.append(p_copy)
        return safe_packets

# Global packet capture service instance
packet_capture_service = PacketCapture()
