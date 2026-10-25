from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

class FlowData:
    """
    Corresponds directly to FlowData in Slide 31 Class Diagram:
    - id: int
    - src_ip: str
    - dst_ip: str
    - src_port: int
    - dst_port: int
    - protocol: str
    - start_time: datetime
    - end_time: datetime
    - packet_count: int
    - byte_count: int
    """
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        flow_id: int = 1
    ):
        self.id: int = flow_id
        self.src_ip: str = src_ip
        self.dst_ip: str = dst_ip
        self.src_port: int = src_port
        self.dst_port: int = dst_port
        self.protocol: str = protocol
        self.start_time: datetime = datetime.utcnow()
        self.end_time: datetime = self.start_time
        self.packet_count: int = 0
        self.byte_count: int = 0
        
        # Directional packet tracking
        self.fwd_packets: List[Dict[str, Any]] = []
        self.bwd_packets: List[Dict[str, Any]] = []
        
        # Raw payload aggregation (for rule inspection / DPI)
        self.payloads: List[bytes] = []

    @property
    def key(self) -> Tuple[str, str, int, int, str]:
        """Bidirectional 5-tuple key"""
        ip1, ip2 = sorted([self.src_ip, self.dst_ip])
        p1, p2 = sorted([self.src_port, self.dst_port])
        return (ip1, ip2, p1, p2, self.protocol)

    def add_packet(self, pkt_meta: Dict[str, Any], direction: str = "fwd"):
        self.packet_count += 1
        length = pkt_meta.get("length", 0)
        self.byte_count += length
        self.end_time = pkt_meta.get("timestamp", datetime.utcnow())
        
        if direction == "fwd":
            self.fwd_packets.append(pkt_meta)
        else:
            self.bwd_packets.append(pkt_meta)
            
        payload = pkt_meta.get("payload")
        if payload:
            self.payloads.append(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count
        }


class FlowFeatureExtractor:
    """
    Corresponds directly to FlowFeatureExtractor in Slide 31 Class Diagram:
    - id: int
    - flow_timeout: int
    - packet_count: int
    - features: list
    - extract_features(flow)
    - generate_features(packets)
    - normalize_features(raw_features)
    - create_flow(packet)
    
    Extracts CICFlowMeter-aligned flow features (Slides 10, 29, 32).
    """
    FEATURE_NAMES = [
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "total_length_of_fwd_packets",
        "total_length_of_bwd_packets",
        "fwd_packet_length_max",
        "fwd_packet_length_min",
        "fwd_packet_length_mean",
        "fwd_packet_length_std",
        "bwd_packet_length_max",
        "bwd_packet_length_min",
        "bwd_packet_length_mean",
        "bwd_packet_length_std",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "flow_iat_mean",
        "flow_iat_std",
        "flow_iat_max",
        "flow_iat_min",
        "fwd_iat_mean",
        "bwd_iat_mean",
        "syn_flag_count",
        "fin_flag_count",
        "rst_flag_count",
        "psh_flag_count",
        "ack_flag_count",
        "urg_flag_count",
        "down_up_ratio",
        "average_packet_size"
    ]

    def __init__(self, flow_timeout: int = 15):
        self.id: int = 1
        self.flow_timeout: int = flow_timeout
        self.packet_count: int = 0
        self.features: List[str] = self.FEATURE_NAMES
        self.active_flows: Dict[Tuple, FlowData] = {}
        self.flow_counter: int = 0

    def create_flow(self, packet_meta: Dict[str, Any]) -> FlowData:
        """Create a new FlowData instance from initial packet metadata"""
        self.flow_counter += 1
        flow = FlowData(
            src_ip=packet_meta.get("src_ip", "0.0.0.0"),
            dst_ip=packet_meta.get("dst_ip", "0.0.0.0"),
            src_port=packet_meta.get("src_port", 0),
            dst_port=packet_meta.get("dst_port", 0),
            protocol=packet_meta.get("protocol", "TCP"),
            flow_id=self.flow_counter
        )
        flow.add_packet(packet_meta, direction="fwd")
        return flow

    def process_packet(self, pkt_meta: Dict[str, Any]) -> Tuple[FlowData, bool]:
        """
        Adds packet to existing flow or creates a new one.
        Returns (flow, is_timed_out)
        """
        self.packet_count += 1
        src_ip = pkt_meta.get("src_ip", "")
        dst_ip = pkt_meta.get("dst_ip", "")
        src_port = pkt_meta.get("src_port", 0)
        dst_port = pkt_meta.get("dst_port", 0)
        proto = pkt_meta.get("protocol", "TCP")
        
        # Check bidirectional key
        key1 = (src_ip, dst_ip, src_port, dst_port, proto)
        key2 = (dst_ip, src_ip, dst_port, src_port, proto)
        
        now = pkt_meta.get("timestamp", datetime.utcnow())
        
        if key1 in self.active_flows:
            flow = self.active_flows[key1]
            # Check timeout
            duration = (now - flow.end_time).total_seconds()
            if duration > self.flow_timeout:
                # Expired flow, pop and create new
                old_flow = self.active_flows.pop(key1)
                new_flow = self.create_flow(pkt_meta)
                self.active_flows[key1] = new_flow
                return old_flow, True
            flow.add_packet(pkt_meta, direction="fwd")
            return flow, False
            
        elif key2 in self.active_flows:
            flow = self.active_flows[key2]
            duration = (now - flow.end_time).total_seconds()
            if duration > self.flow_timeout:
                old_flow = self.active_flows.pop(key2)
                new_flow = self.create_flow(pkt_meta)
                self.active_flows[key1] = new_flow
                return old_flow, True
            flow.add_packet(pkt_meta, direction="bwd")
            return flow, False
            
        else:
            flow = self.create_flow(pkt_meta)
            self.active_flows[key1] = flow
            return flow, False

    def extract_features(self, flow: FlowData) -> Dict[str, float]:
        """
        Extract statistical features matching CICFlowMeter / CICIDS dataset
        """
        all_packets = flow.fwd_packets + flow.bwd_packets
        if not all_packets:
            return {f: 0.0 for f in self.features}
            
        # Timestamps and Duration
        timestamps = sorted([p.get("timestamp", flow.start_time) for p in all_packets])
        duration_sec = max((timestamps[-1] - timestamps[0]).total_seconds(), 0.0001)
        
        # Packet lengths
        fwd_lens = [p.get("length", 0) for p in flow.fwd_packets] or [0]
        bwd_lens = [p.get("length", 0) for p in flow.bwd_packets] or [0]
        all_lens = fwd_lens + bwd_lens
        
        # Flags
        syn_count = sum(1 for p in all_packets if p.get("syn", False))
        fin_count = sum(1 for p in all_packets if p.get("fin", False))
        rst_count = sum(1 for p in all_packets if p.get("rst", False))
        psh_count = sum(1 for p in all_packets if p.get("psh", False))
        ack_count = sum(1 for p in all_packets if p.get("ack", False))
        urg_count = sum(1 for p in all_packets if p.get("urg", False))
        
        # Inter-arrival times (IAT)
        if len(timestamps) > 1:
            iats = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
        else:
            iats = [0.0]
            
        fwd_ts = sorted([p.get("timestamp", flow.start_time) for p in flow.fwd_packets])
        fwd_iats = [(fwd_ts[i] - fwd_ts[i-1]).total_seconds() for i in range(1, len(fwd_ts))] if len(fwd_ts) > 1 else [0.0]
        
        bwd_ts = sorted([p.get("timestamp", flow.start_time) for p in flow.bwd_packets])
        bwd_iats = [(bwd_ts[i] - bwd_ts[i-1]).total_seconds() for i in range(1, len(bwd_ts))] if len(bwd_ts) > 1 else [0.0]

        total_fwd_pkts = len(flow.fwd_packets)
        total_bwd_pkts = len(flow.bwd_packets)
        total_fwd_bytes = sum(fwd_lens)
        total_bwd_bytes = sum(bwd_lens)
        
        features_dict = {
            "flow_duration": float(duration_sec),
            "total_fwd_packets": float(total_fwd_pkts),
            "total_bwd_packets": float(total_bwd_pkts),
            "total_length_of_fwd_packets": float(total_fwd_bytes),
            "total_length_of_bwd_packets": float(total_bwd_bytes),
            "fwd_packet_length_max": float(np.max(fwd_lens)),
            "fwd_packet_length_min": float(np.min(fwd_lens)),
            "fwd_packet_length_mean": float(np.mean(fwd_lens)),
            "fwd_packet_length_std": float(np.std(fwd_lens)),
            "bwd_packet_length_max": float(np.max(bwd_lens)),
            "bwd_packet_length_min": float(np.min(bwd_lens)),
            "bwd_packet_length_mean": float(np.mean(bwd_lens)),
            "bwd_packet_length_std": float(np.std(bwd_lens)),
            "flow_bytes_per_sec": float((total_fwd_bytes + total_bwd_bytes) / duration_sec),
            "flow_packets_per_sec": float(len(all_packets) / duration_sec),
            "flow_iat_mean": float(np.mean(iats)),
            "flow_iat_std": float(np.std(iats)),
            "flow_iat_max": float(np.max(iats)),
            "flow_iat_min": float(np.min(iats)),
            "fwd_iat_mean": float(np.mean(fwd_iats)),
            "bwd_iat_mean": float(np.mean(bwd_iats)),
            "syn_flag_count": float(syn_count),
            "fin_flag_count": float(fin_count),
            "rst_flag_count": float(rst_count),
            "psh_flag_count": float(psh_count),
            "ack_flag_count": float(ack_count),
            "urg_flag_count": float(urg_count),
            "down_up_ratio": float(total_bwd_pkts / max(total_fwd_pkts, 1)),
            "average_packet_size": float(np.mean(all_lens))
        }
        return features_dict

    def generate_features(self, packets: List[Dict[str, Any]]) -> Dict[str, float]:
        """Aggregate batch of raw packets into features directly"""
        if not packets:
            return {f: 0.0 for f in self.features}
        temp_flow = self.create_flow(packets[0])
        for p in packets[1:]:
            temp_flow.add_packet(p)
        return self.extract_features(temp_flow)

    def normalize_features(self, raw_features: Dict[str, float]) -> List[float]:
        """Convert feature dictionary to an ordered feature vector"""
        return [float(raw_features.get(f, 0.0)) for f in self.FEATURE_NAMES]

    def flush_expired_flows(self) -> List[FlowData]:
        """Returns flows that have exceeded flow_timeout"""
        now = datetime.utcnow()
        expired = []
        keys_to_del = []
        for key, flow in self.active_flows.items():
            if (now - flow.end_time).total_seconds() > self.flow_timeout:
                expired.append(flow)
                keys_to_del.append(key)
        for k in keys_to_del:
            del self.active_flows[k]
        return expired
