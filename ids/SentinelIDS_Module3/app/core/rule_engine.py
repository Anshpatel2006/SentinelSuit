import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.config import settings
from app.core.flow_extractor import FlowData

class SnortRule:
    """Represents a parsed Snort signature rule"""
    def __init__(
        self,
        sid: int,
        action: str,
        protocol: str,
        src_ip: str,
        src_port: str,
        dst_ip: str,
        dst_port: str,
        msg: str,
        priority: int = 2,
        classtype: str = "bad-unknown",
        content: Optional[str] = None,
        nocase: bool = False,
        flags: Optional[str] = None,
        raw_rule: str = ""
    ):
        self.sid = sid
        self.action = action
        self.protocol = protocol.lower()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.msg = msg
        self.priority = priority
        self.classtype = classtype
        self.content = content
        self.nocase = nocase
        self.flags = flags
        self.raw_rule = raw_rule

    def match_flow(self, flow: FlowData) -> Optional[Dict[str, Any]]:
        # Protocol Check
        if self.protocol != "any" and self.protocol != flow.protocol.lower():
            return None

        # Port Check
        if self.dst_port != "any":
            allowed_ports = [int(p.strip()) for p in self.dst_port.split(",") if p.strip().isdigit()]
            if allowed_ports and (flow.dst_port not in allowed_ports and flow.src_port not in allowed_ports):
                return None

        # Flag Checks (for scanning probes like NULL, Xmas, FIN)
        if self.flags:
            all_packets = flow.fwd_packets + flow.bwd_packets
            if self.flags == "0":  # NULL scan: No flags
                has_null = any(p.get("flags_val", -1) == 0 for p in all_packets)
                if not has_null:
                    return None
            elif self.flags == "FPU":  # Xmas scan: FIN, PSH, URG set
                has_xmas = any(p.get("fin") and p.get("psh") and p.get("urg") for p in all_packets)
                if not has_xmas:
                    return None
            elif self.flags == "F":  # FIN scan: only FIN set
                has_fin = any(p.get("fin") and not p.get("syn") and not p.get("ack") for p in all_packets)
                if not has_fin:
                    return None
            elif self.flags == "S":  # Pure SYN without ACK (Port sweep)
                has_syn_only = any(p.get("syn") and not p.get("ack") for p in all_packets)
                if not has_syn_only:
                    return None

        # Content Matching (DPI on accumulated payloads)
        if self.content:
            search_target = self.content.encode('utf-8')
            found = False
            for payload in flow.payloads:
                if not payload:
                    continue
                if self.nocase:
                    if search_target.lower() in payload.lower():
                        found = True
                        break
                else:
                    if search_target in payload:
                        found = True
                        break
            if not found:
                return None

        # Match succeeded!
        return {
            "sid": self.sid,
            "msg": self.msg,
            "priority": self.priority,
            "classtype": self.classtype,
            "rule_raw": self.raw_rule
        }


class RuleEngine:
    """
    Corresponds directly to RuleEngine in Slide 31 Class Diagram:
    - id: int
    - rule_set: list
    - rule_type: str
    - enabled: bool
    - load_rules(rule_file)
    - match_flow(flow)
    - get_alert_type(matched_rule)
    - update_rules(new_rules)
    """
    def __init__(self, rule_file_path: Optional[Path] = None):
        self.id: int = 1
        self.rule_type: str = "Snort Signature Rules"
        self.enabled: bool = True
        self.rule_set: List[SnortRule] = []
        self.rule_file: Path = rule_file_path or settings.RULES_PATH
        
        # Load default rules
        self.load_rules(self.rule_file)

    def load_rules(self, rule_file: Path) -> int:
        """Parses Snort .rules file into SnortRule objects"""
        self.rule_set.clear()
        if not rule_file.exists():
            return 0

        rule_pattern = re.compile(
            r'^(?P<action>alert)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+->\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<opts>.+)\)$'
        )

        with open(rule_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                m = rule_pattern.match(line)
                if not m:
                    continue

                action = m.group("action")
                proto = m.group("proto")
                src_ip = m.group("src_ip")
                src_port = m.group("src_port")
                dst_ip = m.group("dst_ip")
                dst_port = m.group("dst_port")
                opts_str = m.group("opts")

                # Parse options inside parentheses
                msg = "Snort Signature Match"
                sid = 1000000
                priority = 2
                classtype = "misc-activity"
                content = None
                nocase = False
                flags = None

                msg_m = re.search(r'msg:\s*\"([^\"]+)\"', opts_str)
                if msg_m:
                    msg = msg_m.group(1)

                sid_m = re.search(r'sid:\s*(\d+)', opts_str)
                if sid_m:
                    sid = int(sid_m.group(1))

                pri_m = re.search(r'priority:\s*(\d+)', opts_str)
                if pri_m:
                    priority = int(pri_m.group(1))

                class_m = re.search(r'classtype:\s*([\w\-]+)', opts_str)
                if class_m:
                    classtype = class_m.group(1)

                content_m = re.search(r'content:\s*\"([^\"]+)\"', opts_str)
                if content_m:
                    content = content_m.group(1)

                if "nocase;" in opts_str:
                    nocase = True

                flags_m = re.search(r'flags:\s*([0A-Z]+)', opts_str)
                if flags_m:
                    flags = flags_m.group(1)

                rule = SnortRule(
                    sid=sid,
                    action=action,
                    protocol=proto,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    msg=msg,
                    priority=priority,
                    classtype=classtype,
                    content=content,
                    nocase=nocase,
                    flags=flags,
                    raw_rule=line
                )
                self.rule_set.append(rule)

        return len(self.rule_set)

    def match_flow(self, flow: FlowData) -> Optional[Dict[str, Any]]:
        """Evaluates flow against all registered rules. Returns highest priority match."""
        if not self.enabled:
            return None

        best_match = None
        for rule in self.rule_set:
            match = rule.match_flow(flow)
            if match:
                # Priority 1 is highest in Snort
                if best_match is None or match["priority"] < best_match["priority"]:
                    best_match = match
                    if best_match["priority"] == 1:
                        break  # Short-circuit on critical match
        return best_match

    def get_alert_type(self, matched_rule: Dict[str, Any]) -> str:
        """Derives clean attack classification name from matched rule"""
        if not matched_rule:
            return "Normal"
        classtype = matched_rule.get("classtype", "")
        msg = matched_rule.get("msg", "")

        if "web-application-attack" in classtype or "SQL" in msg or "XSS" in msg:
            return "Web Attack (Exploit)"
        if "attempted-dos" in classtype or "Flood" in msg:
            return "Denial of Service (DoS)"
        if "attempted-recon" in classtype or "Scan" in msg:
            return "Port Scan / Reconnaissance"
        if "attempted-admin" in classtype or "Brute Force" in msg:
            return "Authentication Brute Force"
        if "trojan-activity" in classtype:
            return "Trojan / Malware Activity"
        return classtype or "Policy Violation"

    def update_rules(self, new_rules: List[str]) -> int:
        """Appends new Snort rules dynamically and persists them"""
        added = 0
        with open(self.rule_file, "a", encoding="utf-8") as f:
            for rule in new_rules:
                if rule.strip():
                    f.write(f"\n{rule.strip()}\n")
                    added += 1
        self.load_rules(self.rule_file)
        return added
