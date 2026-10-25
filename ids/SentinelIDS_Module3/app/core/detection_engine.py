from datetime import datetime
from typing import Dict, Any, Optional
from app.config import settings
from app.core.flow_extractor import FlowData, FlowFeatureExtractor
from app.core.rule_engine import RuleEngine
from app.core.ml_engine import MLModel

class DetectionEngine:
    """
    Corresponds directly to DetectionEngine in Slide 31 Class Diagram:
    - id: int
    - name: str
    - detection_type: str
    - threshold: float
    - status: str
    - analyze_flow(flow)
    - combine_results(ml_result, rule_result)
    - classify_threat(combined_data)
    - generate_alert(classification, flow)
    
    Implements the Hybrid Decision Engine (Slide 10, 29, 30, 32, 34).
    """
    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        ml_model: Optional[MLModel] = None,
        feature_extractor: Optional[FlowFeatureExtractor] = None
    ):
        self.id: int = 1
        self.name: str = "Sentinel Hybrid IDS Decision Engine"
        self.detection_type: str = "Hybrid (Signature Snort Rules + Random Forest Anomaly ML)"
        self.threshold: float = settings.ML_ANOMALY_THRESHOLD
        self.status: str = "ACTIVE"
        
        self.rule_engine = rule_engine or RuleEngine()
        self.ml_model = ml_model or MLModel(threshold=self.threshold)
        self.feature_extractor = feature_extractor or FlowFeatureExtractor()

    def analyze_flow(self, flow: FlowData) -> Dict[str, Any]:
        """
        Executes end-to-end analysis on a network flow:
        1. Feature extraction
        2. ML Anomaly classification
        3. Signature rule evaluation
        4. Hybrid combination & risk scoring
        5. Alert generation (if threat detected)
        """
        # 1. Feature extraction
        features_dict = self.feature_extractor.extract_features(flow)
        feature_vector = self.feature_extractor.normalize_features(features_dict)
        
        # 2. ML Analysis
        ml_result = self.ml_model.classify(feature_vector)
        
        # 3. Rule matching
        rule_match = self.rule_engine.match_flow(flow)
        
        # 4. Combine results
        combined = self.combine_results(ml_result, rule_match, flow, features_dict)
        
        # 5. Classify threat & calculate risk
        classification = self.classify_threat(combined)
        
        # 6. Generate Alert structure if intrusion detected
        alert = None
        if classification["is_threat"]:
            alert = self.generate_alert(classification, flow, features_dict)
            
        return {
            "flow": flow.to_dict(),
            "features": features_dict,
            "ml_result": ml_result,
            "rule_match": rule_match,
            "classification": classification,
            "alert": alert
        }

    def combine_results(
        self,
        ml_result: Dict[str, Any],
        rule_match: Optional[Dict[str, Any]],
        flow: FlowData,
        features: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Combines ML prediction and signature rule indicators into a unified assessment.
        """
        has_rule_match = rule_match is not None
        ml_is_threat = ml_result.get("is_anomaly", False)
        
        # Calculate Base Risk Score (0 - 100)
        risk_score = 0.0
        
        # Rule Contribution (Weights 55%)
        if has_rule_match:
            pri = rule_match.get("priority", 2)
            if pri == 1:
                risk_score += 65.0
            elif pri == 2:
                risk_score += 45.0
            else:
                risk_score += 25.0
                
        # ML Anomaly Contribution (Weights 45%)
        ml_anomaly_score = ml_result.get("anomaly_score", 0.0)
        risk_score += (ml_anomaly_score * 40.0)
        
        # Behavioral modifier (e.g. high packet rate or SYN scan)
        if features.get("flow_packets_per_sec", 0) > 100 or features.get("syn_flag_count", 0) > 20:
            risk_score += 15.0
            
        risk_score = min(100.0, max(0.0, round(risk_score, 2)))
        
        return {
            "has_rule_match": has_rule_match,
            "rule_match": rule_match,
            "ml_result": ml_result,
            "ml_is_threat": ml_is_threat,
            "risk_score": risk_score
        }

    def classify_threat(self, combined_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determines final attack label, severity level, and response action (Slide 34).
        """
        risk_score = combined_data["risk_score"]
        has_rule = combined_data["has_rule_match"]
        rule_match = combined_data["rule_match"]
        ml_result = combined_data["ml_result"]
        ml_pred = ml_result.get("prediction", "BENIGN")
        
        # Determine Threat Status
        is_threat = has_rule or (combined_data["ml_is_threat"] and risk_score >= 45.0)
        
        # Determine Attack Type Label
        if has_rule:
            attack_type = self.rule_engine.get_alert_type(rule_match)
        elif is_threat and ml_pred != "BENIGN":
            attack_type = f"Behavioral Anomaly ({ml_pred})"
        elif is_threat:
            attack_type = "Suspicious Traffic Anomaly"
        else:
            attack_type = "BENIGN / Normal Traffic"

        # Determine Severity (Slide 34)
        if risk_score >= settings.CRITICAL_RISK_THRESHOLD:
            severity = "CRITICAL"
        elif risk_score >= settings.HIGH_RISK_THRESHOLD:
            severity = "HIGH"
        elif risk_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine Response Action (Slide 34: LOG / MONITOR / SCAN / SCAN_AND_AI)
        if severity == "CRITICAL":
            response_action = "SCAN_AND_AI"
        elif severity == "HIGH":
            response_action = "SCAN"
        elif severity == "MEDIUM":
            response_action = "MONITOR"
        else:
            response_action = "LOG"

        return {
            "is_threat": is_threat,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "response_action": response_action
        }

    def generate_alert(
        self,
        classification: Dict[str, Any],
        flow: FlowData,
        features: Dict[str, float]
    ) -> Dict[str, Any]:
        """Creates alert dictionary structure for Database and Notifications"""
        rule_info = ""
        rule_match = self.rule_engine.match_flow(flow)
        if rule_match:
            rule_info = f"Rule SID: {rule_match.get('sid')} | {rule_match.get('msg')} | Class: {rule_match.get('classtype')}"

        details = (
            f"Attack: {classification['attack_type']} | Severity: {classification['severity']} | "
            f"Risk Score: {classification['risk_score']}/100 | Action: {classification['response_action']}. "
            f"{rule_info}"
        )

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "severity": classification["severity"],
            "attack_type": classification["attack_type"],
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "risk_score": classification["risk_score"],
            "response_action": classification["response_action"],
            "details": details,
            "status": "NEW",
            "raw_evidence": {
                "flow_summary": flow.to_dict(),
                "selected_features": {
                    "duration": features.get("flow_duration"),
                    "packets": flow.packet_count,
                    "bytes": flow.byte_count,
                    "packets_per_sec": features.get("flow_packets_per_sec"),
                    "syn_flags": features.get("syn_flag_count")
                },
                "rule_match": rule_match
            }
        }
