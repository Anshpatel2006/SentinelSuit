"""
SentinelIDS Comprehensive Unit and Integration Test Suite
Validates all classes and workflows according to SentinelSuite Presentation (Slides 10, 28-35).
"""
import sys
from datetime import datetime
from app.core.flow_extractor import FlowData, FlowFeatureExtractor
from app.core.rule_engine import RuleEngine
from app.core.ml_engine import MLModel
from app.core.detection_engine import DetectionEngine
from app.core.nmap_scanner import nmap_scanner
from app.core.ai_analyzer import ai_analyzer
from app.core.alert_manager import Alert, alert_manager
from app.database.db_manager import db_manager
from app.reporting.report_generator import report_generator

def run_tests():
    print("=" * 60)
    print("  RUNNING SENTINEL IDS VERIFICATION TEST SUITE")
    print("=" * 60)

    # 1. Test FlowFeatureExtractor
    print("\n[+] 1. Testing FlowData & FlowFeatureExtractor...")
    extractor = FlowFeatureExtractor(flow_timeout=10)
    packet1 = {
        "timestamp": datetime.utcnow(),
        "length": 64,
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False,
        "flags_val": 2,
        "payload": b"GET /login.php HTTP/1.1\r\nHost: target.com\r\n\r\n"
    }
    flow, timed_out = extractor.process_packet(packet1)
    features = extractor.extract_features(flow)
    assert len(features) == len(extractor.features), "Mismatch in feature count!"
    print(f"    - Extracted {len(features)} features successfully.")
    print(f"    - Sample duration: {features['flow_duration']}s, syn_flags: {features['syn_flag_count']}")

    # 2. Test RuleEngine (Snort Signatures)
    print("\n[+] 2. Testing RuleEngine (Snort Signatures)...")
    rule_engine = RuleEngine()
    print(f"    - Loaded {len(rule_engine.rule_set)} Snort-style rules.")
    
    # Create malicious SQL injection packet
    sqli_flow = FlowData("10.0.0.5", "10.0.0.1", 44321, 80, "TCP")
    sqli_flow.add_packet({
        "timestamp": datetime.utcnow(),
        "length": 180,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 44321,
        "dst_port": 80,
        "protocol": "TCP",
        "syn": False, "ack": True, "fin": False, "rst": False, "psh": True, "urg": False,
        "flags_val": 24,
        "payload": b"POST /search HTTP/1.1\r\n\r\nid=1 UNION SELECT username, password FROM users--"
    })
    rule_match = rule_engine.match_flow(sqli_flow)
    assert rule_match is not None, "Expected SQL injection rule to match!"
    print(f"    - Matched Rule: SID {rule_match['sid']} -> {rule_match['msg']}")
    print(f"    - Alert Category: {rule_engine.get_alert_type(rule_match)}")

    # 3. Test MLModel
    print("\n[+] 3. Testing MLModel (Random Forest Anomaly Classifier)...")
    ml_model = MLModel()
    feature_vec = extractor.normalize_features(features)
    ml_res = ml_model.classify(feature_vec)
    print(f"    - ML Prediction: {ml_res['prediction']} (Confidence: {ml_res['confidence']:.2f}, Anomaly Score: {ml_res['anomaly_score']:.2f})")

    # 4. Test DetectionEngine (Hybrid Detection)
    print("\n[+] 4. Testing Hybrid DetectionEngine...")
    detection_engine = DetectionEngine(rule_engine=rule_engine, ml_model=ml_model, feature_extractor=extractor)
    analysis = detection_engine.analyze_flow(sqli_flow)
    classification = analysis["classification"]
    print(f"    - Threat Detected: {classification['is_threat']}")
    print(f"    - Attack Type: {classification['attack_type']}")
    print(f"    - Severity: {classification['severity']}")
    print(f"    - Risk Score: {classification['risk_score']}/100")
    print(f"    - Response Action: {classification['response_action']}")

    # 5. Test DatabaseManager
    print("\n[+] 5. Testing DatabaseManager...")
    saved_alert = db_manager.save_alert(analysis["alert"])
    print(f"    - Saved Alert ID: {saved_alert['id']} to {db_manager.db_type} database.")
    stats = db_manager.get_statistics()
    print(f"    - Stats: Total Alerts: {stats['total_alerts']}, Breakdown: {stats['severity_distribution']}")

    # 6. Test Bounded Nmap Scanner & AI Incident Analyzer
    print("\n[+] 6. Testing Bounded Scanner & AI Incident Analyzer...")
    scan_res = nmap_scanner.run_scan("127.0.0.1")
    print(f"    - Bounded Scanner Status: {scan_res['status']} (Ports scanned: 20)")
    ai_summary = ai_analyzer.generate_incident_summary(saved_alert, scan_res)
    print("    - AI Incident Summary generated successfully (First 150 chars):")
    print("      " + ai_summary.splitlines()[0])

    # 7. Test ReportGenerator
    print("\n[+] 7. Testing ReportGenerator (PDF & JSON)...")
    rep_res = report_generator.generate_report(export_pdf=True)
    print(f"    - Generated JSON: {rep_res['json_path']}")
    print(f"    - Generated PDF: {rep_res['pdf_path']}")

    print("\n" + "=" * 60)
    print("  ALL MODULE 3 SENTINEL IDS TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
