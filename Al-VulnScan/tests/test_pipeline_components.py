from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

import cve_lookup
import ai_analyzer
import config
import pipeline
from config_auditor import audit_configurations
from evidence_engine import evaluate_detection_confidence
from explainability_engine import explain_finding
from fingerprint_engine import fingerprint_service
from nmap_xml_parser import NmapXMLParseError, parse_nmap_xml
from recommendation_engine import recommend_for_finding
from report_generator import generate_reports
from risk_engine import category_for_score, score_finding, score_scan
from rule_engine import evaluate_rules
from scan_comparator import compare_scans, format_comparison_report
from scan_storage import ScanStorage
from scanner import build_scan_arguments, scan_target, validate_ports, validate_target

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_target_validation_and_limits():
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target("2001:db8::1") == "2001:db8::1"
    assert validate_target("test.example.invalid") == "test.example.invalid"
    assert validate_target("192.0.2.0/28") == "192.0.2.0/28"
    with pytest.raises(ValueError):
        validate_target("")
    with pytest.raises(ValueError):
        validate_target("192.0.2.1/28")
    with pytest.raises(ValueError):
        validate_target("192.0.2.0/24")
    with pytest.raises(ValueError):
        validate_target("999.999.1.1")
    with pytest.raises(ValueError):
        validate_target("example..invalid")


def test_port_validation_and_safe_arguments():
    assert validate_ports("443,80,443") == [80, 443]
    with pytest.raises(ValueError):
        validate_ports("0")
    with pytest.raises(ValueError):
        validate_ports("80;id")
    quick = build_scan_arguments("quick")
    assert quick[:4] == ["-sT", "-T3", "--top-ports", "100"]
    custom = build_scan_arguments("standard", [443], [53])
    assert "-p" in custom
    assert "T:443,U:53" in custom
    assert "-sT" in custom and "-sU" in custom
    assert not any("script" in arg for arg in custom)
    aggressive = build_scan_arguments("aggressive")
    assert "-p-" in aggressive
    assert "--version-intensity" in aggressive
    assert aggressive[aggressive.index("--version-intensity") + 1] == "7"
    assert not any(arg in {"-A", "-sC", "--script"} for arg in aggressive)
    with pytest.raises(ValueError, match="cannot be combined with custom ports"):
        build_scan_arguments("aggressive", custom_tcp_ports="443")
    all_protocol_ports = build_scan_arguments("all_tcp_udp")
    assert "-sT" in all_protocol_ports and "-sU" in all_protocol_ports
    assert "T:1-65535,U:1-65535" in all_protocol_ports
    assert all_protocol_ports[all_protocol_ports.index("--version-intensity") + 1] == "7"
    assert not any(arg in {"-A", "-sC", "--script"} for arg in all_protocol_ports)
    with pytest.raises(ValueError, match="cannot be combined with custom ports"):
        build_scan_arguments("all_tcp_udp", custom_udp_ports="53")
    with pytest.raises(ValueError):
        build_scan_arguments("unknown")


def test_scan_requires_explicit_authorization():
    with pytest.raises(PermissionError):
        scan_target("127.0.0.1")
    with pytest.raises(PermissionError):
        scan_target("192.0.2.0/30", authorized=True)
    with pytest.raises(PermissionError, match="requires explicit confirmation"):
        scan_target("127.0.0.1", "aggressive", authorized=True)
    with pytest.raises(PermissionError, match="all TCP and UDP ports profile"):
        scan_target("127.0.0.1", "all_tcp_udp", authorized=True)


def test_xml_parser_preserves_states_and_evidence():
    result = parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))
    assert result["status"] == "completed"
    assert result["nmap_version"] == "7.94"
    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["hostnames"] == ["test.example.invalid"]
    assert result["services"][0]["state"] == "open"
    assert result["services"][0]["version_status"] == "exact"
    assert result["services"][0]["version_exact"] == "1.2.3"
    assert result["services"][0]["detection_confidence"] == 10
    assert result["services"][0]["detection_confidence_scale"] == "nmap_1_to_10"
    assert evaluate_detection_confidence(result["services"][0])["status"] == "high"
    assert result["services"][0]["cpe"][0].startswith("cpe:2.3:")
    assert result["services"][0]["scripts"][0]["output"] == "sanitized evidence"
    assert [item["state"] for item in result["services"]] == [
        "open",
        "open|filtered",
        "filtered",
    ]
    assert result["hosts"][0]["os"][0]["name"] == "Example OS"


def test_partial_xml_and_fingerprint_confidence():
    partial = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><ports/></host>'
        '<runstats><finished exit="error" errormsg="interrupted"/></runstats></nmaprun>'
    )
    assert partial["status"] == "partial"
    assert partial["errors"] == ["interrupted"]
    service = fingerprint_service(
        "192.0.2.10",
        {
            "host": "192.0.2.10",
            "port": 23,
            "protocol": "tcp",
            "state": "filtered",
            "service": "telnet",
            "product": "",
            "version": "",
            "detection_confidence": 95,
        },
        enable_http_probe=True,
    )
    assert service["fingerprint"]["confidence"] == "high"
    assert service["fingerprint"]["version_verified"] is False
    assert service["fingerprint"]["http_probe"] is None


def test_xml_parser_missing_fields_and_malformed_xml():
    result = parse_nmap_xml(
        '<nmaprun><host><ports><port protocol="tcp" portid="80">'
        '<state state="open"/></port></ports></host></nmaprun>'
    )
    assert result["services"][0]["service"] == ""
    assert result["services"][0]["version"] == ""
    assert result["status"] == "partial"
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml("<nmaprun>")
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml("<other/>")
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml('<!DOCTYPE nmaprun [<!ENTITY x "x">]><nmaprun/>')
    no_open = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="80">'
        '<state state="closed"/></port></ports></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>'
    )
    assert no_open["services"][0]["state"] == "closed"
    assert evaluate_rules(no_open) == []


def test_no_nmap_installation_returns_structured_failure(monkeypatch):
    monkeypatch.setattr("scanner.shutil.which", lambda _: None)
    result = scan_target("127.0.0.1", authorized=True)
    assert result["status"] == "failed"
    assert result["services"] == []
    assert "Nmap was not found" in result["errors"][0]


def test_scan_subprocess_uses_argv_and_parses_xml(monkeypatch):
    xml = FIXTURE.read_text(encoding="utf-8")
    monkeypatch.setattr("scanner.shutil.which", lambda _: "/usr/bin/nmap")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return __import__("subprocess").CompletedProcess(
            command, 0, stdout=xml, stderr=""
        )

    monkeypatch.setattr("scanner.subprocess.run", fake_run)
    result = scan_target("192.0.2.10", "quick", authorized=True)
    command, options = calls[0]
    assert isinstance(command, list)
    assert command[0] == "/usr/bin/nmap"
    assert command[1] == "192.0.2.10"
    assert options.get("shell", False) is False
    assert options["timeout"] > 0
    assert result["status"] == "completed"
    assert result["summary"]["confirmed_open"] == 1
    assert result["nmap_xml"] == xml


def test_nvd_rate_limit_retries_are_bounded(monkeypatch):
    attempts = []

    def rate_limited(*args, **kwargs):
        attempts.append(1)
        response = requests.Response()
        response.status_code = 429
        response.headers["Retry-After"] = "0"
        response.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        return response

    monkeypatch.setattr(cve_lookup._SESSION, "get", rate_limited)
    monkeypatch.setattr(cve_lookup.time, "sleep", lambda _: None)
    with pytest.raises(cve_lookup.NVDLookupError):
        cve_lookup._request_nvd({"keywordSearch": "sample"})
    assert len(attempts) == cve_lookup.NVD_RETRIES + 1


def test_nvd_empty_candidate_result(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_search", lambda query, cpe: ())
    assert cve_lookup.lookup_service_cves(
        {
            "state": "open",
            "product": "Example product",
            "version": "",
            "cpe": [],
        }
    ) == []


def test_ollama_unavailable_returns_nonfatal_status(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(ai_analyzer.requests, "get", fail)
    result = ai_analyzer.analyze_scan({"target": "127.0.0.1", "services": []})
    assert result["status"] == "unavailable"
    assert "deterministic results are preserved" in result["analysis"]


def test_ollama_missing_model_is_not_downloaded(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"models": []}

    monkeypatch.setattr(ai_analyzer.requests, "get", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(
        ai_analyzer.requests,
        "post",
        lambda *args, **kwargs: pytest.fail("model-not-found must not call chat"),
    )
    result = ai_analyzer.analyze_scan({"services": []})
    assert result["status"] == "model_not_found"
    assert "No model was downloaded" in result["analysis"]


def test_invalid_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("TEST_LIMIT", "not-a-number")
    with pytest.raises(ValueError, match="TEST_LIMIT"):
        config._positive_int("TEST_LIMIT", 10)


def test_rule_engine_open_only_and_deduplicates():
    scan = {
        "target": "192.0.2.10",
        "services": [
            {"host": "192.0.2.10", "port": 23, "protocol": "tcp", "state": "open", "service": "telnet"},
            {"host": "192.0.2.10", "port": 23, "protocol": "tcp", "state": "open", "service": "telnet"},
            {"host": "192.0.2.10", "port": 21, "protocol": "tcp", "state": "open|filtered", "service": "ftp"},
        ],
    }
    findings = evaluate_rules(scan)
    assert len(findings) == 1
    assert findings[0]["status"] == "potential"
    assert findings[0]["rule_id"] == "NET-CLR-001"
    assert findings[0]["evidence"][0]["value"] == "open"


def test_cpe_version_range_applicability():
    service_cpes = ["cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*"]
    record = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "2.0",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert cve_lookup._cpe_matches(record, service_cpes, "1.5")[0] == "version_match"
    assert cve_lookup._cpe_matches(record, service_cpes, "2.1")[0] == "version_mismatch"
    assert cve_lookup._cpe_matches(record, service_cpes, "")[0] == "product_match"
    assert cve_lookup._cpe_matches(record, [], "1.5")[0] == "candidate"


def test_closed_or_unknown_service_skips_nvd(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_request_nvd", lambda _: pytest.fail("unexpected NVD call"))
    assert cve_lookup.lookup_service_cves({"state": "open|filtered", "product": "Example"}) == []
    assert cve_lookup.lookup_service_cves({"state": "open", "service": "ssh"}) == []


def test_nvd_api_failures_are_explicit_and_bounded(monkeypatch):
    attempts = []

    def failing_get(*args, **kwargs):
        attempts.append(kwargs["timeout"])
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(cve_lookup._SESSION, "get", failing_get)
    monkeypatch.setattr(cve_lookup.time, "sleep", lambda _: None)
    cve_lookup._search.cache_clear()
    with pytest.raises(cve_lookup.NVDLookupError):
        cve_lookup._search("sample", "")
    assert len(attempts) == cve_lookup.NVD_RETRIES + 1
    cve_lookup._search.cache_clear()


def test_risk_is_deterministic_and_caps_unverified_candidates():
    finding = {"severity": "critical", "confidence": "medium"}
    candidate = {
        "match_status": "candidate",
        "cvss_score": 10.0,
        "severity": "critical",
    }
    first = score_finding(finding, [candidate])
    assert first == score_finding(finding, [candidate])
    assert first["score"] <= 49
    assert first["category"] != "Critical"
    assert category_for_score(0) == "Informational"
    assert category_for_score(24) == "Low"
    assert category_for_score(25) == "Medium"
    assert category_for_score(50) == "High"
    assert category_for_score(75) == "Critical"
    assert score_finding({"severity": "low", "confidence": "unknown"})["score"] == 2


def test_risk_assessment_includes_its_detected_service_and_version():
    assessments = score_scan(
        {
            "services": [
                {
                    "host": "127.0.0.1",
                    "port": 443,
                    "service": "https",
                    "product": "Example Server",
                    "version": "1.2.3",
                    "cve_candidates": [],
                }
            ],
            "findings": [
                {
                    "finding_id": "TEST-001:127.0.0.1:443",
                    "name": "Test finding",
                    "host": "127.0.0.1",
                    "port": 443,
                    "severity": "low",
                    "confidence": "medium",
                }
            ],
        }
    )
    assert assessments[0]["service"] == "https"
    assert assessments[0]["product"] == "Example Server"
    assert assessments[0]["version"] == "1.2.3"


def test_explanation_and_recommendation_are_structured():
    finding = {
        "name": "Potential service exposure",
        "description": "Observed service",
        "rule_id": "NET-CLR-001",
        "confidence": "medium",
        "evidence": [{"source": "nmap_xml", "value": "open"}],
    }
    explanation = explain_finding(finding)
    recommendation = recommend_for_finding(
        {**finding, "remediation": "Verify configuration.", "references": []},
        {"category": "Medium"},
    )[0]
    assert explanation["rule_ids"] == ["NET-CLR-001"]
    assert explanation["evidence_sources"] == ["nmap_xml"]
    assert explanation["evidence_confidence"] == "medium"
    assert recommendation["type"] == "suggested_requires_verification"
    assert "operational_impact" in recommendation


def test_report_formats_escape_html_and_preserve_json(tmp_path):
    result = {
        "target": "192.0.2.10",
        "status": "completed",
        "scan_type": "quick",
        "services": [
            {
                "host": "192.0.2.10",
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "<script>alert(1)</script>",
                "version": "",
                "cve_candidates": [],
            }
        ],
        "findings": [],
        "risk_assessments": [],
        "recommendations": [],
        "errors": [],
    }
    paths = generate_reports(result, tmp_path, scan_id="test-scan")
    assert set(paths) == {"markdown", "json", "html"}
    html_text = Path(paths["html"]).read_text(encoding="utf-8")
    assert "<script>" not in html_text
    assert "&lt;script&gt;" in html_text
    report_json = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert report_json["scan_id"] == "test-scan"
    with pytest.raises(FileExistsError):
        generate_reports(result, tmp_path, scan_id="test-scan")


def test_reports_tolerate_missing_and_malformed_optional_fields(tmp_path):
    paths = generate_reports(
        {
            "target": "127.0.0.1",
            "status": "partial",
            "services": None,
            "hosts": "invalid",
            "findings": None,
            "configuration_audit": None,
            "risk_assessments": "invalid",
            "recommendations": None,
            "ai_analysis": None,
            "errors": "optional stage unavailable",
        },
        tmp_path,
        scan_id="malformed",
    )
    assert "No host records" in Path(paths["markdown"]).read_text(encoding="utf-8")
    assert "optional stage unavailable" in Path(paths["html"]).read_text(encoding="utf-8")


def test_storage_roundtrip_and_corrupt_history(tmp_path):
    storage = ScanStorage(tmp_path)
    saved = storage.save_scan(
        {
            "target": "127.0.0.1",
            "scan_type": "quick",
            "status": "completed",
            "services": [],
        }
    )
    assert storage.load_scan(saved["scan_id"])["target"] == "127.0.0.1"
    storage.update_scan(saved["scan_id"], {"report_locations": {"json": "x.json"}})
    assert storage.load_scan(saved["scan_id"])["report_locations"]["json"] == "x.json"
    corrupt = tmp_path / "20261021T000000Z_aaaaaaaaaaaa"
    corrupt.mkdir()
    (corrupt / "metadata.json").write_text("{broken", encoding="utf-8")
    assert len(storage.list_scans()) == 1


def test_comparison_warns_for_incomplete_scan_and_no_false_remediation():
    old = {
        "target": "192.0.2.10",
        "status": "completed",
        "scan_type": "standard",
        "services": [{"host": "192.0.2.10", "port": 443, "protocol": "tcp", "state": "open"}],
        "findings": [{"finding_id": "x"}],
    }
    new = {
        "target": "192.0.2.10",
        "status": "partial",
        "scan_type": "standard",
        "services": [],
        "findings": [],
    }
    result = compare_scans(old, new)
    assert result["comparable"] is False
    assert result["no_longer_open_ports"][0]["port"] == 443
    assert "No remediation is claimed" in format_comparison_report(result)
    assert "incomplete" in result["limitations"][0]


def test_configuration_audit_does_not_infer_missing_probe_data():
    result = audit_configurations({"services": [{"port": 443, "service": "https"}]})
    assert result["checks"] == []
    assert "not currently assessed" in result["summary"]["not_run"]


def test_pipeline_wires_evidence_rules_cves_risk_and_ai(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "lookup_service_cves",
        lambda service: [
            {
                "id": "CVE-TEST-0001",
                "match_status": "candidate",
                "cvss_score": None,
                "severity": "unknown",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-TEST-0001",
                "applicability_verified": False,
            }
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "analyze_scan",
        lambda scan: {
            "status": "completed",
            "analysis": "Evidence is a candidate only.",
            "label": "AI-assisted analysis",
        },
    )
    result = pipeline.analyze_scan_result(
        {
            "target": "192.0.2.10",
            "scope": "192.0.2.10",
            "status": "completed",
            "scan_type": "standard",
            "services": [
                {
                    "host": "192.0.2.10",
                    "port": 21,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ftp",
                    "product": "Example FTP",
                    "version": "",
                    "version_status": "unknown",
                    "version_exact": "",
                    "cpe": [],
                    "detection_confidence": 90,
                }
            ],
            "errors": [],
        }
    )
    assert result["services"][0]["evidence"]["cve_matching_eligible"]
    assert result["services"][0]["cve_candidates"][0]["match_status"] == "candidate"
    assert result["findings"][0]["rule_id"] == "NET-CLR-002"
    assert result["risk_assessments"]
    assert result["findings"][0]["explanation"]["rule_ids"] == ["NET-CLR-002"]
    assert result["recommendations"]
    assert result["ai_analysis"]["status"] == "completed"
