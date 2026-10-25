from malware_platform.reporting.risk_engine import assess
from malware_platform.reporting.report import _report_sections


def test_threat_intel_risk_contributes_to_risk_score():
    result = assess(intel={"decision": {"risk": "high"}})

    assert result["score"] == 70
    assert result["level"] == "high"
    assert result["factors"] == result["reasons"]


def test_medium_threat_intel_risk_cannot_be_downgraded_to_low():
    result = assess(intel={"decision": {"risk": "medium"}})

    assert result["score"] == 30
    assert result["level"] == "medium"


def test_yara_errors_do_not_count_as_matches():
    result = assess(static={"yara_matches": [{"error": "permission denied"}]})

    assert result["score"] == 0
    assert result["reasons"] == []


def test_real_yara_matches_contribute_to_risk_score():
    result = assess(static={"yara_matches": [{"rule": "SuspiciousRule"}]})

    assert result["score"] == 5
    assert result["reasons"] == ["1 YARA match(es)"]


def test_final_report_is_supported_by_report_renderers():
    report, intel = _report_sections({
        "metadata": {"sample_id": "SAM-1", "original_name": "demo.exe"},
        "hashes": {"sha256": "a" * 64},
        "threat_intel": {"known": False},
    })

    assert report["intel"]["hashes"]["sha256"] == "a" * 64
    assert intel["decision"]["known"] is False