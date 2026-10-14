from malware_platform.pipeline.flow import apply_threat_intel_override
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


def test_confirmed_threat_intel_overrides_benign_ml_label():
    result = apply_threat_intel_override(
        {
            "ready": True,
            "label": "benign",
            "prediction": 0,
            "malware_probability": 0.45,
        },
        {
            "malicious": True,
            "risk": "high",
            "vt_positive_engines": 48,
            "detections": {"malicious": 48, "undetected": 27},
        },
    )

    assert result["label"] == "malware"
    assert result["prediction"] == 1
    assert result["model_label"] == "benign"
    assert result["malware_probability"] == 48 / 75
    assert result["risk_level"] == "high"
    assert result["decision_source"] == "threat_intelligence_override"


def test_malwarebazaar_high_risk_uses_full_probability():
    result = apply_threat_intel_override(
        {"ready": True, "label": "benign", "prediction": 0, "malware_probability": 0.4},
        {"malicious": True, "risk": "high", "mb": {"signature": "family"}},
    )

    assert result["malware_probability"] == 1.0
    assert result["risk_level"] == "high"


def test_final_report_is_supported_by_report_renderers():
    report, intel = _report_sections({
        "metadata": {"sample_id": "SAM-1", "original_name": "demo.exe"},
        "hashes": {"sha256": "a" * 64},
        "threat_intel": {"known": False},
    })

    assert report["intel"]["hashes"]["sha256"] == "a" * 64
    assert intel["decision"]["known"] is False