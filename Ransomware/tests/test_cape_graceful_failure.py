from malware_platform.pipeline.flow import run


def test_run_performs_only_threat_intelligence_lookups(monkeypatch, tmp_path):
    calls = []

    def record_static_call(*args):
        calls.append("static")

    def record_cape_call(*args):
        calls.append("cape")

    monkeypatch.setattr("malware_platform.pipeline.flow.upload_file", lambda path: {
        "sample_id": "SAM-TEST",
        "original_name": "demo.exe",
        "stored_name": "demo.exe",
        "stored_path": str(tmp_path / "demo.exe"),
        "size": 2,
        "extension": ".exe",
    })
    monkeypatch.setattr("malware_platform.pipeline.flow.generate_hashes", lambda path: {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    })
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.lookup_sample",
        lambda sha256: {"known": False, "malicious": False, "risk": "low"},
    )
    monkeypatch.setattr("malware_platform.pipeline.flow.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("malware_platform.pipeline.flow.save_html", lambda *args: None)
    monkeypatch.setattr("malware_platform.pipeline.flow.save_pdf", lambda *args: None)
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.perform_static_analysis",
        record_static_call,
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.analyze_with_cape",
        record_cape_call,
    )

    result = run(str(tmp_path / "demo.exe"))

    assert result["branch"] == "threat_intelligence_only"
    assert result["analysis_scope"] == ["VirusTotal", "MalwareBazaar"]
    assert "cape" not in result
    assert "static" not in result
    assert result["risk"]["level"] == "low"
    assert calls == []


def test_full_analysis_runs_static_analysis_and_cape(monkeypatch, tmp_path):
    sample_path = str(tmp_path / "demo.exe")
    cape_calls = []
    static_result = {"file_identification": {"magic": "exe"}}

    monkeypatch.setattr("malware_platform.pipeline.flow.upload_file", lambda _: {
        "sample_id": "SAM-FULL",
        "original_name": "demo.exe",
        "stored_name": "demo.exe",
        "stored_path": sample_path,
        "size": 2,
        "extension": ".exe",
    })
    monkeypatch.setattr("malware_platform.pipeline.flow.generate_hashes", lambda _: {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    })
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.lookup_sample",
        lambda _: {"known": False, "malicious": False, "risk": "low"},
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.check_authenticode",
        lambda _: {"Status": "NotSigned"},
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.perform_static_analysis",
        lambda _: static_result,
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.analyze_with_cape",
        lambda path: cape_calls.append(path),
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.extract_iocs",
        lambda *_: {},
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.FEATURES",
        ["f1", "f2"],
    )
    monkeypatch.setattr(
        "malware_platform.pipeline.flow.MODEL_PATH",
        tmp_path / "model.joblib",
    )
    monkeypatch.setattr("malware_platform.pipeline.flow.train_model", lambda: None)
    monkeypatch.setattr("malware_platform.pipeline.flow.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("malware_platform.pipeline.flow.save_html", lambda *args: None)
    monkeypatch.setattr("malware_platform.pipeline.flow.save_pdf", lambda *args: None)

    result = run(sample_path, full_analysis=True)

    assert cape_calls == [sample_path]
    assert result["branch"] == "full_analysis"
    assert result["analysis_scope"][-1] == "ML"
    assert result["static"] == static_result
    assert result["cape"]["status"] == "not_available"
