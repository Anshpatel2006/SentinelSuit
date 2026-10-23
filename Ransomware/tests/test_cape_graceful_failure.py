from pathlib import Path

from malware_platform.pipeline.flow import run


def test_run_continues_without_cape(monkeypatch, tmp_path):
    sample = tmp_path / "demo.exe"
    sample.write_bytes(b"MZ")

    monkeypatch.setattr("malware_platform.pipeline.flow.upload_file", lambda path: {
        "sample_id": "SAM-TEST",
        "original_name": "demo.exe",
        "stored_name": "demo.exe",
        "stored_path": str(sample),
        "size": sample.stat().st_size,
        "extension": ".exe",
    })
    monkeypatch.setattr("malware_platform.pipeline.flow.generate_hashes", lambda path: {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    })
    monkeypatch.setattr("malware_platform.pipeline.flow.check_authenticode", lambda path: None)
    monkeypatch.setattr("malware_platform.pipeline.flow.lookup_sample", lambda sha256: {"known": False})
    monkeypatch.setattr("malware_platform.pipeline.flow.perform_static_analysis", lambda path: {"file_identification": {"magic": "exe"}})
    monkeypatch.setattr("malware_platform.pipeline.flow.analyze_with_cape", lambda path: None)
    monkeypatch.setattr("malware_platform.pipeline.flow.extract_to_files", lambda *args, **kwargs: {
        "complete_exact": False,
        "features": {k: None for k in ["f1", "f2"]},
        "unresolved": ["f1", "f2"],
    })
    monkeypatch.setattr("malware_platform.pipeline.flow.predict", lambda features: {"ready": False, "reason": "CAPE unavailable"})
    monkeypatch.setattr("malware_platform.pipeline.flow.extract_iocs", lambda static, cape: {})
    monkeypatch.setattr("malware_platform.pipeline.flow.assess", lambda **kwargs: {"level": "low", "score": 10})
    monkeypatch.setattr("malware_platform.pipeline.flow.REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr("malware_platform.pipeline.flow.CAPE_STORAGE", tmp_path)
    monkeypatch.setattr("malware_platform.pipeline.flow.MODEL_PATH", str(tmp_path / "model.joblib"))
    monkeypatch.setattr("malware_platform.pipeline.flow.FEATURES", ["f1", "f2"])

    result = run(str(sample))

    assert result["branch"] == "unknown"
    assert result["cape"]["status"] == "not_available"
    assert result["risk"]["level"] == "low"
