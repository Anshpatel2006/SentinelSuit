import json

from fastapi.testclient import TestClient

from malware_platform.api.app import app
import malware_platform.api.routes.analysis as analysis


def test_report_pdf_download(monkeypatch, tmp_path):
    report = {
        "metadata": {
            "sample_id": "SAM-123",
            "original_name": "demo.exe",
        },
        "hashes": {"md5": "a", "sha1": "b", "sha256": "c"},
        "risk": {"level": "high", "score": 90},
        "ml": {"ready": False, "reason": "not available"},
        "iocs": {},
    }
    (tmp_path / "SAM-123_final.json").write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(analysis, "REPORTS_DIR", tmp_path)

    client = TestClient(app)
    response = client.get("/api/v1/reports/SAM-123/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")
