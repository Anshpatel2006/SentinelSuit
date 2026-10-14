from unittest.mock import Mock

import requests

from malware_platform.intel import threat_intel


def test_virustotal_falls_back_when_vt_client_fails(monkeypatch):
    class BrokenClient:
        def __init__(self, *args, **kwargs):
            raise TypeError("unsupported request_timeout")

    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}
    }
    request = Mock(return_value=response)

    monkeypatch.setitem(__import__("sys").modules, "vt", Mock(Client=BrokenClient))
    monkeypatch.setattr(requests, "get", request)
    monkeypatch.setattr(threat_intel, "VIRUSTOTAL_API_KEY", "test-vt-key")

    result = threat_intel.lookup_virustotal("a" * 64)

    assert result["source"] == "virustotal"
    assert request.call_args.kwargs["headers"] == {"x-apikey": "test-vt-key"}


def test_malwarebazaar_lookup_uses_auth_key(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "query_status": "ok",
        "data": [{"file_type": "exe", "signature": "test"}],
    }
    request = Mock(return_value=response)

    monkeypatch.setattr(requests, "post", request)
    monkeypatch.setattr(threat_intel, "MALWAREBAZAAR_API_KEY", "test-mb-key")

    result = threat_intel.lookup_malwarebazaar("b" * 64)

    assert result["source"] == "malwarebazaar"
    assert request.call_args.kwargs["headers"] == {"Auth-Key": "test-mb-key"}