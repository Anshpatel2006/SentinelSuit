import json

from malware_platform.intel import threat_intel


def test_virustotal_result_is_json_serializable(monkeypatch):
    class FileObject:
        last_analysis_stats = type("WhistleBlowerDict", (dict,), {})(
            {"malicious": 2, "harmless": 10}
        )
        popular_threat_classification = None
        type_description = "PE32"

    class Client:
        def __init__(self, key):
            pass

        def get_object(self, path):
            return FileObject()

        def close(self):
            pass

    monkeypatch.setitem(__import__("sys").modules, "vt", type("Vt", (), {"Client": Client}))
    monkeypatch.setattr(threat_intel, "VIRUSTOTAL_API_KEY", "test-key")

    result = threat_intel.lookup_virustotal("a" * 64)

    json.dumps(result)