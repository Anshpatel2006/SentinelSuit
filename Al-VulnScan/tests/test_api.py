from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from api import ScanManager, configured_cors_origins, make_handler
from scan_storage import ScanStorage


@pytest.fixture
def api_server(tmp_path):
    scanner_calls = []

    def fake_scan(
        target,
        *,
        scan_type,
        authorized,
        confirm_multiple_hosts,
        confirm_aggressive,
        confirm_all_ports,
    ):
        scanner_calls.append(
            (
                target,
                scan_type,
                authorized,
                confirm_multiple_hosts,
                confirm_aggressive,
                confirm_all_ports,
            )
        )
        return {
            "target": target,
            "scope": target,
            "scan_type": scan_type,
            "status": "completed",
            "errors": [],
            "services": [],
            "hosts": [],
            "nmap_xml": None,
        }

    manager = ScanManager(
        storage=ScanStorage(tmp_path / "history"),
        report_dir=tmp_path / "reports",
        scanner=fake_scan,
        analyzer=lambda result, **_: result,
    )
    origins = configured_cors_origins("http://localhost:5173")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(manager, origins))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", manager, scanner_calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(base, path, *, method="GET", payload=None, origin=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={
            **({"Content-Type": "application/json"} if data is not None else {}),
            **({"Origin": origin} if origin else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def test_api_exposes_health_profiles_and_enforces_scan_authorization(api_server):
    base, _manager, scanner_calls = api_server
    status, _, body = _request(base, "/health")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}

    status, _, body = _request(base, "/profiles")
    assert status == 200
    assert {item["id"] for item in json.loads(body)["profiles"]} == {
        "quick",
        "standard",
        "deep",
        "aggressive",
        "all_tcp_udp",
        "udp",
        "comprehensive",
    }

    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "127.0.0.1", "profile": "quick"},
    )
    assert status == 403
    assert json.loads(body)["error"]

    status, _, _ = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "192.0.2.1/30", "profile": "quick", "authorized": True},
    )
    assert status == 400

    status, _, _ = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "127.0.0.1", "profile": "comprehensive", "authorized": True},
    )
    assert status == 403
    assert scanner_calls == []

    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "127.0.0.1", "profile": "aggressive", "authorized": True},
    )
    assert status == 403
    assert "confirm_aggressive" in json.loads(body)["error"]
    assert scanner_calls == []

    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "127.0.0.1", "profile": "all_tcp_udp", "authorized": True},
    )
    assert status == 403
    assert "confirm_all_ports" in json.loads(body)["error"]
    assert scanner_calls == []

    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={
            "target": "127.0.0.1",
            "profile": "all_tcp_udp",
            "authorized": True,
            "confirm_all_ports": True,
        },
    )
    assert status == 202
    scan_id = json.loads(body)["scan_id"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = _request(base, f"/scans/{scan_id}")
        if json.loads(body)["status"] == "completed":
            break
        time.sleep(0.01)
    assert status == 200
    assert scanner_calls == [
        ("127.0.0.1", "all_tcp_udp", True, False, False, True)
    ]

    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={
            "target": "127.0.0.1",
            "profile": "aggressive",
            "authorized": True,
            "confirm_aggressive": True,
        },
    )
    assert status == 202
    scan_id = json.loads(body)["scan_id"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = _request(base, f"/scans/{scan_id}")
        if json.loads(body)["status"] == "completed":
            break
        time.sleep(0.01)
    assert status == 200
    assert scanner_calls == [
        ("127.0.0.1", "all_tcp_udp", True, False, False, True),
        ("127.0.0.1", "aggressive", True, False, True, False),
    ]


def test_api_scan_status_history_and_report_download_are_mocked(api_server):
    base, _manager, scanner_calls = api_server
    status, _, body = _request(
        base,
        "/scans",
        method="POST",
        payload={"target": "127.0.0.1", "profile": "quick", "authorized": True},
    )
    assert status == 202
    submitted = json.loads(body)
    scan_id = submitted["scan_id"]
    assert submitted["status"] in {"queued", "running"}

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = _request(base, f"/scans/{scan_id}")
        scan = json.loads(body)
        if scan["status"] == "completed":
            break
        time.sleep(0.01)
    assert status == 200
    assert scan["scan_id"] == scan_id
    assert scan["progress"] == 100
    assert scan["result"]["status"] == "completed"
    assert scan["error"] is None
    assert scanner_calls == [("127.0.0.1", "quick", True, False, False, False)]

    status, _, body = _request(base, "/scans")
    assert status == 200
    assert any(item["scan_id"] == scan_id for item in json.loads(body)["scans"])

    status, headers, body = _request(base, f"/scans/{scan_id}/report?format=json")
    assert status == 200
    assert headers["Content-Disposition"] == f'attachment; filename="{scan_id}.json"'
    assert json.loads(body)["scan_id"] == scan_id


def test_api_uses_existing_domain_and_multi_host_scope_authorization(api_server):
    base, _manager, scanner_calls = api_server
    payload = {
        "target": "192.0.2.0/30",
        "profile": "standard",
        "authorized": True,
    }
    status, _, body = _request(base, "/scans", method="POST", payload=payload)
    assert status == 403
    assert "confirm_multiple_hosts" in json.loads(body)["error"]

    payload["confirm_multiple_hosts"] = True
    status, _, body = _request(base, "/scans", method="POST", payload=payload)
    assert status == 202
    scan_id = json.loads(body)["scan_id"]

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = _request(base, f"/scans/{scan_id}")
        scan = json.loads(body)
        if scan["status"] == "completed":
            break
        time.sleep(0.01)
    assert status == 200
    assert scan["result"]["target"] == "192.0.2.0/30"
    assert scanner_calls == [("192.0.2.0/30", "standard", True, True, False, False)]

    payload = {
        "target": "test.example.invalid",
        "profile": "quick",
        "authorized": True,
    }
    status, _, body = _request(base, "/scans", method="POST", payload=payload)
    assert status == 202
    scan_id = json.loads(body)["scan_id"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = _request(base, f"/scans/{scan_id}")
        scan = json.loads(body)
        if scan["status"] == "completed":
            break
        time.sleep(0.01)
    assert status == 200
    assert scan["result"]["target"] == "test.example.invalid"
    assert scanner_calls[-1] == ("test.example.invalid", "quick", True, False, False, False)


def test_api_rejects_unconfigured_origins_and_invalid_cors_configuration(api_server):
    base, _manager, _scanner_calls = api_server
    status, _, body = _request(base, "/health", origin="https://attacker.example")
    assert status == 403
    assert json.loads(body)["error"] == "Origin is not allowed."

    with pytest.raises(ValueError):
        configured_cors_origins("https://example.com")
    with pytest.raises(ValueError):
        configured_cors_origins("*")
