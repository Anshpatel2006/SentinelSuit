"""Loopback-only HTTP adapter for authorized AI-VulnScan assessments."""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from config import REPORT_OUTPUT_DIR
from pipeline import analyze_scan_result
from report_generator import generate_reports
from scan_storage import ScanStorage, generate_scan_id, validate_scan_id
from scanner import (
    SCAN_PROFILES,
    scan_target,
    target_host_count,
    validate_target,
)

logger = logging.getLogger(__name__)

API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8765
MAX_REQUEST_BYTES = 16 * 1024
MAX_RETAINED_JOBS = 128
API_PROFILES = (
    "quick",
    "standard",
    "deep",
    "aggressive",
    "all_tcp_udp",
    "udp",
    "comprehensive",
)
REPORT_FORMATS = {
    "md": ("text/markdown; charset=utf-8", ".md"),
    "json": ("application/json; charset=utf-8", ".json"),
    "html": ("text/html; charset=utf-8", ".html"),
}


def configured_cors_origins(raw: str | None = None) -> frozenset[str]:
    """Return exact localhost frontend origins configured for browser access."""
    setting = raw if raw is not None else os.getenv(
        "AL_VULNSCAN_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    origins: set[str] = set()
    for value in setting.split(","):
        origin = value.strip()
        if not origin:
            continue
        try:
            parsed = urlsplit(origin)
            parsed.port
        except ValueError as exc:
            raise ValueError(
                "CORS origins must be exact HTTP(S) localhost frontend origins."
            ) from exc
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "CORS origins must be exact HTTP(S) localhost frontend origins."
            )
        if parsed.path == "/":
            origin = origin[:-1]
        origins.add(origin)
    return frozenset(origins)


def _response_for_job(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_id": job["scan_id"],
        "status": job["status"],
        "progress": job["progress"],
        "result": job.get("result"),
        "error": job.get("error"),
        "target": job.get("target"),
        "profile": job.get("profile"),
    }


class ScanManager:
    """Run one bounded scan at a time and persist results using CLI storage."""

    def __init__(
        self,
        storage: ScanStorage | None = None,
        *,
        report_dir: str | Path | None = None,
        scanner=scan_target,
        analyzer=analyze_scan_result,
        report_writer=generate_reports,
    ):
        self.storage = storage or ScanStorage()
        self.report_dir = Path(report_dir or REPORT_OUTPUT_DIR).resolve()
        self._scanner = scanner
        self._analyzer = analyzer
        self._report_writer = report_writer
        self._lock = threading.Lock()
        self._active = False
        self._jobs: dict[str, dict[str, Any]] = {}

    def submit(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        if payload.get("authorized") is not True:
            raise PermissionError("Every scan requires authorized: true.")
        target = validate_target(payload.get("target"))
        host_count = target_host_count(target)
        multiple_hosts_confirmed = payload.get("confirm_multiple_hosts") is True
        if host_count > 1 and not multiple_hosts_confirmed:
            raise PermissionError(
                f"Scope contains {host_count} addresses; "
                "confirm_multiple_hosts: true is required."
            )
        profile = payload.get("profile")
        if not isinstance(profile, str) or profile not in API_PROFILES:
            raise ValueError("Choose a supported scan profile.")
        if profile == "comprehensive" and payload.get("confirm_comprehensive") is not True:
            raise PermissionError(
                "The comprehensive profile requires confirm_comprehensive: true."
            )
        if profile == "aggressive" and payload.get("confirm_aggressive") is not True:
            raise PermissionError(
                "The aggressive all-TCP-ports profile requires confirm_aggressive: true."
            )
        if profile == "all_tcp_udp" and payload.get("confirm_all_ports") is not True:
            raise PermissionError(
                "The all TCP and UDP ports profile requires confirm_all_ports: true."
            )

        with self._lock:
            if self._active:
                raise RuntimeError("A scan is already running; try again later.")
            scan_id = generate_scan_id()
            job = {
                "scan_id": scan_id,
                "target": target,
                "profile": profile,
                "confirm_multiple_hosts": multiple_hosts_confirmed,
                "confirm_aggressive": profile == "aggressive",
                "confirm_all_ports": profile == "all_tcp_udp",
                "status": "queued",
                "progress": 0,
                "result": None,
                "error": None,
            }
            self._jobs[scan_id] = job
            self._active = True
            self._prune_jobs()
            worker = threading.Thread(
                target=self._run_scan,
                args=(
                    scan_id,
                    target,
                    profile,
                    multiple_hosts_confirmed,
                    profile == "aggressive",
                    profile == "all_tcp_udp",
                ),
                daemon=True,
                name=f"al-vulnscan-{scan_id}",
            )
            worker.start()
        return _response_for_job(job)

    def _prune_jobs(self) -> None:
        if len(self._jobs) <= MAX_RETAINED_JOBS:
            return
        for scan_id, job in list(self._jobs.items()):
            if len(self._jobs) <= MAX_RETAINED_JOBS:
                break
            if job["status"] in {"completed", "partial", "failed"}:
                self._jobs.pop(scan_id, None)

    def _run_scan(
        self,
        scan_id: str,
        target: str,
        profile: str,
        multiple_hosts_confirmed: bool,
        aggressive_confirmed: bool,
        all_ports_confirmed: bool,
    ) -> None:
        try:
            with self._lock:
                job = self._jobs[scan_id]
                job.update(status="running", progress=10)
            scanned = self._scanner(
                target,
                scan_type=profile,
                authorized=True,
                confirm_multiple_hosts=multiple_hosts_confirmed,
                confirm_aggressive=aggressive_confirmed,
                confirm_all_ports=all_ports_confirmed,
            )
            with self._lock:
                self._jobs[scan_id]["progress"] = 60
            result = self._analyzer(scanned, enable_http_probe=False, include_ai=False)
            raw_xml = result.pop("nmap_xml", None)
            result["scan_id"] = scan_id
            saved = self.storage.save_scan(result, nmap_xml=raw_xml, scan_id=scan_id)
            paths = self._report_writer(result, output_dir=self.report_dir, scan_id=scan_id)
            self.storage.update_scan(
                scan_id,
                {
                    "report_locations": paths,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            result["scan_id"] = saved["scan_id"]
            status = result.get("status", "failed")
            if status not in {"completed", "partial", "failed"}:
                status = "failed"
            with self._lock:
                self._jobs[scan_id].update(
                    status=status,
                    progress=100,
                    result=result,
                    error=(result.get("errors") or [None])[0]
                    if status == "failed"
                    else None,
                )
        except Exception as exc:
            logger.exception("API scan %s failed.", scan_id)
            with self._lock:
                self._jobs[scan_id].update(
                    status="failed",
                    progress=100,
                    error=str(exc),
                )
        finally:
            with self._lock:
                self._active = False

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        try:
            scan_id = validate_scan_id(scan_id)
        except ValueError:
            return None
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None:
                return dict(_response_for_job(job))
        try:
            result = self.storage.load_scan(scan_id)
        except (FileNotFoundError, OSError, ValueError):
            return None
        status = result.get("status", "unknown")
        return {
            "scan_id": scan_id,
            "status": status,
            "progress": 100 if status in {"completed", "partial", "failed"} else 0,
            "result": result,
            "error": (result.get("errors") or [None])[0]
            if status == "failed"
            else None,
        }

    def list_scans(self) -> list[dict[str, Any]]:
        scans = []
        for metadata in self.storage.list_scans():
            status = metadata.get("status", "unknown")
            scans.append(
                {
                    "scan_id": metadata.get("scan_id"),
                    "status": status,
                    "progress": 100 if status in {"completed", "partial", "failed"} else 0,
                    "result": None,
                    "error": None,
                    "target": metadata.get("target"),
                    "profile": metadata.get("scan_type"),
                    "created_at": metadata.get("created_at"),
                }
            )
        with self._lock:
            persisted_ids = {item["scan_id"] for item in scans}
            for job in self._jobs.values():
                if job["scan_id"] not in persisted_ids:
                    scans.insert(0, _response_for_job(job))
        return scans

    def report_path(self, scan_id: str, format_name: str) -> tuple[Path, str] | None:
        if format_name not in REPORT_FORMATS:
            return None
        entry = self.get_scan(scan_id)
        if entry is None or entry["status"] not in {"completed", "partial", "failed"}:
            return None
        try:
            metadata = self.storage.load_metadata(scan_id)
        except (FileNotFoundError, OSError, ValueError):
            return None
        content_type, suffix = REPORT_FORMATS[format_name]
        path = self.report_dir / f"{scan_id}{suffix}"
        declared = metadata.get("report_locations", {}).get(
            {"md": "markdown", "json": "json", "html": "html"}[format_name]
        )
        try:
            if (
                not declared
                or Path(declared).resolve() != path.resolve()
                or path.resolve().parent != self.report_dir
                or not path.is_file()
            ):
                return None
        except (OSError, TypeError, ValueError):
            return None
        return path, content_type


def make_handler(manager: ScanManager, cors_origins: frozenset[str]):
    class APIHandler(BaseHTTPRequestHandler):
        server_version = "Al-VulnScan-API/1"

        def log_message(self, format: str, *args: Any) -> None:
            logger.info("%s - %s", self.address_string(), format % args)

        def _send_bytes(
            self,
            status: int,
            content: bytes,
            content_type: str,
            *,
            download_name: str | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            origin = self.headers.get("Origin")
            if origin in cors_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            if download_name:
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{download_name}"',
                )
            self.end_headers()
            self.wfile.write(content)

        def _send_json(self, status: int, payload: Any) -> None:
            self._send_bytes(
                status,
                json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def _reject_unconfigured_origin(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is not None and origin not in cors_origins:
                self._send_json(403, {"error": "Origin is not allowed."})
                return True
            return False

        def do_OPTIONS(self) -> None:
            if self._reject_unconfigured_origin():
                return
            self.send_response(204)
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            if self._reject_unconfigured_origin():
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/health":
                self._send_json(200, {"status": "ok"})
            elif parsed.path == "/profiles":
                self._send_json(
                    200,
                    {
                        "profiles": [
                            {"id": key, **SCAN_PROFILES[key]}
                            for key in API_PROFILES
                        ]
                    },
                )
            elif parsed.path == "/scans":
                self._send_json(200, {"scans": manager.list_scans()})
            elif parsed.path.startswith("/scans/"):
                parts = parsed.path.strip("/").split("/")
                if len(parts) == 2:
                    scan = manager.get_scan(parts[1])
                    if scan is None:
                        self._send_json(404, {"error": "Scan not found."})
                    else:
                        self._send_json(200, scan)
                    return
                if len(parts) == 3 and parts[2] == "report":
                    params = parse_qs(parsed.query)
                    format_name = (params.get("format") or [""])[0]
                    report = manager.report_path(parts[1], format_name)
                    if report is None:
                        self._send_json(404, {"error": "Report not found."})
                        return
                    path, content_type = report
                    self._send_bytes(
                        200,
                        path.read_bytes(),
                        content_type,
                        download_name=path.name,
                    )
                    return
                self._send_json(404, {"error": "Route not found."})
            else:
                self._send_json(404, {"error": "Route not found."})

        def do_POST(self) -> None:
            if self._reject_unconfigured_origin():
                return
            if urlsplit(self.path).path != "/scans":
                self._send_json(404, {"error": "Route not found."})
                return
            content_length = self.headers.get("Content-Length")
            try:
                length = int(content_length or "")
            except ValueError:
                self._send_json(400, {"error": "A valid Content-Length is required."})
                return
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._send_json(413, {"error": "Request body is empty or too large."})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "Request body must be valid JSON."})
                return
            try:
                response = manager.submit(payload)
            except PermissionError as exc:
                self._send_json(403, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self._send_json(429, {"error": str(exc)})
                return
            except (TypeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(202, response)

    return APIHandler


def serve(port: int = DEFAULT_API_PORT) -> None:
    """Start the API on IPv4 loopback only."""
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    origins = configured_cors_origins()
    server = ThreadingHTTPServer((API_HOST, port), make_handler(ScanManager(), origins))
    server.daemon_threads = True
    logger.info("AI-VulnScan API listening at http://%s:%d", API_HOST, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("AI-VulnScan API stopped.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the loopback-only AI-VulnScan API.")
    parser.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    args = parser.parse_args()
    serve(args.port)


if __name__ == "__main__":
    main()
