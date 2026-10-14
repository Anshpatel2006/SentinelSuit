"""
AI-VulnScan - Scan Storage Module

Purpose:
    Save, load, list, and manage scan results.

Features:
    - Saves structured scan results as JSON.
    - Saves scan metadata separately.
    - Optionally preserves raw Nmap XML.
    - Generates unique scan IDs.
    - Uses atomic file writes to reduce corruption risk.
    - Validates scan IDs to prevent path traversal.
    - Lists previous scans.
    - Loads saved scans.
    - Deletes scans when explicitly requested.

Requirements:
    Python standard library only.

Storage structure:
    scans/
        <scan_id>/
            scan.json
            metadata.json
            nmap.xml          # Optional
"""

import json
import os
import re
import tempfile
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_STORAGE_DIR = BASE_DIR / "scans"

SCAN_ID_PATTERN = re.compile(
    r"^\d{8}T\d{6}Z_[a-f0-9]{12}$"
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_timestamp() -> str:
    """Return the current UTC time in ISO 8601 format."""

    return datetime.now(timezone.utc).isoformat()


def generate_scan_id() -> str:
    """
    Generate a unique scan ID.

    Example:
        20261009T023000Z_a1b2c3d4e5f6
    """

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    random_part = uuid.uuid4().hex[:12]

    return f"{timestamp}_{random_part}"


def validate_scan_id(scan_id: str) -> str:
    """Reject invalid scan IDs."""

    if not isinstance(scan_id, str):
        raise ValueError("Scan ID must be a string.")

    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise ValueError("Invalid scan ID format.")

    return scan_id


def ensure_json_serializable(data: Any) -> None:
    """Ensure data can be saved as JSON."""

    try:
        json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Data cannot be serialized to JSON: {exc}"
        ) from exc


def atomic_write_text(
    destination: Path,
    content: str,
) -> None:
    """
    Write text using a temporary file and atomic replacement.

    The temporary file is created in the destination directory
    so replacement occurs on the same filesystem.
    """

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=".tmp_",
            suffix=".tmp",
            delete=False,
        ) as temp_file:

            temporary_path = Path(temp_file.name)

            temp_file.write(content)
            temp_file.flush()

            os.fsync(temp_file.fileno())

        os.replace(
            temporary_path,
            destination,
        )

    finally:
        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            temporary_path.unlink(missing_ok=True)


def atomic_write_json(
    destination: Path,
    data: Any,
) -> None:
    """Save JSON safely."""

    ensure_json_serializable(data)

    content = json.dumps(
        data,
        indent=4,
        ensure_ascii=False,
        allow_nan=False,
    )

    atomic_write_text(
        destination,
        content + "\n",
    )


def read_json_file(path: Path) -> dict:
    """Read a JSON file and validate its top-level structure."""

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path.name}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"{path.name} must contain a JSON object."
        )

    return data


# ============================================================
# STORAGE CLASS
# ============================================================

class ScanStorage:
    """
    Manages persistent AI-VulnScan scan results.

    Example:
        storage = ScanStorage()

        saved = storage.save_scan(scan_result)

        previous = storage.load_scan(
            saved["scan_id"]
        )
    """

    def __init__(
        self,
        storage_dir: Optional[str | Path] = None,
    ):
        if storage_dir is None:
            storage_dir = DEFAULT_STORAGE_DIR

        self.storage_dir = Path(
            storage_dir
        ).expanduser().resolve()

        self.storage_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    # --------------------------------------------------------
    # Resolve scan directory
    # --------------------------------------------------------

    def _scan_directory(
        self,
        scan_id: str,
    ) -> Path:

        scan_id = validate_scan_id(scan_id)

        directory = (
            self.storage_dir / scan_id
        ).resolve()

        # Defensive path check.
        if directory.parent != self.storage_dir:
            raise ValueError(
                "Invalid scan directory."
            )

        return directory

    # --------------------------------------------------------
    # Save scan
    # --------------------------------------------------------

    def save_scan(
        self,
        scan_result: dict,
        nmap_xml: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """
        Save a scan result.

        Args:
            scan_result:
                Dictionary returned by scanner.py or an
                enriched result from a later processing stage.

            nmap_xml:
                Optional raw Nmap XML string.
                The scanner must provide this separately.

            metadata:
                Optional additional metadata.

        Returns:
            Dictionary containing the scan ID and paths.
        """

        if not isinstance(scan_result, dict):
            raise TypeError(
                "scan_result must be a dictionary."
            )

        if metadata is not None and not isinstance(
            metadata,
            dict,
        ):
            raise TypeError(
                "metadata must be a dictionary."
            )

        ensure_json_serializable(scan_result)

        if metadata is not None:
            ensure_json_serializable(metadata)

        if nmap_xml is not None:
            if not isinstance(nmap_xml, str):
                raise TypeError(
                    "nmap_xml must be a string."
                )

            if not nmap_xml.strip():
                raise ValueError(
                    "nmap_xml cannot be empty."
                )

            if "<nmaprun" not in nmap_xml:
                raise ValueError(
                    "The supplied text does not appear "
                    "to contain Nmap XML."
                )

        # Create a unique ID for every saved scan.
        scan_id = generate_scan_id()

        scan_dir = self._scan_directory(
            scan_id
        )

        scan_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        scan_file = scan_dir / "scan.json"

        metadata_file = (
            scan_dir / "metadata.json"
        )

        xml_file = scan_dir / "nmap.xml"

        timestamp = utc_timestamp()

        # Preserve the scan result without modifying the
        # original dictionary.
        stored_scan = dict(scan_result)

        stored_scan["scan_id"] = scan_id
        stored_scan["stored_at"] = timestamp

        # Save the scan before creating its metadata.
        atomic_write_json(
            scan_file,
            stored_scan,
        )

        scan_metadata = {
            "scan_id": scan_id,
            "created_at": timestamp,
            "target": scan_result.get(
                "target",
                "unknown",
            ),
            "scan_type": scan_result.get(
                "scan_type",
                "unknown",
            ),
            "status": scan_result.get(
                "status",
                "unknown",
            ),
            "service_count": len(
                scan_result.get("services", [])
            ),
            "nmap_xml_available": (
                nmap_xml is not None
            ),
            "files": {
                "scan": "scan.json",
                "metadata": "metadata.json",
                "nmap_xml": (
                    "nmap.xml"
                    if nmap_xml is not None
                    else None
                ),
            },
            "additional_metadata": metadata or {},
        }

        atomic_write_json(
            metadata_file,
            scan_metadata,
        )

        # Save raw Nmap XML only when explicitly provided.
        if nmap_xml is not None:
            atomic_write_text(
                xml_file,
                nmap_xml,
            )

        return {
            "scan_id": scan_id,
            "scan_directory": str(scan_dir),
            "scan_file": str(scan_file),
            "metadata_file": str(metadata_file),
            "nmap_xml_file": (
                str(xml_file)
                if nmap_xml is not None
                else None
            ),
            "nmap_xml_saved": (
                nmap_xml is not None
            ),
        }

    # --------------------------------------------------------
    # Load scan
    # --------------------------------------------------------

    def load_scan(
        self,
        scan_id: str,
    ) -> dict:
        """Load a previously saved scan."""

        scan_dir = self._scan_directory(
            scan_id
        )

        scan_file = scan_dir / "scan.json"

        if not scan_file.is_file():
            raise FileNotFoundError(
                f"Scan not found: {scan_id}"
            )

        return read_json_file(
            scan_file
        )

    # --------------------------------------------------------
    # Load metadata
    # --------------------------------------------------------

    def load_metadata(
        self,
        scan_id: str,
    ) -> dict:
        """Load metadata for a previously saved scan."""

        scan_dir = self._scan_directory(
            scan_id
        )

        metadata_file = (
            scan_dir / "metadata.json"
        )

        if not metadata_file.is_file():
            raise FileNotFoundError(
                f"Metadata not found for scan: {scan_id}"
            )

        return read_json_file(
            metadata_file
        )

    # --------------------------------------------------------
    # Load raw Nmap XML
    # --------------------------------------------------------

    def load_nmap_xml(
        self,
        scan_id: str,
    ) -> str:
        """Load raw Nmap XML if it was saved."""

        scan_dir = self._scan_directory(
            scan_id
        )

        xml_file = scan_dir / "nmap.xml"

        if not xml_file.is_file():
            raise FileNotFoundError(
                f"No saved Nmap XML for scan: {scan_id}"
            )

        return xml_file.read_text(
            encoding="utf-8"
        )

    # --------------------------------------------------------
    # List scans
    # --------------------------------------------------------

    def list_scans(self) -> list[dict]:
        """
        List saved scans.

        Results are sorted newest first by scan ID.
        """

        scans = []

        if not self.storage_dir.exists():
            return scans

        for directory in self.storage_dir.iterdir():

            if not directory.is_dir():
                continue

            scan_id = directory.name

            if not SCAN_ID_PATTERN.fullmatch(
                scan_id
            ):
                continue

            metadata_file = (
                directory / "metadata.json"
            )

            scan_file = (
                directory / "scan.json"
            )

            if not metadata_file.is_file():
                continue

            try:
                metadata = read_json_file(
                    metadata_file
                )

                metadata["scan_available"] = (
                    scan_file.is_file()
                )

                scans.append(metadata)

            except (ValueError, OSError):
                # Skip unreadable entries rather than
                # terminating the entire history listing.
                continue

        scans.sort(
            key=lambda item: item.get(
                "created_at",
                "",
            ),
            reverse=True,
        )

        return scans

    # --------------------------------------------------------
    # Delete scan
    # --------------------------------------------------------

    def delete_scan(
        self,
        scan_id: str,
    ) -> bool:
        """
        Delete a saved scan and its associated files.

        This action is permanent.
        """

        scan_dir = self._scan_directory(
            scan_id
        )

        if not scan_dir.is_dir():
            return False

        import shutil

        shutil.rmtree(
            scan_dir
        )

        return True


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def save_scan(
    scan_result: dict,
    nmap_xml: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Convenience function to save a scan."""

    storage = ScanStorage()

    return storage.save_scan(
        scan_result=scan_result,
        nmap_xml=nmap_xml,
        metadata=metadata,
    )


def load_scan(scan_id: str) -> dict:
    """Convenience function to load a scan."""

    storage = ScanStorage()

    return storage.load_scan(
        scan_id
    )


def list_scans() -> list[dict]:
    """Convenience function to list saved scans."""

    storage = ScanStorage()

    return storage.list_scans()


# ============================================================
# BASIC TEST
# ============================================================

if __name__ == "__main__":

    # Use a temporary test directory so the test does not
    # mix sample data with your actual scan history.
    import tempfile

    with tempfile.TemporaryDirectory(
        prefix="ai_vulnscan_storage_test_"
    ) as temporary_directory:

        storage = ScanStorage(
            storage_dir=temporary_directory
        )

        sample_scan = {
            "target": "127.0.0.1",
            "scan_type": "standard",
            "status": "completed",
            "host_state": "up",
            "summary": {
                "total_services": 1,
                "tcp_services": 1,
                "udp_services": 0,
            },
            "services": [
                {
                    "port": 6379,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "redis",
                    "product": "Redis",
                    "version": "7.0.15",
                    "version_status": "exact",
                    "cpe": [
                        "cpe:/a:redislabs:redis:7.0.15"
                    ],
                }
            ],
        }

        saved = storage.save_scan(
            scan_result=sample_scan,
            metadata={
                "purpose": "storage_module_test",
            },
        )

        print("\nScan saved successfully.")
        print("Scan ID:", saved["scan_id"])
        print("Scan file:", saved["scan_file"])

        loaded = storage.load_scan(
            saved["scan_id"]
        )

        print("\nLoaded scan:")
        print("Target:", loaded["target"])
        print("Services:", len(loaded["services"]))

        history = storage.list_scans()

        print("\nSaved scans:", len(history))

        print("\nStorage module test completed successfully.")