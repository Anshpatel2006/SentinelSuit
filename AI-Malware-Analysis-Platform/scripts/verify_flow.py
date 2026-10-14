#!/usr/bin/env python3
"""Pre-flight checks for the analysis pipeline."""

from pathlib import Path
import importlib.util
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malware_platform.analysis.cape_client import CAPE_URL, check_cape
from malware_platform.config import (
    CAPE_STORAGE,
    CUSTOM_PLUGINS_DIR,
    MALMEM_DATASET,
    REPORTS_DIR,
)


def check(name, ok, detail=""):
    print(f"[{'OK' if ok else 'FAIL'}] {name} {detail}")


def main():
    ok = True
    for mod in ["requests", "pefile", "filetype", "sklearn", "joblib", "fastapi"]:
        found = importlib.util.find_spec(mod) is not None
        check(mod, found)
        ok &= found

    cape = check_cape()
    check("CAPE API", cape, CAPE_URL)
    ok &= cape

    mem = CAPE_STORAGE / "7" / "memory.dmp"
    check("Example CAPE memory dump", mem.exists(), str(mem))
    check(
        "Volatility plugin pspcid_final_test.py",
        (CUSTOM_PLUGINS_DIR / "pspcid_final_test.py").exists(),
    )
    check("MalMem dataset", MALMEM_DATASET.exists(), str(MALMEM_DATASET))
    check("Reports directory", REPORTS_DIR.exists(), str(REPORTS_DIR))
    print("\nREADY" if ok else "\nNOT READY")


if __name__ == "__main__":
    main()
