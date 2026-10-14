import os
import subprocess
import sys
from pathlib import Path



def test_project_env_values_are_loaded():
    project_root = Path(__file__).resolve().parents[1]
    env_values = dict(os.environ)
    env_values.pop("MALWAREBAZAAR_API_KEY", None)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from malware_platform.config import MALWAREBAZAAR_API_KEY; print(bool(MALWAREBAZAAR_API_KEY))",
        ],
        cwd=project_root,
        env=env_values,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == "True"