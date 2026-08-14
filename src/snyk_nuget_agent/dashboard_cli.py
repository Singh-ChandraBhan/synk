"""Dashboard console entry point."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    dashboard = Path(__file__).with_name("dashboard.py")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(dashboard)])

