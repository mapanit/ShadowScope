"""Shared output paths for generated scan reports."""
import re
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent / "output"


def safe_path_component(value: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return component or "scan"


def report_directory(target: str, scan_name: str) -> Path:
    """Return the per-target, per-scan directory and create it."""
    directory = (
        REPORTS_DIR
        / safe_path_component(target)
        / safe_path_component(scan_name)
    )
    directory.mkdir(parents=True, exist_ok=True)
    return directory
