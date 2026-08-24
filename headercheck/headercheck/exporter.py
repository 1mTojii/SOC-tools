"""Export scan results to JSON/CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .checker import ScanResult


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "url": result.url,
        "status_code": result.status_code,
        "error": result.error,
        "present_headers": result.present_headers,
        "missing_headers": [
            {
                "name": f.rule.name,
                "severity": f.rule.severity.value,
                "description": f.rule.description,
                "recommendation": f.rule.recommendation,
            }
            for f in result.missing
        ],
        "version_leaks": [
            {"header": b.header_name, "value": b.value} for b in result.banners
        ],
        "exposed_paths": [
            {"path": p.path, "status_code": p.status_code} for p in result.exposed_paths
        ],
    }


def export_json(result: ScanResult, path: str) -> None:
    Path(path).write_text(json.dumps(_result_to_dict(result), indent=2))


def export_csv(result: ScanResult, path: str) -> None:
    """
    CSV doesn't map cleanly onto this nested structure, so it flattens to
    one row per finding, with a "category" column distinguishing the kind
    of finding.
    """
    fieldnames = ["category", "name", "severity", "detail"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in result.missing:
            writer.writerow({
                "category": "missing_header",
                "name": finding.rule.name,
                "severity": finding.rule.severity.value,
                "detail": finding.rule.description,
            })

        for b in result.banners:
            writer.writerow({
                "category": "version_leak",
                "name": b.header_name,
                "severity": "MEDIUM",
                "detail": b.value,
            })

        for p in result.exposed_paths:
            writer.writerow({
                "category": "exposed_path",
                "name": p.path,
                "severity": "HIGH",
                "detail": f"HTTP {p.status_code}",
            })
