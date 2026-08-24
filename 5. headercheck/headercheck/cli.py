"""
headercheck CLI -- an HTTP security header checker.

Usage:
    python -m headercheck.cli --url https://example.com
    python -m headercheck.cli --url example.com --no-path-check
    python -m headercheck.cli --url https://example.com --json out.json --csv out.csv
    python -m headercheck.cli --url https://self-signed.example --no-verify-tls
"""

from __future__ import annotations

import argparse
import sys

from .checker import scan_url
from .exporter import export_csv, export_json
from .reporter import print_banner, print_result, print_summary


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="headercheck",
        description="Checks a URL's HTTP response for missing security headers and common misconfigurations.",
    )
    p.add_argument("--url", required=True, help="Target URL (scheme optional, defaults to https://)")
    p.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0)")
    p.add_argument("--no-path-check", action="store_true", help="Skip probing for exposed sensitive paths (faster)")
    p.add_argument("--no-verify-tls", action="store_true", help="Disable TLS certificate verification (for self-signed test targets)")
    p.add_argument("--json", metavar="PATH", help="Export results to a JSON file")
    p.add_argument("--csv", metavar="PATH", help="Export results to a CSV file")
    p.add_argument("--quiet", action="store_true", help="Suppress the banner")
    return p


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.quiet:
        print_banner()

    result = scan_url(
        url=args.url,
        timeout=args.timeout,
        verify_tls=not args.no_verify_tls,
        check_paths=not args.no_path_check,
    )

    print_result(result)
    print_summary(result)

    if args.json:
        export_json(result, args.json)
        print(f"Wrote JSON export -> {args.json}")
    if args.csv:
        export_csv(result, args.csv)
        print(f"Wrote CSV export -> {args.csv}")

    return 1 if result.error else 0


if __name__ == "__main__":
    sys.exit(run())
