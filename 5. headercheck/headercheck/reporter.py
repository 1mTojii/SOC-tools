"""Colored terminal output for headercheck."""

from __future__ import annotations

from .checker import ScanResult
from .rules import Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
RED = "\033[31m"

BANNER = r"""
 _                    _                _               _
| |__   ___  __ _  __| | ___ _ __    ___| |__   ___  ___| | __
| '_ \ / _ \/ _` |/ _` |/ _ \ '__|  / __| '_ \ / _ \/ __| |/ /
| | | |  __/ (_| | (_| |  __/ |    | (__| | | |  __/ (__|   <
|_| |_|\___|\__,_|\__,_|\___|_|     \___|_| |_|\___|\___|_|\_\
        HTTP security header checker
"""

_SEVERITY_COLOR = {
    Severity.LOW: CYAN,
    Severity.MEDIUM: YELLOW,
    Severity.HIGH: ORANGE,
}


def print_banner() -> None:
    print(f"{BOLD}{CYAN}{BANNER}{RESET}")


def print_result(result: ScanResult) -> None:
    print(f"{BOLD}Target: {RESET}{result.url}")

    if result.error:
        print(f"{RED}{BOLD}Could not connect: {RESET}{result.error}")
        return

    print(f"{DIM}HTTP status: {result.status_code}{RESET}\n")

    if result.present_headers:
        print(f"{BOLD}{GREEN}Present security headers:{RESET}")
        for name, value in result.present_headers.items():
            display_value = value if len(value) <= 70 else value[:67] + "..."
            print(f"  {GREEN}\u2713{RESET} {name}: {DIM}{display_value}{RESET}")
        print()

    if result.missing:
        print(f"{BOLD}Missing security headers:{RESET}")
        for finding in result.missing:
            rule = finding.rule
            color = _SEVERITY_COLOR[rule.severity]
            print(f"  {color}{BOLD}[{rule.severity.value:<6}]{RESET} {rule.name}")
            print(f"      {DIM}{rule.description}{RESET}")
            print(f"      {DIM}suggested: {rule.recommendation}{RESET}")
        print()

    if result.banners:
        print(f"{BOLD}{ORANGE}Version-leaking banners:{RESET}")
        for b in result.banners:
            print(f"  {ORANGE}{BOLD}[MEDIUM]{RESET} {b.header_name}: {b.value}")
            print(f"      {DIM}Exposing exact software versions helps attackers find known exploits.{RESET}")
        print()

    if result.exposed_paths:
        print(f"{BOLD}{RED}Exposed sensitive paths:{RESET}")
        for p in result.exposed_paths:
            print(f"  {RED}{BOLD}[HIGH]{RESET} {p.path} -- returned HTTP {p.status_code}")
        print()


def print_summary(result: ScanResult) -> None:
    print(f"{DIM}{'-' * 60}{RESET}")
    if result.error:
        print(f"{BOLD}Scan failed.{RESET}")
    else:
        print(f"{BOLD}Summary{RESET}")
        print(f"  headers present : {len(result.present_headers)}")
        print(f"  headers missing : {len(result.missing)}")
        print(f"  version leaks   : {len(result.banners)}")
        print(f"  exposed paths   : {len(result.exposed_paths)}")
    print(f"{DIM}{'-' * 60}{RESET}")
