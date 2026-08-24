"""
Core logic for headercheck.

Three things happen against a target URL:
  1. Fetch the response headers and check which security headers are present
  2. Look at the Server/X-Powered-By headers for version-string leakage
  3. Probe a short list of commonly-exposed sensitive paths
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .rules import HEADER_RULES, SENSITIVE_PATHS, HeaderRule, Severity


@dataclass
class MissingHeaderFinding:
    rule: HeaderRule


@dataclass
class BannerFinding:
    header_name: str
    value: str


@dataclass
class ExposedPathFinding:
    path: str
    status_code: int


@dataclass
class ScanResult:
    url: str
    status_code: int | None = None
    present_headers: dict = field(default_factory=dict)
    missing: list[MissingHeaderFinding] = field(default_factory=list)
    banners: list[BannerFinding] = field(default_factory=list)
    exposed_paths: list[ExposedPathFinding] = field(default_factory=list)
    error: str | None = None


def _make_request(url: str, timeout: float) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "headercheck/1.0"})


def _fetch_headers(url: str, timeout: float, verify_tls: bool) -> tuple[int, dict]:
    """Returns (status_code, headers_dict). Raises on network failure."""
    ctx = None
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = _make_request(url, timeout)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        headers = {k: v for k, v in resp.getheaders()}
        return resp.status, headers


def check_headers(headers: dict) -> tuple[dict, list[MissingHeaderFinding], list[BannerFinding]]:
    """
    Checks the given header dict against the known rule set.
    Returns (present_headers_matched, missing_findings, banner_findings).
    Header lookups are case-insensitive since HTTP header names are.
    """
    # Normalize keys to lowercase for case-insensitive lookup, but keep
    # original casing for display.
    lower_map = {k.lower(): (k, v) for k, v in headers.items()}

    present = {}
    missing = []
    for rule in HEADER_RULES:
        key = rule.name.lower()
        if key in lower_map:
            original_key, value = lower_map[key]
            present[original_key] = value
        else:
            missing.append(MissingHeaderFinding(rule=rule))

    banners = []
    for banner_header in ("server", "x-powered-by"):
        if banner_header in lower_map:
            original_key, value = lower_map[banner_header]
            # A bare "nginx" or "Apache" isn't very interesting -- what's
            # notable is a header that includes a specific version number,
            # since that tells an attacker exactly what to look up exploits
            # for. A simple heuristic: does it contain a digit?
            if any(ch.isdigit() for ch in value):
                banners.append(BannerFinding(header_name=original_key, value=value))

    return present, missing, banners


def check_sensitive_paths(base_url: str, timeout: float, verify_tls: bool) -> list[ExposedPathFinding]:
    """Probes a short list of commonly-exposed sensitive paths."""
    findings = []
    ctx = None
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    for path in SENSITIVE_PATHS:
        full_url = urljoin(base_url, path)
        try:
            req = _make_request(full_url, timeout)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    findings.append(ExposedPathFinding(path=path, status_code=resp.status))
        except urllib.error.HTTPError as e:
            # 404/403/etc. are the expected, "good" outcome here -- not an error.
            continue
        except (urllib.error.URLError, TimeoutError, OSError):
            continue

    return findings


def scan_url(url: str, timeout: float = 5.0, verify_tls: bool = True, check_paths: bool = True) -> ScanResult:
    """Runs the full check suite against a single URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = ScanResult(url=url)

    try:
        status, headers = _fetch_headers(url, timeout, verify_tls)
    except urllib.error.HTTPError as e:
        # Still got a real response with headers, just a non-2xx status.
        status = e.code
        headers = dict(e.headers.items()) if e.headers else {}
        result.status_code = status
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        result.error = str(e)
        return result
    else:
        result.status_code = status

    present, missing, banners = check_headers(headers)
    result.present_headers = present
    result.missing = missing
    result.banners = banners

    if check_paths:
        result.exposed_paths = check_sensitive_paths(url, timeout, verify_tls)

    return result
