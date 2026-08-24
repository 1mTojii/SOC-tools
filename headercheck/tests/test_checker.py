import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from headercheck.checker import check_headers
from headercheck.rules import Severity


def test_detects_all_present_headers():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    present, missing, banners = check_headers(headers)
    assert len(present) == 6
    assert len(missing) == 0


def test_detects_all_missing_headers():
    headers = {"Content-Type": "text/html"}
    present, missing, banners = check_headers(headers)
    assert len(present) == 0
    assert len(missing) == 6


def test_header_lookup_is_case_insensitive():
    headers = {"strict-transport-security": "max-age=100", "x-FRAME-options": "DENY"}
    present, missing, banners = check_headers(headers)
    assert len(present) == 2
    assert len(missing) == 4


def test_detects_version_leaking_banner():
    headers = {"Server": "Apache/2.4.29 (Ubuntu)"}
    present, missing, banners = check_headers(headers)
    assert len(banners) == 1
    assert banners[0].header_name == "Server"


def test_bare_server_name_without_version_not_flagged():
    # No digits in the value -- shouldn't be treated as a version leak
    headers = {"Server": "nginx"}
    present, missing, banners = check_headers(headers)
    assert len(banners) == 0


def test_missing_findings_have_correct_severity():
    headers = {}
    present, missing, banners = check_headers(headers)
    hsts_finding = next(f for f in missing if f.rule.name == "Strict-Transport-Security")
    assert hsts_finding.rule.severity == Severity.HIGH

    referrer_finding = next(f for f in missing if f.rule.name == "Referrer-Policy")
    assert referrer_finding.rule.severity == Severity.LOW


if __name__ == "__main__":
    test_detects_all_present_headers()
    test_detects_all_missing_headers()
    test_header_lookup_is_case_insensitive()
    test_detects_version_leaking_banner()
    test_bare_server_name_without_version_not_flagged()
    test_missing_findings_have_correct_severity()
    print("All tests passed.")
