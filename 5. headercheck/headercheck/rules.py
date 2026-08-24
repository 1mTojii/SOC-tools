"""
Rule definitions for headercheck.

Each rule describes one security-relevant HTTP response header: what it's
called, why it matters, and how severe it is if missing. This list is
intentionally focused on well-known, broadly-applicable headers -- not
exhaustive, and "missing" doesn't always mean "vulnerable" (some headers
genuinely don't apply to every kind of site/API).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class HeaderRule:
    name: str               # the actual HTTP header name to look for
    severity: Severity
    description: str        # why this header matters
    recommendation: str      # a short example of a good value


HEADER_RULES: list[HeaderRule] = [
    HeaderRule(
        name="Strict-Transport-Security",
        severity=Severity.HIGH,
        description="Without HSTS, browsers may be tricked into connecting over plain HTTP, enabling downgrade/MITM attacks.",
        recommendation="max-age=31536000; includeSubDomains",
    ),
    HeaderRule(
        name="Content-Security-Policy",
        severity=Severity.HIGH,
        description="Without a CSP, the browser has no restriction on which scripts/resources can execute, making XSS far more impactful.",
        recommendation="default-src 'self'",
    ),
    HeaderRule(
        name="X-Frame-Options",
        severity=Severity.MEDIUM,
        description="Without this, the page can be embedded in an iframe on another site, enabling clickjacking attacks.",
        recommendation="DENY or SAMEORIGIN",
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        severity=Severity.MEDIUM,
        description="Without this, browsers may 'sniff' content types, which can lead to serving user-uploaded files as executable scripts.",
        recommendation="nosniff",
    ),
    HeaderRule(
        name="Referrer-Policy",
        severity=Severity.LOW,
        description="Without this, the full URL (including query strings, which may contain sensitive tokens) may leak to third parties via the Referer header.",
        recommendation="strict-origin-when-cross-origin",
    ),
    HeaderRule(
        name="Permissions-Policy",
        severity=Severity.LOW,
        description="Without this, the page has no explicit restriction on browser features (camera, geolocation, etc.) it or embedded content can use.",
        recommendation="geolocation=(), camera=(), microphone=()",
    ),
]

# Paths commonly worth checking for accidental exposure -- source control
# metadata, environment files, backup files, etc. A 200 OK on these is a
# real, concrete finding (unlike a missing header, which is more of a
# hardening suggestion).
SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/.DS_Store",
    "/backup.zip",
    "/.aws/credentials",
]
