# headercheck

An HTTP security header checker. Points at a URL, reports which standard
security headers are present/missing, flags version-leaking `Server`/
`X-Powered-By` banners, and probes for a short list of commonly-exposed
sensitive paths (`.git`, `.env`, backup files, etc.).

## How it works

Three checks run against the target:

1. **Header presence** — fetches the response and checks for six
   well-known security headers (HSTS, CSP, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Permissions-Policy), each with
   a severity level and a short explanation of what it protects against.
2. **Version leakage** — looks at `Server`/`X-Powered-By` for values that
   contain a version number (e.g. `Apache/2.4.29`) rather than just a bare
   product name — the version number is what actually helps an attacker
   look up known exploits.
3. **Exposed sensitive paths** — makes a request to a short list of paths
   that shouldn't normally be reachable (`/.git/HEAD`, `/.env`, backup
   files, etc.) and flags any that return `200 OK`.

**Important:** a missing header is a hardening suggestion, not proof of a
vulnerability — plenty of APIs and internal tools reasonably skip some of
these. An exposed `.git`/`.env` path returning real content is a much more
concrete finding.

## Usage

```bash
python -m headercheck.cli --url https://example.com

# Skip the sensitive-path probing (faster, less noisy against a target)
python -m headercheck.cli --url example.com --no-path-check

# Export results
python -m headercheck.cli --url https://example.com --json out.json --csv out.csv

# Testing against a self-signed/local target
python -m headercheck.cli --url https://localhost:8443 --no-verify-tls
```

## Sample output

```
Missing security headers:
  [HIGH  ] Strict-Transport-Security
      Without HSTS, browsers may be tricked into connecting over plain HTTP, enabling downgrade/MITM attacks.
      suggested: max-age=31536000; includeSubDomains

Version-leaking banners:
  [MEDIUM] Server: Apache/2.4.29 (Ubuntu)
      Exposing exact software versions helps attackers find known exploits.

Exposed sensitive paths:
  [HIGH] /.git/HEAD -- returned HTTP 200

------------------------------------------------------------
Summary
  headers present : 2
  headers missing : 4
  version leaks   : 1
  exposed paths   : 1
------------------------------------------------------------
```

## Project structure

```
headercheck/
├── headercheck/
│   ├── rules.py      # header definitions + sensitive path list
│   ├── checker.py     # core fetching + checking logic
│   ├── reporter.py   # colored terminal output
│   ├── exporter.py   # JSON/CSV export
│   └── cli.py         # argument parsing & orchestration
└── tests/
    └── test_checker.py
```

## Running tests

```bash
python tests/test_checker.py
```

## A note on scope and legality

The sensitive-path checks only make plain GET requests to paths on the
target you specify — no exploitation, no brute-forcing beyond that short
fixed list. Still, only run this against sites you own or have permission
to test, same rule as the other tools in this repo — probing a site you
don't control, even non-destructively, can look like reconnaissance for an
attack and isn't something to do without authorization.

## Why this exists

A different angle on defensive tooling than the other projects here —
BruteSentry and the port scanners deal with network-level/log-level
signals, this one deals with application-layer HTTP configuration, which
is a very common, very real thing security teams audit (missing security
headers show up constantly in real pentest reports). AI-assisted build;
understood and tested by me against real sites and a deliberately
misconfigured local test server.

## Ideas for extending it

- Add more headers to the rule set (e.g. `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`)
- Check cookie flags (`Secure`, `HttpOnly`, `SameSite`) on any `Set-Cookie` headers
- Follow redirects and report on the full redirect chain instead of just the final response
- Batch mode — read a list of URLs from a file and scan all of them

## License

MIT
