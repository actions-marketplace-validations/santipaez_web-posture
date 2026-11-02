"""Command line entry point.

    python -m posture example.com --authorized --reason "my own domain"
"""

from __future__ import annotations

import argparse
import sys

from .checks import DEFAULT_CHECKS, Deps, Target
from .model import Severity
from .render import to_json, to_text
from .scan import AuthorizationError, Scanner, require_authorization
from .transport import SystemResolver, UrllibTransport, certificate_expiry_days


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="posture", description="Passive web security posture check.")
    parser.add_argument("domain", help="host to check, for example example.com")
    parser.add_argument("--authorized", action="store_true", help="confirm you own the host or have written permission")
    parser.add_argument("--reason", default="", help="who authorised this scan; recorded in the output")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--delay", type=float, default=0.5, help="seconds between checks")
    args = parser.parse_args(argv)

    try:
        reason = require_authorization(args.authorized, args.reason)
    except AuthorizationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    deps = Deps(http=UrllibTransport(), dns=SystemResolver(), cert_expiry=certificate_expiry_days)
    scanner = Scanner(checks=DEFAULT_CHECKS, deps=deps, delay=args.delay)
    report = scanner.scan(Target(host=args.domain))

    if args.json:
        print(to_json(report))
    else:
        print(f"authorized by  {reason}\n")
        print(to_text(report))

    return 1 if report.by_severity(Severity.HIGH) else 0


if __name__ == "__main__":
    raise SystemExit(main())
