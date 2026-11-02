"""Scan orchestration and the authorization gate."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .checks import Check, Deps, Target
from .model import Report


class AuthorizationError(RuntimeError):
    """Raised when a scan is started without an explicit authorization flag."""


def require_authorization(authorized: bool, reason: str) -> str:
    """The flag is not decoration. Scanning a host you do not control is what
    turns a posture check into unauthorised probing, and the reason ends up in
    the output so the run is auditable after the fact."""
    if not authorized:
        raise AuthorizationError(
            "Refusing to scan. Pass --authorized only for a host you own or have "
            "written permission to test."
        )
    if not reason.strip():
        raise AuthorizationError("--reason is required: record who authorised this scan.")
    return reason.strip()


@dataclass
class Scanner:
    checks: Sequence[Check]
    deps: Deps
    delay: float = 0.5
    sleep: Callable[[float], None] = time.sleep

    def scan(self, target: Target) -> Report:
        findings = []
        for index, check in enumerate(self.checks):
            if index and self.delay:
                # Pacing between checks. A tight loop across many hosts is
                # indistinguishable from an attack on the receiving side.
                self.sleep(self.delay)
            findings.extend(check.run(target, self.deps))
        return Report(target=target.host, findings=tuple(findings))
