"""Passive checks.

Every check reads something the target already publishes: DNS records, TLS
handshakes, response headers, or a single GET to a path that must not be public.
Nothing here exploits a vulnerability, submits a form, or probes a port.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from .model import Finding, Severity
from .transport import DnsResolver, HttpResponse, HttpTransport


@dataclass(frozen=True)
class Deps:
    http: HttpTransport
    dns: DnsResolver
    cert_expiry: Callable[[str], int | None]


@dataclass(frozen=True)
class Target:
    host: str

    @property
    def base(self) -> str:
        return f"https://{self.host}"

    @property
    def plain(self) -> str:
        return f"http://{self.host}"


class Check(Protocol):
    name: str

    def run(self, target: Target, deps: Deps) -> list[Finding]: ...


class DmarcCheck:
    """DMARC is the one policy that tells receivers what to do with mail that
    fails SPF and DKIM. `p=none` asks them to do nothing."""

    name = "dmarc"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        records = [record for record in deps.dns.txt(f"_dmarc.{target.host}") if "v=dmarc1" in record.lower()]

        if not records:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="No DMARC record",
                    detail=f"No _dmarc TXT record on {target.host}. Anyone can send mail as this domain.",
                    remediation="publish v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain",
                )
            ]

        if len(records) > 1:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.MEDIUM,
                    title="Multiple DMARC records",
                    detail=f"{len(records)} records found. Receivers treat an ambiguous policy as no policy.",
                    remediation="keep exactly one _dmarc record",
                )
            ]

        record = records[0].lower()
        findings: list[Finding] = []

        if "p=none" in record:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="DMARC policy is p=none",
                    detail=(
                        "p=none monitors without enforcing. Spoofed mail still reaches recipients, "
                        "so the record documents abuse instead of stopping it."
                    ),
                    remediation="move to p=quarantine once reports look clean, then p=reject",
                )
            )

        if "pct=" in record and "pct=100" not in record:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.MEDIUM,
                    title="DMARC policy applies partially",
                    detail="pct below 100 leaves a share of failing mail unfiltered.",
                    remediation="set pct=100",
                )
            )

        if "rua=" not in record:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.LOW,
                    title="No DMARC aggregate reports",
                    detail="Without rua you cannot see who is sending as this domain.",
                    remediation="add rua=mailto:dmarc@yourdomain",
                )
            )

        return findings


class SpfCheck:
    name = "spf"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        records = [record for record in deps.dns.txt(target.host) if record.lower().startswith("v=spf1")]

        if not records:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.MEDIUM,
                    title="No SPF record",
                    detail="Receivers have no list of hosts allowed to send mail for this domain.",
                    remediation="publish v=spf1 include:yourprovider -all",
                )
            ]

        if len(records) > 1:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="Multiple SPF records",
                    detail="The SPF specification allows one record. Two means receivers fail the check.",
                    remediation="merge into a single record",
                )
            ]

        record = records[0].lower()
        if "+all" in record:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="SPF allows every sender",
                    detail="+all authorises the entire internet to send mail as this domain.",
                    remediation="replace +all with -all after listing the real senders",
                )
            ]

        if "~all" in record:
            return [
                Finding(
                    check=self.name,
                    severity=Severity.LOW,
                    title="SPF uses soft fail",
                    detail="~all marks unauthorised mail as suspicious instead of rejecting it.",
                    remediation="move to -all",
                )
            ]

        return []


class HttpsCheck:
    name = "https"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        findings: list[Finding] = []

        response = deps.http.get(target.plain, follow_redirects=False)
        location = response.headers.get("location", "")
        if response.status >= 300 and location.startswith("https://"):
            pass
        else:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="HTTP does not redirect to HTTPS",
                    detail=f"http://{target.host} answered {response.status} without an HTTPS redirect.",
                    remediation="redirect all HTTP traffic to HTTPS with a 301",
                )
            )

        days = deps.cert_expiry(target.host)
        if days is None:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="TLS handshake failed",
                    detail="The certificate could not be validated from a default trust store.",
                    remediation="renew the certificate and check the chain",
                )
            )
        elif days < 0:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title="Certificate expired",
                    detail=f"The certificate expired {abs(days)} days ago.",
                    remediation="renew immediately",
                )
            )
        elif days < 21:
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.MEDIUM,
                    title="Certificate expires soon",
                    detail=f"{days} days remaining.",
                    remediation="renew before it lapses; automation avoids the outage",
                )
            )

        return findings


SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "No HSTS header",
        "Browsers will happily downgrade to HTTP on the first request.",
        "add Strict-Transport-Security: max-age=31536000",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy",
        "Nothing constrains which scripts may run, so one injected tag executes.",
        "start with a report-only policy, then enforce",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "No X-Content-Type-Options",
        "Browsers may sniff a type different from the one declared.",
        "add X-Content-Type-Options: nosniff",
    ),
    "referrer-policy": (
        Severity.LOW,
        "No Referrer-Policy",
        "Full URLs leak to third parties on outbound links.",
        "add Referrer-Policy: strict-origin-when-cross-origin",
    ),
}


class HeadersCheck:
    name = "headers"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        response = deps.http.get(target.base, follow_redirects=True)
        findings: list[Finding] = []

        for header, (severity, title, detail, remediation) in SECURITY_HEADERS.items():
            if response.headers.get(header):
                continue
            findings.append(
                Finding(
                    check=self.name,
                    severity=severity,
                    title=title,
                    detail=detail,
                    remediation=remediation,
                )
            )

        return findings


class CookieCheck:
    name = "cookies"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        response = deps.http.get(target.base, follow_redirects=True)
        raw = response.headers.get("set-cookie")
        if not raw:
            return []

        lowered = raw.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if not missing:
            return []

        return [
            Finding(
                check=self.name,
                severity=Severity.MEDIUM,
                title="Cookie without protective flags",
                detail=f"Missing: {', '.join(missing)}.",
                remediation="set Secure, HttpOnly and SameSite on every session cookie",
            )
        ]


EXPOSED = {
    "/.git/HEAD": (b"ref:", "A Git repository is served publicly"),
    "/.env": (b"=", "An environment file is served publicly"),
}


class ExposedFilesCheck:
    """One GET per path. It reads the first bytes to confirm the hit is real
    rather than a soft 404 that returns 200 for everything."""

    name = "exposed-files"

    def run(self, target: Target, deps: Deps) -> list[Finding]:
        findings: list[Finding] = []

        for path, (signature, title) in EXPOSED.items():
            response = deps.http.get(f"{target.base}{path}", follow_redirects=False)
            if response.status != 200 or signature not in response.body.lower():
                continue
            findings.append(
                Finding(
                    check=self.name,
                    severity=Severity.HIGH,
                    title=title,
                    detail=f"GET {path} returned 200 with content that matches the real file.",
                    remediation="block dotfiles at the web server and rotate every credential in that file",
                )
            )

        return findings


DEFAULT_CHECKS: tuple[Check, ...] = (
    DmarcCheck(),
    SpfCheck(),
    HttpsCheck(),
    HeadersCheck(),
    CookieCheck(),
    ExposedFilesCheck(),
)
