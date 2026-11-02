"""HTTP and DNS access, behind protocols so checks can run against fakes."""

from __future__ import annotations

import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

USER_AGENT = "web-posture/0.1 (passive security posture check)"
TIMEOUT = 10


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpTransport(Protocol):
    def get(self, url: str, *, follow_redirects: bool = False) -> HttpResponse: ...


class UrllibTransport:
    """One request per call, no retries, no redirects unless asked. A scan that
    hammers a host is indistinguishable from an attack, so pacing lives in the
    caller."""

    def __init__(self, timeout: int = TIMEOUT) -> None:
        self._timeout = timeout
        self._plain = urllib.request.build_opener(NoRedirect)
        self._following = urllib.request.build_opener()

    def get(self, url: str, *, follow_redirects: bool = False) -> HttpResponse:
        opener = self._following if follow_redirects else self._plain
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(request, timeout=self._timeout) as response:
                return HttpResponse(
                    url=response.geturl(),
                    status=response.status,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=response.read(4096),
                )
        except urllib.error.HTTPError as error:
            return HttpResponse(
                url=url,
                status=error.code,
                headers={key.lower(): value for key, value in (error.headers or {}).items()},
                body=b"",
            )


class DnsResolver(Protocol):
    def txt(self, name: str) -> list[str]: ...


class SystemResolver:
    """Uses the system resolver through nslookup, which keeps the tool free of
    dependencies at the cost of parsing text output."""

    def txt(self, name: str) -> list[str]:
        try:
            output = subprocess.run(
                ["nslookup", "-type=TXT", name],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return []

        records: list[str] = []
        chunks: list[str] = []
        for line in output.splitlines():
            if "text =" not in line.lower():
                continue
            value = line.split("=", 1)[1].strip().strip('"')
            if value.startswith('"') or chunks:
                chunks.append(value.strip('"'))
                if value.endswith('"'):
                    records.append("".join(chunks))
                    chunks = []
            else:
                records.append(value.strip('"'))
        return records


def certificate_expiry_days(host: str, port: int = 443) -> int | None:
    """Days until the certificate expires, or None when the handshake fails."""
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(
            __import__("socket").create_connection((host, port), timeout=TIMEOUT),
            server_hostname=host,
        ) as tls:
            certificate = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return None

    not_after = certificate.get("notAfter") if certificate else None
    if not not_after:
        return None

    import time

    remaining = ssl.cert_time_to_seconds(not_after) - time.time()
    return int(remaining // 86400)
