import unittest

from posture import (
    AuthorizationError,
    CookieCheck,
    Deps,
    DmarcCheck,
    ExposedFilesCheck,
    HeadersCheck,
    HttpsCheck,
    Scanner,
    Severity,
    SpfCheck,
    Target,
    require_authorization,
)
from posture.transport import HttpResponse

TARGET = Target(host="example.com")


class FakeHttp:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get(self, url: str, *, follow_redirects: bool = False) -> HttpResponse:
        self.calls.append(url)
        return self._responses.get(url, HttpResponse(url=url, status=404, headers={}, body=b""))


class FakeDns:
    def __init__(self, records: dict[str, list[str]]) -> None:
        self._records = records

    def txt(self, name: str) -> list[str]:
        return self._records.get(name, [])


def deps(http: FakeHttp | None = None, dns: FakeDns | None = None, expiry: int | None = 400) -> Deps:
    return Deps(
        http=http or FakeHttp({}),
        dns=dns or FakeDns({}),
        cert_expiry=lambda host: expiry,
    )


class DmarcTests(unittest.TestCase):
    def test_missing_record_is_high(self):
        findings = DmarcCheck().run(TARGET, deps())
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].title, "No DMARC record")

    def test_p_none_is_high(self):
        dns = FakeDns({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:a@example.com"]})
        findings = DmarcCheck().run(TARGET, deps(dns=dns))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("p=none", findings[0].title)

    def test_enforced_policy_with_reports_is_clean(self):
        dns = FakeDns({"_dmarc.example.com": ["v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com"]})
        self.assertEqual(DmarcCheck().run(TARGET, deps(dns=dns)), [])

    def test_partial_policy_and_missing_reports_are_reported(self):
        dns = FakeDns({"_dmarc.example.com": ["v=DMARC1; p=reject; pct=25"]})
        findings = DmarcCheck().run(TARGET, deps(dns=dns))
        self.assertEqual({finding.title for finding in findings}, {
            "DMARC policy applies partially",
            "No DMARC aggregate reports",
        })


class SpfTests(unittest.TestCase):
    def test_missing_record(self):
        self.assertEqual(SpfCheck().run(TARGET, deps())[0].severity, Severity.MEDIUM)

    def test_plus_all_is_high(self):
        dns = FakeDns({"example.com": ["v=spf1 +all"]})
        findings = SpfCheck().run(TARGET, deps(dns=dns))
        self.assertEqual(findings[0].title, "SPF allows every sender")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_duplicate_records(self):
        dns = FakeDns({"example.com": ["v=spf1 -all", "v=spf1 include:x -all"]})
        self.assertEqual(SpfCheck().run(TARGET, deps(dns=dns))[0].severity, Severity.HIGH)

    def test_hard_fail_record_is_clean(self):
        dns = FakeDns({"example.com": ["v=spf1 include:_spf.example.net -all"]})
        self.assertEqual(SpfCheck().run(TARGET, deps(dns=dns)), [])


class HttpsTests(unittest.TestCase):
    def test_missing_redirect_is_high(self):
        http = FakeHttp({"http://example.com": HttpResponse("http://example.com", 200, {}, b"")})
        findings = HttpsCheck().run(TARGET, deps(http=http))
        self.assertIn("HTTP does not redirect to HTTPS", {finding.title for finding in findings})

    def test_redirect_present_and_certificate_healthy(self):
        http = FakeHttp({
            "http://example.com": HttpResponse("http://example.com", 301, {"location": "https://example.com/"}, b""),
        })
        self.assertEqual(HttpsCheck().run(TARGET, deps(http=http)), [])

    def test_expiring_certificate_is_medium(self):
        http = FakeHttp({
            "http://example.com": HttpResponse("http://example.com", 301, {"location": "https://example.com/"}, b""),
        })
        findings = HttpsCheck().run(TARGET, deps(http=http, expiry=7))
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_failed_handshake_is_high(self):
        http = FakeHttp({
            "http://example.com": HttpResponse("http://example.com", 301, {"location": "https://example.com/"}, b""),
        })
        findings = HttpsCheck().run(TARGET, deps(http=http, expiry=None))
        self.assertEqual(findings[0].title, "TLS handshake failed")


class HeadersTests(unittest.TestCase):
    def test_all_headers_present_is_clean(self):
        http = FakeHttp({
            "https://example.com": HttpResponse("https://example.com", 200, {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            }, b""),
        })
        self.assertEqual(HeadersCheck().run(TARGET, deps(http=http)), [])

    def test_missing_headers_are_reported(self):
        http = FakeHttp({"https://example.com": HttpResponse("https://example.com", 200, {}, b"")})
        findings = HeadersCheck().run(TARGET, deps(http=http))
        self.assertEqual(len(findings), 4)


class CookieTests(unittest.TestCase):
    def test_cookie_without_flags(self):
        http = FakeHttp({
            "https://example.com": HttpResponse("https://example.com", 200, {"set-cookie": "session=abc; Path=/"}, b""),
        })
        findings = CookieCheck().run(TARGET, deps(http=http))
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("secure", findings[0].detail)

    def test_cookie_with_all_flags_is_clean(self):
        http = FakeHttp({
            "https://example.com": HttpResponse("https://example.com", 200, {
                "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
            }, b""),
        })
        self.assertEqual(CookieCheck().run(TARGET, deps(http=http)), [])


class ExposedFilesTests(unittest.TestCase):
    def test_real_git_head_is_high(self):
        http = FakeHttp({
            "https://example.com/.git/HEAD": HttpResponse("https://example.com/.git/HEAD", 200, {}, b"ref: refs/heads/main\n"),
        })
        findings = ExposedFilesCheck().run(TARGET, deps(http=http))
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("/.git/HEAD", findings[0].detail)

    def test_soft_404_is_not_a_finding(self):
        http = FakeHttp({
            "https://example.com/.git/HEAD": HttpResponse("https://example.com/.git/HEAD", 200, {}, b"<html>not found</html>"),
        })
        self.assertEqual(ExposedFilesCheck().run(TARGET, deps(http=http)), [])


class AuthorizationTests(unittest.TestCase):
    def test_refuses_without_flag(self):
        with self.assertRaises(AuthorizationError):
            require_authorization(False, "my domain")

    def test_refuses_without_reason(self):
        with self.assertRaises(AuthorizationError):
            require_authorization(True, "   ")

    def test_returns_reason(self):
        self.assertEqual(require_authorization(True, "my domain"), "my domain")


class ScannerTests(unittest.TestCase):
    def test_paces_between_checks(self):
        waits: list[float] = []
        scanner = Scanner(checks=(DmarcCheck(), SpfCheck(), SpfCheck()), deps=deps(), delay=0.5, sleep=waits.append)
        scanner.scan(TARGET)
        self.assertEqual(waits, [0.5, 0.5])

    def test_collects_findings_from_every_check(self):
        scanner = Scanner(checks=(DmarcCheck(), SpfCheck()), deps=deps(), delay=0, sleep=lambda _: None)
        report = scanner.scan(TARGET)
        self.assertEqual(len(report.findings), 2)
        self.assertLess(report.score(), 100)


if __name__ == "__main__":
    unittest.main()
