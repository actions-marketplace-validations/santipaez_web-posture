# web-posture

[![tests](https://github.com/santipaez/web-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/santipaez/web-posture/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Passive security posture checks for a web domain: mail policy, TLS, security headers,
cookie flags and files that should never be served.

It stays inside what a site already publishes to anyone. No exploitation, no port
scanning, no fuzzing, no payloads. That boundary is the point, and the tool enforces it.

```
$ python -m posture acme-shop.example --authorized --reason "my own domain"

target  acme-shop.example
score   49/100

HIGH (1)
  [dmarc] No DMARC record
    No _dmarc TXT record on acme-shop.example. Anyone can send mail as this domain.
    fix: publish v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain
...
```

## The finding worth knowing about

`p=none` is the most common DMARC configuration and the most misunderstood. It does not
block anything: it tells the receiving server to deliver the mail and report back. A
domain with `p=none` and no SPF is fully spoofable, and the record makes it look
protected.

```
v=DMARC1; p=none; rua=mailto:dmarc@example.com   # monitoring, not protection
v=DMARC1; p=quarantine; pct=100; rua=...         # suspicious mail goes to spam
v=DMARC1; p=reject; pct=100; rua=...             # spoofed mail is refused
```

The tool reports `p=none` as high severity, `pct` below 100 as medium, and missing
aggregate reports as low.

## What it checks

| Check | Reads | Reported when |
|---|---|---|
| `dmarc` | `_dmarc` TXT record | missing, `p=none`, `pct<100`, no `rua` |
| `spf` | domain TXT record | missing, `+all`, duplicate records, `~all` |
| `https` | one HTTP request, TLS handshake | no HTTPS redirect, expired or expiring certificate |
| `headers` | response headers | missing HSTS, CSP, `nosniff`, referrer policy |
| `cookies` | `Set-Cookie` | missing `Secure`, `HttpOnly` or `SameSite` |
| `exposed-files` | one GET to `/.git/HEAD` and `/.env` | 200 with content that matches the real file |

Each check also returns the fix, because a finding without a remediation is noise.

## Use it as a GitHub Action

The same checks run on every deploy, and the job fails when something high severity
appears:

```yaml
name: posture
on:
  deployment_status:
  schedule:
    - cron: "0 6 * * 1"

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: santipaez/web-posture@v1
        with:
          domain: acme-shop.example
          authorized: "true"          # required: the action refuses without it
          reason: "my own production domain"
          delay: "0.5"
```

The `authorized` input is enforced before anything else runs. A scheduled weekly check is
the useful default: mail policy and certificates drift, and nobody notices until a
certificate expires or a DMARC record is edited.

## Authorization

The tool refuses to run without an explicit flag:

```
$ python -m posture example.com
error: Refusing to scan. Pass --authorized only for a host you own or have written
permission to test.

$ python -m posture example.com --authorized
error: --reason is required: record who authorised this scan.
```

The reason is printed in the output, so a saved report says who approved the run. This is
not paperwork: probing a host you do not control is unauthorised testing, and the
difference between a posture check and an incident report is one signature.

## Quickstart

```bash
git clone https://github.com/santipaez/web-posture && cd web-posture
python -m unittest discover -s tests           # 23 tests, standard library only
python -m posture yourdomain.com --authorized --reason "my own domain"
python -m posture yourdomain.com --authorized --reason "owner" --json
```

Exit codes: `0` no high findings, `1` at least one high finding, `2` refused to start.
That makes it usable as a gate in a pipeline.

## Design notes

**Transports are protocols.** `HttpTransport` and `DnsResolver` are injected, so every
check runs against a fake in tests. No network access, no flaky suite, and the check
logic is tested independently from the I/O.

**Pacing is explicit.** Requests are spaced by `--delay`, defaulting to half a second. A
tight loop across many hosts looks like an attack from the receiving side, and a tool
that encourages it is a liability for whoever runs it.

**Soft 404s are not findings.** A server that returns 200 for every path would otherwise
report every file as exposed. The check reads the first bytes and matches the file's real
structure before claiming anything.

**Scoring is coarse.** 100 minus a fixed penalty per finding. It is a signal for tracking
one domain over time, not a compliance rating, and it should not be read as one.

## Limitations

- No active testing by design. It will not find injection, authentication flaws or
  business logic bugs, and it does not pretend to.
- DNS is read through the system resolver, so TXT parsing depends on `nslookup` output.
  A native resolver is the first thing to add.
- DKIM is not verified: selectors have to be known in advance, and guessing them would
  cross into probing.
- TLS is assessed by version and expiry only. Cipher suites and certificate transparency
  are out of scope for this version.
- Aggregated DMARC reports are mentioned as a missing control but not parsed.

## Layout

```
posture/
  model.py      findings, severities and scoring
  transport.py  HTTP and DNS behind protocols, real implementations
  checks.py     one check per concern, each returning findings and fixes
  scan.py       orchestration, pacing and the authorization gate
  render.py     text and JSON output
  __main__.py   command line entry point
tests/          23 unit tests, all offline
```

MIT licensed. Use it on infrastructure you own or are authorised to test.
