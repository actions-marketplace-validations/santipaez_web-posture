"""Report rendering."""

from __future__ import annotations

import json
from dataclasses import asdict

from .model import Report, Severity

_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def to_text(report: Report) -> str:
    lines = [f"target  {report.target}", f"score   {report.score()}/100", ""]

    for severity in _ORDER:
        findings = report.by_severity(severity)
        if not findings:
            continue
        lines.append(f"{severity.value.upper()} ({len(findings)})")
        for finding in findings:
            lines.append(f"  [{finding.check}] {finding.title}")
            lines.append(f"    {finding.detail}")
            if finding.remediation:
                lines.append(f"    fix: {finding.remediation}")
        lines.append("")

    if not report.findings:
        lines.append("No findings.")

    return "\n".join(lines).rstrip()


def to_json(report: Report) -> str:
    payload = {
        "target": report.target,
        "score": report.score(),
        "summary": {severity.value: len(report.by_severity(severity)) for severity in _ORDER},
        "findings": [asdict(finding) for finding in report.findings],
    }
    return json.dumps(payload, indent=2)
