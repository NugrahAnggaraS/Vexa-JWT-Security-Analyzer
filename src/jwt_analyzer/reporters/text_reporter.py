"""Terminal report with optional severity colors."""

from __future__ import annotations

from jwt_analyzer.engine import AnalysisResult, DISCLAIMER
from jwt_analyzer.findings import Severity
from jwt_analyzer.reporters.base import BaseReporter

_SEVERITY_COLOR = {
    Severity.CRITICAL: 31,
    Severity.HIGH: 31,
    Severity.MEDIUM: 33,
    Severity.LOW: 36,
    Severity.INFO: 37,
}


class TextReporter(BaseReporter):
    """Readable console report."""

    format_name = "text"

    def __init__(self, *, color: bool = False) -> None:
        self.color = color

    def render(self, result: AnalysisResult) -> str:
        meta = result.token.metadata
        lines = [
            "JWT Security Analyzer",
            "────────────────────────────────────────",
            "",
            "Token Information",
            "────────────────────────────────────────",
            f"Algorithm  : {_display(meta.alg)}",
            f"Type       : {_display(meta.typ)}",
            f"Key ID     : {_display(meta.kid)}",
            f"Issuer     : {_display(meta.iss)}",
            f"Subject    : {_display(meta.sub)}",
            f"Audience   : {_display_aud(meta.aud)}",
            f"Expiration : {_display(meta.exp)}",
            "",
            "Security Findings",
            "────────────────────────────────────────",
            "",
        ]
        if not result.findings:
            lines.append("No security findings")
        for finding in result.findings:
            label = _paint(f"[{finding.severity.value}]", _SEVERITY_COLOR[finding.severity], self.color)
            lines.extend(
                [
                    f"{label} {finding.id}",
                    finding.title,
                    f"Confidence: {finding.confidence.value}",
                    f"Description: {finding.description}",
                    f"Evidence: {finding.evidence}",
                    f"Impact: {finding.impact}",
                    f"Remediation: {finding.remediation}",
                    "",
                ]
            )
        lines.extend(
            [
                "Summary",
                "────────────────────────────────────────",
                f"Total Findings : {result.risk.total}",
                "",
            ]
        )
        for severity in Severity:
            lines.append(f"{severity.value:<10} : {result.risk.count(severity)}")
        lines.extend(
            [
                "",
                f"Risk Score : {result.risk.score}/{result.risk.maximum}",
                DISCLAIMER,
            ]
        )
        return "\n".join(lines)


def _display(value: object) -> str:
    return "-" if value is None else str(value)


def _display_aud(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(value) if value else "-"
    return str(value)


def _paint(value: str, code: int, enabled: bool) -> str:
    if not enabled:
        return value
    return f"\033[{code}m{value}\033[0m"
