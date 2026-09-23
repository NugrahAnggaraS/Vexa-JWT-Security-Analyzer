"""Markdown report."""

from __future__ import annotations

from jwt_analyzer.engine import DISCLAIMER, AnalysisResult
from jwt_analyzer.findings import Severity
from jwt_analyzer.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Markdown document with the same sections as the HTML report."""

    format_name = "markdown"

    def render(self, result: AnalysisResult) -> str:
        meta = result.token.metadata
        lines = [
            "# JWT Security Report",
            "",
            "## Executive Summary",
            "",
            f"Total Findings : {result.risk.total}",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for severity in Severity:
            lines.append(f"| {severity.value} | {result.risk.count(severity)} |")
        lines.extend(
            [
                "",
                f"**Risk Score : {result.risk.score}/{result.risk.maximum}**",
                "",
                DISCLAIMER,
                "",
                "## Token Information",
                "",
                f"- Algorithm: {_md(meta.alg)}",
                f"- Type: {_md(meta.typ)}",
                f"- Key ID: {_md(meta.kid)}",
                f"- Issuer: {_md(meta.iss)}",
                f"- Subject: {_md(meta.sub)}",
                f"- Audience: {_md(_audience(meta.aud))}",
                f"- Expiration: {_md(meta.exp)}",
                "",
                "## Security Findings",
                "",
            ]
        )
        if not result.findings:
            lines.append("No security findings.")
        for finding in result.findings:
            lines.extend(
                [
                    f"### {finding.id} {finding.title}",
                    "",
                    f"- Severity: {finding.severity.value}",
                    f"- Confidence: {finding.confidence.value}",
                    "",
                    finding.description,
                    "",
                    "#### Evidence",
                    "",
                    finding.evidence,
                    "",
                    "#### Impact",
                    "",
                    finding.impact,
                    "",
                    "#### Recommendation",
                    "",
                    finding.remediation,
                    "",
                ]
            )
        lines.extend(["## Technical Details", "", "See the JSON report for the machine-readable token document.", ""])
        return "\n".join(lines)


def _md(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value).replace("\n", " ")


def _audience(value: object) -> object:
    if isinstance(value, list):
        return ", ".join(value)
    return value
