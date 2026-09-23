"""CSV report with one row per finding."""

from __future__ import annotations

import csv
from io import StringIO

from jwt_analyzer.engine import AnalysisResult
from jwt_analyzer.reporters.base import BaseReporter

_COLUMNS = (
    "id",
    "title",
    "severity",
    "confidence",
    "description",
    "evidence",
    "impact",
    "remediation",
    "references",
    "risk_score",
    "risk_score_max",
)


class CsvReporter(BaseReporter):
    """Spreadsheet rows. The risk score is repeated on every row."""

    format_name = "csv"

    def render(self, result: AnalysisResult) -> str:
        buffer = StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "impact": finding.impact,
                    "remediation": finding.remediation,
                    "references": " ".join(finding.references),
                    "risk_score": result.risk.score,
                    "risk_score_max": result.risk.maximum,
                }
            )
        return buffer.getvalue()
