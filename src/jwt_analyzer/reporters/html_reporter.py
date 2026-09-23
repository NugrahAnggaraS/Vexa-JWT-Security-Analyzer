"""Self-contained HTML report for an assessment appendix."""

from __future__ import annotations

import html
import json

from jwt_analyzer.engine import DISCLAIMER, AnalysisResult
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.reporters.base import BaseReporter

_STYLE = """
body { font-family: Georgia, "Times New Roman", serif; margin: 2rem auto; max-width: 52rem; color: #1c1917; background: #fafaf9; }
h1, h2, h3 { font-family: "Segoe UI", sans-serif; }
header { border-bottom: 3px solid #1c1917; margin-bottom: 1.5rem; }
.score { font-size: 1.4rem; font-weight: 700; }
.disclaimer { color: #44403c; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #d6d3d1; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #e7e5e4; }
article { border: 1px solid #d6d3d1; background: white; padding: 1rem; margin: 1rem 0; }
.CRITICAL, .HIGH { color: #991b1b; }
.MEDIUM { color: #a16207; }
.LOW { color: #0f766e; }
pre { white-space: pre-wrap; word-break: break-word; background: #f5f5f4; padding: 0.8rem; }
"""


class HtmlReporter(BaseReporter):
    """One HTML file with no external stylesheets, scripts, or images."""

    format_name = "html"

    def render(self, result: AnalysisResult) -> str:
        meta = result.token.metadata
        rows = "\n".join(
            f"<tr><th>{severity.value}</th><td>{result.risk.count(severity)}</td></tr>"
            for severity in Severity
        )
        findings = "\n".join(_finding_article(index, finding) for index, finding in enumerate(result.findings, start=1))
        if not findings:
            findings = "<p>No security findings.</p>"
        technical = html.escape(json.dumps(result.token.to_dict(), indent=2, ensure_ascii=False))
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JWT Security Report</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
<h1>JWT Security Report</h1>
</header>
<section id="executive-summary">
<h2>Executive Summary</h2>
<p>Total Findings : {result.risk.total}</p>
<table>
<thead><tr><th>Severity</th><th>Count</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p class="score">Risk Score : {result.risk.score}/{result.risk.maximum}</p>
<p class="disclaimer">{html.escape(DISCLAIMER)}</p>
</section>
<section id="token-information">
<h2>Token Information</h2>
<table>
<tbody>
<tr><th>Algorithm</th><td>{_cell(meta.alg)}</td></tr>
<tr><th>Type</th><td>{_cell(meta.typ)}</td></tr>
<tr><th>Key ID</th><td>{_cell(meta.kid)}</td></tr>
<tr><th>Issuer</th><td>{_cell(meta.iss)}</td></tr>
<tr><th>Subject</th><td>{_cell(meta.sub)}</td></tr>
<tr><th>Audience</th><td>{_cell(_audience(meta.aud))}</td></tr>
<tr><th>Expiration</th><td>{_cell(meta.exp)}</td></tr>
</tbody>
</table>
</section>
<section id="security-findings">
<h2>Security Findings</h2>
{findings}
</section>
<section id="technical-details">
<h2>Technical Details</h2>
<pre>{technical}</pre>
</section>
</body>
</html>
"""


def _finding_article(index: int, finding: Finding) -> str:
    references = ", ".join(html.escape(ref) for ref in finding.references) or "-"
    severity = html.escape(finding.severity.value)
    return f"""<article id="finding-{index}">
<h3>{html.escape(finding.id)} {html.escape(finding.title)}</h3>
<p>Severity: <strong class="{severity}">{severity}</strong></p>
<p>Confidence: {html.escape(finding.confidence.value)}</p>
<p>{html.escape(finding.description)}</p>
<h4>Evidence</h4>
<p>{html.escape(finding.evidence)}</p>
<h4>Impact</h4>
<p>{html.escape(finding.impact)}</p>
<h4>Recommendation</h4>
<p>{html.escape(finding.remediation)}</p>
<h4>References</h4>
<p>{references}</p>
</article>"""


def _cell(value: object) -> str:
    if value is None:
        return "-"
    return html.escape(str(value))


def _audience(value: object) -> object:
    if isinstance(value, list):
        return ", ".join(value)
    return value
