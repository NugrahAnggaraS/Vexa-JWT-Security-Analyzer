"""Unit tests for the finding engine, risk score, and report formats."""

from __future__ import annotations

import base64
import csv
import json
from io import StringIO
from typing import Any

import pytest

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.engine import (
    AnalysisConfig,
    AnalyzerEngine,
    ScoringConfig,
    SeverityRule,
    apply_severity_rules,
    risk_score,
)
from jwt_analyzer.exceptions import JWTParseError, ReporterError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT
from jwt_analyzer.reporters import get_reporter


NOW = 1_700_000_000


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def claims(**extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 60,
        "jti": "id-1",
    }
    payload.update(extra)
    return payload


def finding(
    finding_id: str,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        title=finding_id,
        severity=severity,
        confidence=confidence,
        description="description",
        evidence="evidence",
        impact="impact",
        remediation="remediation",
    )


def by_id(findings, finding_id: str) -> list[Finding]:
    return [item for item in findings if item.id == finding_id]


class _Named(BaseAnalyzer):
    def __init__(self, stage: str, items: list[Finding]) -> None:
        self.stage = stage
        self.items = items
        self.calls = 0

    @property
    def name(self) -> str:
        return self.stage

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        del token
        self.calls += 1
        return list(self.items)


class TestRiskScore:
    def test_formula_is_deterministic(self) -> None:
        findings = (
            finding("C", Severity.CRITICAL, Confidence.HIGH),
            finding("H", Severity.HIGH, Confidence.MEDIUM),
            finding("L", Severity.LOW, Confidence.LOW),
        )
        first = risk_score(findings)
        second = risk_score(findings)
        # 40*10 + 20*6 + 4*3 = 532; (532 + 5) // 10 = 53
        assert first.score == 53
        assert first.maximum == 100
        assert second == first
        assert first.critical == 1
        assert first.high == 1
        assert first.low == 1
        assert f"{first.score}/{first.maximum}" == "53/100"

    def test_score_is_capped(self) -> None:
        findings = tuple(finding(f"C{index}", Severity.CRITICAL) for index in range(5))
        assert risk_score(findings).score == 100

    def test_weights_are_configurable(self) -> None:
        scored = risk_score(
            (finding("H"),),
            ScoringConfig(weights={Severity.HIGH: 5}),
        )
        assert scored.score == 5

    def test_certain_matches_high_confidence(self) -> None:
        assert Confidence.CERTAIN is Confidence.HIGH
        assert Confidence.FIRM is Confidence.MEDIUM
        assert Confidence.TENTATIVE is Confidence.LOW
        assert Confidence.CERTAIN.value == "HIGH"
        certain = risk_score((finding("H", confidence=Confidence.CERTAIN),))
        high = risk_score((finding("H", confidence=Confidence.HIGH),))
        assert certain.score == high.score == 20

    def test_info_does_not_add_points(self) -> None:
        assert risk_score((finding("I", Severity.INFO),)).score == 0


class TestEngine:
    def test_parse_failure_stops_the_chain(self) -> None:
        stage = _Named("later", [finding("JWT-TEST-001")])
        engine = AnalyzerEngine(AnalysisConfig(analyzers=(stage,)))
        with pytest.raises(JWTParseError):
            engine.run("not-a-jwt")
        assert stage.calls == 0

    def test_findings_are_collected_in_pipeline_order(self) -> None:
        first = _Named("first", [finding("JWT-TEST-001", Severity.LOW)])
        second = _Named("second", [finding("JWT-TEST-002", Severity.MEDIUM)])
        result = AnalyzerEngine(AnalysisConfig(analyzers=(first, second), severity_rules=())).run(
            make_token({"alg": "RS256", "typ": "JWT"}, claims())
        )
        assert [item.id for item in result.findings] == ["JWT-TEST-001", "JWT-TEST-002"]
        assert result.risk.low == 1
        assert result.risk.medium == 1

    def test_documented_rule_upgrades_alg_none_without_editing_the_analyzer(self) -> None:
        payload = claims()
        del payload["exp"]
        token = make_token({"alg": "none", "typ": "JWT"}, payload)
        upgraded = AnalyzerEngine(AnalysisConfig(now=NOW)).run(token)
        assert by_id(upgraded.findings, "JWT-ALG-001")[0].severity is Severity.CRITICAL
        assert by_id(upgraded.findings, "JWT-EXP-001")[0].severity is Severity.HIGH

        kept = AnalyzerEngine(AnalysisConfig(now=NOW, severity_rules=())).run(token)
        assert by_id(kept.findings, "JWT-ALG-001")[0].severity is Severity.HIGH

    def test_custom_rule_overrides_a_payload_finding(self) -> None:
        payload = claims()
        del payload["exp"]
        result = AnalyzerEngine(
            AnalysisConfig(
                now=NOW,
                severity_rules=(SeverityRule("JWT-EXP-001", Severity.CRITICAL),),
            )
        ).run(make_token({"alg": "RS256", "typ": "JWT"}, payload))
        assert by_id(result.findings, "JWT-EXP-001")[0].severity is Severity.CRITICAL

    def test_apply_rules_leaves_unknown_ids_unchanged(self) -> None:
        original = finding("JWT-OTHER", Severity.LOW)
        updated = apply_severity_rules((original,), (SeverityRule("JWT-ALG-001", Severity.CRITICAL),))
        assert updated == (original,)


class TestReporters:
    def setup_method(self) -> None:
        payload = claims()
        del payload["exp"]
        self.result = AnalyzerEngine(AnalysisConfig(now=NOW)).run(
            make_token({"alg": "none", "typ": "JWT", "kid": "key-01"}, payload)
        )

    def test_factory_selects_json_and_rejects_unknown_formats(self) -> None:
        assert get_reporter("JSON").format_name == "json"
        assert get_reporter("html").format_name == "html"
        with pytest.raises(ReporterError):
            get_reporter("pdf")

    def test_json_schema_is_parseable(self) -> None:
        document = json.loads(get_reporter("json").render(self.result))
        assert document["schema_version"] == 1
        assert isinstance(document["findings"], list)
        assert document["findings"]
        sample = document["findings"][0]
        assert set(sample) == {
            "id",
            "title",
            "severity",
            "confidence",
            "description",
            "evidence",
            "impact",
            "remediation",
            "references",
        }
        assert document["summary"]["by_severity"]["CRITICAL"] >= 1
        assert document["summary"]["risk_score"] == self.result.risk.score
        assert document["summary"]["risk_score_max"] == 100
        assert "manual security assessment" in document["disclaimer"]
        assert document["token"]["metadata"]["alg"] == "none"

    def test_html_is_standalone_and_escapes_markup(self) -> None:
        marked = claims(sub="<script>alert(1)</script>")
        del marked["exp"]
        result = AnalyzerEngine(AnalysisConfig(now=NOW)).run(
            make_token({"alg": "RS256", "typ": "JWT"}, marked)
        )
        page = get_reporter("html").render(result)
        assert page.startswith("<!DOCTYPE html>")
        assert "<link" not in page
        assert "<script" not in page
        assert "https://" not in page.split("<style>", 1)[0]
        for heading in (
            "Executive Summary",
            "Token Information",
            "Security Findings",
            "Evidence",
            "Severity",
            "Confidence",
            "Recommendation",
            "Technical Details",
        ):
            assert heading in page
        assert "Risk Score :" in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_text_report_includes_the_score_and_optional_color(self) -> None:
        text = get_reporter("text").render(self.result)
        assert "JWT-ALG-001" in text
        assert "Confidence: HIGH" in text
        assert f"Risk Score : {self.result.risk.score}/100" in text
        assert "\033[" not in text
        colored = get_reporter("text", color=True).render(self.result)
        assert "\033[31m[CRITICAL]\033[0m JWT-ALG-001" in colored

    def test_markdown_and_csv(self) -> None:
        markdown = get_reporter("markdown").render(self.result)
        assert "# JWT Security Report" in markdown
        assert "Risk Score :" in markdown
        assert "### JWT-ALG-001" in markdown

        rows = list(csv.DictReader(StringIO(get_reporter("csv").render(self.result))))
        assert rows
        assert rows[0]["id"]
        assert rows[0]["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert rows[0]["risk_score"] == str(self.result.risk.score)
