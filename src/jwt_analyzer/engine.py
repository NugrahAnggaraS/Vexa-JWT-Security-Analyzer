"""Facade that runs the analyzer chain, aggregates findings, and scores them.

Pipeline:

    Input -> Parser -> HeaderAnalyzer -> PayloadAnalyzer -> CryptoAnalyzer
          -> JwksAnalyzer -> OidcTokenAnalyzer -> severity rules -> risk score

A token that is not a compact JWT raises ``JWTParseError`` and the chain
stops before any analyzer runs. Analyzers report findings; they do not stop
the chain.

Risk score, from 0 to 100:

    points = severity weight * confidence tenths
    score  = min(maximum, round_half_up(sum(points) / 10))

Default weights are CRITICAL 40, HIGH 20, MEDIUM 10, LOW 4, and INFO 0.
Confidence tenths are HIGH/CERTAIN 10, MEDIUM/FIRM 6, and LOW/TENTATIVE 3.
The same findings always produce the same score. The score summarizes the
findings; it does not replace a manual assessment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Optional, Sequence

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.crypto import CryptoAnalysisConfig, CryptoAnalyzer
from jwt_analyzer.analyzers.header import HeaderAnalysisConfig, HeaderAnalyzer
from jwt_analyzer.analyzers.jwks import JwksAnalysisConfig, JwksAnalyzer
from jwt_analyzer.analyzers.oidc import OidcAnalysisConfig, OidcTokenAnalyzer
from jwt_analyzer.analyzers.payload import PayloadAnalysisConfig, PayloadAnalyzer
from jwt_analyzer.exceptions import ReporterError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import JWTMetadata, ParsedJWT, parse_jwt

logger = logging.getLogger("jwt_analyzer.engine")

SCHEMA_VERSION = 1
DISCLAIMER = (
    "This risk score is a deterministic summary of the findings. "
    "It does not replace a manual security assessment."
)

# Overrides applied after analyzers run, so a rule can change severity
# without editing the analyzer that emitted the finding.
# alg none is the unsafe algorithm case in the severity classification.
DOCUMENTED_SEVERITY_RULES: tuple[tuple[str, Severity], ...] = (
    # CRITICAL: clearly unsafe algorithm configuration.
    # HIGH: JWT-EXP-001 missing expiration, JWT-SIG-002 weak secret, JWT-SEC-001 sensitive data.
    # MEDIUM: JWT-LIFE-001 excessive lifetime, JWT-JKU-001 and JWT-X5U-001 external keys.
    # LOW: informational configuration weakness. INFO: security-relevant metadata.
    ("JWT-ALG-001", Severity.CRITICAL),
)

DEFAULT_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}
DEFAULT_CONFIDENCE_TENTHS: dict[Confidence, int] = {
    Confidence.HIGH: 10,
    Confidence.MEDIUM: 6,
    Confidence.LOW: 3,
}


@dataclass(frozen=True)
class SeverityRule:
    """One documented override from a finding id to a severity."""

    finding_id: str
    severity: Severity

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, str) or not self.finding_id.strip():
            raise ValueError("finding_id must be a non-empty string")
        if not isinstance(self.severity, Severity):
            raise ValueError("severity must be a Severity value")


def documented_severity_rules() -> tuple[SeverityRule, ...]:
    """Return the built-in severity overrides."""
    return tuple(SeverityRule(finding_id, severity) for finding_id, severity in DOCUMENTED_SEVERITY_RULES)


@dataclass(frozen=True)
class ScoringConfig:
    """Weights used by the risk-score formula. Missing keys keep the defaults."""

    weights: Mapping[Severity, int] = field(default_factory=dict)
    confidence_tenths: Mapping[Confidence, int] = field(default_factory=dict)
    maximum: int = 100

    def __post_init__(self) -> None:
        if isinstance(self.maximum, bool) or not isinstance(self.maximum, int) or self.maximum < 1:
            raise ValueError("maximum must be a positive integer")
        object.__setattr__(self, "weights", _clean_weights(self.weights))
        object.__setattr__(self, "confidence_tenths", _clean_tenths(self.confidence_tenths))

    def resolved_weights(self) -> dict[Severity, int]:
        resolved = dict(DEFAULT_WEIGHTS)
        resolved.update(self.weights)
        return resolved

    def resolved_tenths(self) -> dict[Confidence, int]:
        resolved = dict(DEFAULT_CONFIDENCE_TENTHS)
        resolved.update(self.confidence_tenths)
        return resolved


@dataclass(frozen=True)
class RiskScore:
    """Deterministic score and the severity counts that produced it."""

    score: int
    maximum: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def count(self, severity: Severity) -> int:
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.medium,
            Severity.LOW: self.low,
            Severity.INFO: self.info,
        }[severity]

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "by_severity": {severity.value: self.count(severity) for severity in Severity},
            "risk_score": self.score,
            "risk_score_max": self.maximum,
        }


@dataclass(frozen=True)
class AnalysisConfig:
    """Pipeline, clock, and scoring policy for one engine run."""

    analyzers: Optional[Sequence[BaseAnalyzer]] = None
    header: Optional[HeaderAnalysisConfig] = None
    payload: Optional[PayloadAnalysisConfig] = None
    crypto: Optional[CryptoAnalysisConfig] = None
    jwks: Optional[JwksAnalysisConfig] = None
    oidc: Optional[OidcAnalysisConfig] = None
    now: Optional[float] = None
    severity_rules: Optional[tuple[SeverityRule, ...]] = None
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    ignore: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AnalysisResult:
    """Parsed token, aggregated findings, and the risk score."""

    token: ParsedJWT
    findings: tuple[Finding, ...]
    risk: RiskScore

    def to_dict(self) -> dict[str, object]:
        """Return the stable document written by the JSON reporter."""
        return {
            "schema_version": SCHEMA_VERSION,
            "token": self.token.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.risk.to_dict(),
            "disclaimer": DISCLAIMER,
        }


class AnalyzerEngine:
    """Run the analysis pipeline and aggregate its findings."""

    def __init__(self, config: Optional[AnalysisConfig] = None) -> None:
        self.config = config if config is not None else AnalysisConfig()

    def run(self, token: str) -> AnalysisResult:
        """Parse ``token`` and collect findings from every configured stage.

        ``JWTParseError`` propagates and later stages are not called.
        """
        parsed = parse_jwt(token)
        findings: list[Finding] = []
        for analyzer in self._analyzers():
            produced = analyzer.analyze(parsed)
            logger.debug("%s produced %d finding(s)", analyzer.name, len(produced))
            findings.extend(produced)
        rules = self.config.severity_rules
        if rules is None:
            rules = documented_severity_rules()
        normalized = apply_severity_rules(findings, rules)
        ignored = {item.strip().upper() for item in self.config.ignore if item and item.strip()}
        if ignored:
            normalized = tuple(item for item in normalized if item.id.upper() not in ignored)
            logger.info("suppressed finding ids: %s", ", ".join(sorted(ignored)))
        result = AnalysisResult(
            token=parsed,
            findings=normalized,
            risk=risk_score(normalized, self.config.scoring),
        )
        logger.info("analysis finished: findings=%d risk=%d/%d", result.risk.total, result.risk.score, result.risk.maximum)
        return result

    def render(self, result: AnalysisResult, fmt: str, *, color: bool = False) -> str:
        """Format ``result`` with the reporter selected by ``fmt``."""
        from jwt_analyzer.reporters import get_reporter

        return get_reporter(fmt, color=color).render(result)

    def _analyzers(self) -> tuple[BaseAnalyzer, ...]:
        if self.config.analyzers is not None:
            return tuple(self.config.analyzers)
        payload_config = self.config.payload
        if payload_config is None and self.config.now is not None:
            payload_config = PayloadAnalysisConfig(now=self.config.now)
        return (
            HeaderAnalyzer(self.config.header),
            PayloadAnalyzer(payload_config),
            CryptoAnalyzer(self.config.crypto),
            JwksAnalyzer(self.config.jwks),
            OidcTokenAnalyzer(self.config.oidc),
        )


def analysis_result_from_dict(data: Mapping[str, Any]) -> AnalysisResult:
    """Rebuild an analysis result from a JSON report document."""
    if not isinstance(data, Mapping):
        raise ReporterError("Report must be a JSON object", code="INVALID_REPORT")
    token_doc = data.get("token")
    findings_doc = data.get("findings")
    if not isinstance(token_doc, Mapping) or not isinstance(findings_doc, list):
        raise ReporterError("Report is missing token or findings", code="INVALID_REPORT")
    metadata_doc = token_doc.get("metadata")
    signature_doc = token_doc.get("signature")
    header = token_doc.get("header")
    payload = token_doc.get("payload")
    if not isinstance(metadata_doc, Mapping) or not isinstance(header, dict) or not isinstance(payload, dict):
        raise ReporterError("Report token is incomplete", code="INVALID_REPORT")
    if not isinstance(signature_doc, Mapping):
        signature_doc = {}
    findings: list[Finding] = []
    for item in findings_doc:
        if not isinstance(item, Mapping):
            raise ReporterError("Report findings must be objects", code="INVALID_REPORT")
        try:
            findings.append(
                Finding(
                    id=str(item["id"]),
                    title=str(item["title"]),
                    severity=Severity(str(item["severity"])),
                    confidence=Confidence(str(item["confidence"])),
                    description=str(item.get("description", "")),
                    evidence=str(item.get("evidence", "")),
                    impact=str(item.get("impact", "")),
                    remediation=str(item.get("remediation", "")),
                    references=tuple(str(ref) for ref in item.get("references") or ()),
                )
            )
        except (KeyError, ValueError) as exc:
            raise ReporterError(f"Report finding is invalid: {exc}", code="INVALID_REPORT") from exc
    custom = token_doc.get("custom_claims")
    parsed = ParsedJWT(
        raw="",
        header=header,
        payload=payload,
        signature=b"",
        header_segment="",
        payload_segment="",
        signature_segment=str(signature_doc.get("raw") or ""),
        metadata=JWTMetadata(
            alg=_optional_meta(metadata_doc.get("alg")),
            typ=_optional_meta(metadata_doc.get("typ")),
            kid=_optional_meta(metadata_doc.get("kid")),
            cty=_optional_meta(metadata_doc.get("cty")),
            iss=_optional_meta(metadata_doc.get("iss")),
            sub=_optional_meta(metadata_doc.get("sub")),
            aud=metadata_doc.get("aud") if isinstance(metadata_doc.get("aud"), (str, list)) else None,
            exp=_optional_number(metadata_doc.get("exp")),
            iat=_optional_number(metadata_doc.get("iat")),
            nbf=_optional_number(metadata_doc.get("nbf")),
            jti=_optional_meta(metadata_doc.get("jti")),
        ),
        custom_claims=custom if isinstance(custom, dict) else {},
    )
    frozen = tuple(findings)
    return AnalysisResult(token=parsed, findings=frozen, risk=risk_score(frozen))


def _optional_meta(value: object) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _optional_number(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def apply_severity_rules(
    findings: Sequence[Finding],
    rules: Sequence[SeverityRule],
) -> tuple[Finding, ...]:
    """Return findings with documented severity overrides applied.

    The last rule for an id wins. Findings without a rule keep the severity
    their analyzer chose.
    """
    table: dict[str, Severity] = {}
    for rule in rules:
        table[rule.finding_id] = rule.severity
    updated: list[Finding] = []
    for finding in findings:
        severity = table.get(finding.id)
        if severity is None or severity is finding.severity:
            updated.append(finding)
        else:
            updated.append(replace(finding, severity=severity))
    return tuple(updated)


def risk_score(findings: Sequence[Finding], config: Optional[ScoringConfig] = None) -> RiskScore:
    """Score ``findings`` with the documented formula."""
    scoring = config if config is not None else ScoringConfig()
    weights = scoring.resolved_weights()
    tenths = scoring.resolved_tenths()
    counts = {severity: 0 for severity in Severity}
    points = 0
    for finding in findings:
        counts[finding.severity] += 1
        factor = tenths.get(finding.confidence, DEFAULT_CONFIDENCE_TENTHS[Confidence.HIGH])
        points += weights[finding.severity] * factor
    score = min(scoring.maximum, (points + 5) // 10)
    return RiskScore(
        score=score,
        maximum=scoring.maximum,
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
    )


def _clean_weights(weights: Mapping[Severity, int]) -> dict[Severity, int]:
    cleaned: dict[Severity, int] = {}
    for severity, weight in weights.items():
        if not isinstance(severity, Severity):
            raise ValueError("weight keys must be Severity values")
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
            raise ValueError("severity weights must be non-negative integers")
        cleaned[severity] = weight
    return cleaned


def _clean_tenths(factors: Mapping[Confidence, int]) -> dict[Confidence, int]:
    cleaned: dict[Confidence, int] = {}
    for confidence, factor in factors.items():
        if not isinstance(confidence, Confidence):
            raise ValueError("confidence keys must be Confidence values")
        cleaned[confidence] = _as_tenths(factor)
    return cleaned


def _as_tenths(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("confidence factor must be a tenth from 0 to 10 or a fraction from 0 to 1")
    if isinstance(value, int) and 0 <= value <= 10:
        return value
    if isinstance(value, float) and 0 <= value <= 1:
        return int(round(value * 10))
    raise ValueError("confidence factor must be a tenth from 0 to 10 or a fraction from 0 to 1")
