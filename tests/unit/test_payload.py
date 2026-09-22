"""Unit tests for payload, claim, expiration, and sensitive-data analysis."""

from __future__ import annotations

import base64
import json

import pytest

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.payload import (
    PayloadAnalysisConfig,
    PayloadAnalyzer,
    PayloadCheck,
    analyze_payload,
)
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import parse_jwt

NOW = 1_700_000_000
SECRET = "s3cret-value-xyz"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(payload: dict, header: dict | None = None) -> str:
    header = {"alg": "RS256", "typ": "JWT"} if header is None else header
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def make_token_from_json(payload_json: str, header: dict | None = None) -> str:
    header = {"alg": "RS256", "typ": "JWT"} if header is None else header
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(payload_json.encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def valid_payload(**overrides: object) -> dict:
    payload: dict = {
        "iss": "https://auth.example.com",
        "sub": "user-123",
        "aud": "api",
        "exp": NOW + 600,
        "iat": NOW,
        "nbf": NOW,
        "jti": "token-1",
    }
    payload.update(overrides)
    return payload


def analyze(
    payload: dict,
    config: PayloadAnalysisConfig | None = None,
) -> list[Finding]:
    chosen = config if config is not None else PayloadAnalysisConfig(now=NOW)
    return PayloadAnalyzer(chosen).analyze(parse_jwt(make_token(payload)))


def by_id(findings: list[Finding], finding_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.id == finding_id]


class TestCleanPayload:
    def test_complete_short_lived_token_has_no_findings(self) -> None:
        assert analyze(valid_payload()) == []

    def test_audience_list_is_valid(self) -> None:
        assert analyze(valid_payload(aud=["api", "admin"])) == []

    def test_equal_time_claims_are_consistent(self) -> None:
        assert analyze(valid_payload(iat=NOW, nbf=NOW, exp=NOW + 10)) == []

    def test_benign_claim_names_are_not_sensitive(self) -> None:
        payload = valid_payload(
            email="user@example.com",
            role="admin",
            topsecret="not-a-keyword-boundary",
            tokenizer="jwt",
        )
        assert analyze(payload) == []


class TestRequiredClaims:
    def test_missing_exp_is_high(self) -> None:
        payload = valid_payload()
        del payload["exp"]
        findings = analyze(payload)
        match = by_id(findings, "JWT-EXP-001")

        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].title == "Token has no expiration claim"
        assert by_id(findings, "JWT-LIFE-001") == []
        assert by_id(findings, "JWT-EXP-002") == []

    def test_null_exp_is_missing(self) -> None:
        findings = analyze(valid_payload(exp=None))
        assert by_id(findings, "JWT-EXP-001")

    def test_other_missing_claims_use_configured_severity(self) -> None:
        payload = valid_payload()
        del payload["iss"]
        del payload["nbf"]
        findings = analyze(payload)

        missing = by_id(findings, "JWT-CLM-001")
        by_claim = {finding.evidence: finding for finding in missing}
        assert by_claim["claim=iss"].severity is Severity.MEDIUM
        assert by_claim["claim=nbf"].severity is Severity.LOW

    def test_required_claims_can_be_narrowed(self) -> None:
        payload = {"sub": "user-123"}
        config = PayloadAnalysisConfig(now=NOW, required_claims=frozenset({"sub"}))
        assert analyze(payload, config) == []

    def test_custom_required_claim(self) -> None:
        config = PayloadAnalysisConfig(now=NOW, required_claims=frozenset({"azp"}))
        findings = analyze(valid_payload(), config)
        match = by_id(findings, "JWT-CLM-001")
        assert len(match) == 1
        assert "claim=azp" in match[0].evidence


class TestClaimTypesAndValues:
    def test_string_exp_is_an_invalid_time_type(self) -> None:
        findings = analyze(valid_payload(exp="1700000600"))
        match = by_id(findings, "JWT-CLM-002")
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert "claim=exp" in match[0].evidence
        assert "actual_type=str" in match[0].evidence
        assert by_id(findings, "JWT-EXP-002") == []

    def test_boolean_exp_is_not_treated_as_a_number(self) -> None:
        findings = analyze(valid_payload(exp=True))
        match = by_id(findings, "JWT-CLM-002")
        assert match[0].severity is Severity.HIGH
        assert "actual_type=bool" in match[0].evidence
        assert by_id(findings, "JWT-EXP-002") == []

    def test_non_string_subject(self) -> None:
        findings = analyze(valid_payload(sub=15))
        match = by_id(findings, "JWT-CLM-002")
        assert match[0].severity is Severity.MEDIUM
        assert "claim=sub" in match[0].evidence

    def test_audience_must_be_strings(self) -> None:
        findings = analyze(valid_payload(aud=["api", 1]))
        match = by_id(findings, "JWT-CLM-002")
        assert "claim=aud" in match[0].evidence
        assert "actual_type=list" in match[0].evidence

    def test_empty_string_claims(self) -> None:
        findings = analyze(valid_payload(iss="  ", sub="", jti=""))
        reasons = {finding.evidence for finding in by_id(findings, "JWT-CLM-003")}
        assert "claim=iss; reason=empty" in reasons
        assert "claim=sub; reason=empty" in reasons
        assert "claim=jti; reason=empty" in reasons

    def test_empty_audience_array(self) -> None:
        findings = analyze(valid_payload(aud=[]))
        assert by_id(findings, "JWT-CLM-003")[0].evidence == "claim=aud; reason=empty_array"

    def test_analyzer_uses_raw_payload_when_metadata_drops_aud(self) -> None:
        token = parse_jwt(make_token(valid_payload(aud=15)))
        assert token.metadata.aud is None
        findings = PayloadAnalyzer(PayloadAnalysisConfig(now=NOW)).analyze(token)
        assert by_id(findings, "JWT-CLM-002")


class TestExpirationAndLifetime:
    def test_expired_token(self) -> None:
        findings = analyze(valid_payload(iat=NOW - 120, nbf=NOW - 120, exp=NOW - 10))
        match = by_id(findings, "JWT-EXP-002")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert match[0].title == "Token has expired"
        assert match[0].confidence is Confidence.HIGH

    def test_token_expiring_at_the_current_second_is_expired(self) -> None:
        findings = analyze(valid_payload(iat=NOW - 10, nbf=NOW - 10, exp=NOW))
        assert by_id(findings, "JWT-EXP-002")

    def test_leeway_keeps_a_recently_expired_token_quiet(self) -> None:
        config = PayloadAnalysisConfig(now=NOW, leeway_seconds=30)
        findings = analyze(valid_payload(iat=NOW - 40, nbf=NOW - 40, exp=NOW - 10), config)
        assert by_id(findings, "JWT-EXP-002") == []

    def test_not_yet_valid(self) -> None:
        findings = analyze(valid_payload(iat=NOW, nbf=NOW + 100, exp=NOW + 200))
        match = by_id(findings, "JWT-EXP-003")
        assert match[0].title == "Token is not yet valid"
        assert match[0].severity is Severity.MEDIUM
        assert by_id(findings, "JWT-EXP-002") == []

    def test_future_iat_is_low(self) -> None:
        findings = analyze(valid_payload(iat=NOW + 100, nbf=NOW + 100, exp=NOW + 200))
        match = by_id(findings, "JWT-EXP-005")
        assert match[0].severity is Severity.LOW

    def test_nbf_after_exp_is_inconsistent(self) -> None:
        config = PayloadAnalysisConfig(now=250, max_lifetime_seconds=3600)
        findings = analyze(valid_payload(iat=100, nbf=300, exp=200), config)
        match = by_id(findings, "JWT-EXP-004")

        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].title == "Inconsistent temporal claims"
        assert "nbf > exp" in match[0].evidence
        assert "iat > exp" not in match[0].evidence

    def test_iat_after_nbf_and_exp(self) -> None:
        findings = analyze(valid_payload(iat=NOW + 50, nbf=NOW, exp=NOW + 10))
        evidence = by_id(findings, "JWT-EXP-004")[0].evidence
        assert "iat > nbf" in evidence
        assert "iat > exp" in evidence

    def test_long_lifetime_on_a_token_that_is_not_expired(self) -> None:
        findings = analyze(valid_payload(iat=NOW, nbf=NOW, exp=NOW + 7200))
        match = by_id(findings, "JWT-LIFE-001")

        assert [finding.id for finding in findings] == ["JWT-LIFE-001"]
        assert match[0].severity is Severity.MEDIUM
        assert match[0].title == "Excessive token lifetime"
        assert "lifetime_seconds=7200" in match[0].evidence
        assert "max_lifetime_seconds=3600" in match[0].evidence
        assert "token_expired=false" in match[0].evidence

    def test_lifetime_at_the_threshold_is_accepted(self) -> None:
        assert analyze(valid_payload(iat=NOW, nbf=NOW, exp=NOW + 3600)) == []

    def test_lifetime_threshold_is_configurable(self) -> None:
        config = PayloadAnalysisConfig(now=NOW, max_lifetime_seconds=8000)
        assert analyze(valid_payload(iat=NOW, nbf=NOW, exp=NOW + 7200), config) == []

    def test_negative_lifetime_is_an_ordering_problem(self) -> None:
        findings = analyze(valid_payload(iat=NOW + 100, nbf=NOW, exp=NOW + 10))
        assert by_id(findings, "JWT-LIFE-001") == []
        assert "iat > exp" in by_id(findings, "JWT-EXP-004")[0].evidence

    def test_default_clock_flags_a_past_expiration(self) -> None:
        findings = analyze(
            valid_payload(iat=0, nbf=0, exp=1),
            PayloadAnalysisConfig(),
        )
        assert by_id(findings, "JWT-EXP-002")


class TestSensitiveData:
    @pytest.mark.parametrize(
        ("key", "keyword"),
        [
            ("password", "password"),
            ("passwd", "passwd"),
            ("api_key", "api_key"),
            ("apiKey", "api_key"),
            ("APIKEY", "apikey"),
            ("private_key", "private_key"),
            ("credit_card", "credit_card"),
            ("card_number", "card_number"),
            ("user_secret", "secret"),
            ("authorization", "authorization"),
            ("access_token", "token"),
        ],
    )
    def test_sensitive_claim_names_are_masked(self, key: str, keyword: str) -> None:
        findings = analyze(valid_payload(**{key: SECRET}))
        match = by_id(findings, "JWT-SEC-001")

        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].title == "Potential sensitive information found"
        assert f"keyword={keyword}" in match[0].evidence
        assert f"path=payload.{key}" in match[0].evidence
        assert "value=***;" in match[0].evidence
        assert SECRET not in json.dumps(match[0].to_dict())

    def test_password_and_api_key_in_one_payload_are_both_masked(self) -> None:
        findings = analyze(
            valid_payload(password=SECRET, api_key="another-secret-value")
        )
        blob = json.dumps([finding.to_dict() for finding in findings])
        assert len(by_id(findings, "JWT-SEC-001")) == 2
        assert SECRET not in blob
        assert "another-secret-value" not in blob
        assert "payload.password" in blob
        assert "payload.api_key" in blob

    def test_nested_and_list_claims_are_masked(self) -> None:
        payload = valid_payload(
            profile={"api_key": SECRET},
            keys=[{"private_key": "pem-data-should-stay-hidden"}],
        )
        findings = analyze(payload)
        evidence = [finding.evidence for finding in by_id(findings, "JWT-SEC-001")]
        assert any("path=payload.profile.api_key" in item for item in evidence)
        assert any("path=payload.keys[0].private_key" in item for item in evidence)
        blob = json.dumps([finding.to_dict() for finding in findings])
        assert SECRET not in blob
        assert "pem-data-should-stay-hidden" not in blob

    def test_numeric_secret_is_masked(self) -> None:
        findings = analyze(valid_payload(api_key=123456789))
        evidence = by_id(findings, "JWT-SEC-001")[0].evidence
        assert "kind=number" in evidence
        assert "123456789" not in evidence

    def test_sensitive_check_can_be_disabled(self) -> None:
        config = PayloadAnalysisConfig(now=NOW, check_sensitive_claims=False)
        assert analyze(valid_payload(password=SECRET), config) == []


class TestDuplicateClaims:
    def test_duplicate_subject_is_a_json_formatting_anomaly(self) -> None:
        payload_json = (
            '{"iss":"https://auth.example.com","sub":"user","sub":"admin",'
            '"aud":"api","exp":1700000600,"iat":1700000000,"nbf":1700000000,'
            '"jti":"token-1"}'
        )
        parsed = parse_jwt(make_token_from_json(payload_json))
        findings = PayloadAnalyzer(PayloadAnalysisConfig(now=NOW)).analyze(parsed)
        match = by_id(findings, "JWT-DUP-001")

        assert parsed.payload["sub"] == "admin"
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].title == "Duplicate claim detected: sub"
        assert "path=payload.sub" in match[0].evidence
        assert "anomaly=duplicate_json_key" in match[0].evidence
        assert "formatting" in match[0].description
        assert [finding.id for finding in findings] == ["JWT-DUP-001"]

    def test_duplicate_is_reported_when_the_surviving_value_looks_valid(self) -> None:
        payload_json = (
            '{"iss":"https://auth.example.com","sub":1,"sub":"admin",'
            '"aud":"api","exp":1700000600,"iat":1700000000,"nbf":1700000000,'
            '"jti":"token-1"}'
        )
        findings = PayloadAnalyzer(PayloadAnalysisConfig(now=NOW)).analyze(
            parse_jwt(make_token_from_json(payload_json))
        )
        assert [finding.id for finding in findings] == ["JWT-DUP-001"]
        assert by_id(findings, "JWT-CLM-002") == []

    def test_nested_duplicate_key(self) -> None:
        payload_json = (
            '{"iss":"https://auth.example.com","sub":"user-123","aud":"api",'
            '"exp":1700000600,"iat":1700000000,"nbf":1700000000,"jti":"token-1",'
            '"user":{"role":"user","role":"admin"}}'
        )
        findings = PayloadAnalyzer(PayloadAnalysisConfig(now=NOW)).analyze(
            parse_jwt(make_token_from_json(payload_json))
        )
        match = by_id(findings, "JWT-DUP-001")
        assert len(match) == 1
        assert match[0].title == "Duplicate claim detected: role"
        assert "path=payload.user.role" in match[0].evidence

    def test_duplicate_check_can_be_disabled(self) -> None:
        payload_json = (
            '{"iss":"https://auth.example.com","sub":"user","sub":"admin",'
            '"aud":"api","exp":1700000600,"iat":1700000000,"nbf":1700000000,'
            '"jti":"token-1"}'
        )
        config = PayloadAnalysisConfig(now=NOW, check_duplicate_claims=False)
        findings = PayloadAnalyzer(config).analyze(parse_jwt(make_token_from_json(payload_json)))
        assert findings == []


class TestPipeline:
    def test_payload_analyzer_is_a_pipeline_stage(self) -> None:
        analyzer = PayloadAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "payload"

    def test_checks_run_as_a_chain(self) -> None:
        class OnlyThis(PayloadCheck):
            def check(self, token: object, config: PayloadAnalysisConfig) -> list[Finding]:
                del token, config
                return [
                    Finding(
                        id="JWT-TEST-001",
                        title="Stub",
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        description="stub",
                        evidence="stub",
                        impact="stub",
                        remediation="stub",
                    )
                ]

        token = parse_jwt(make_token(valid_payload(password=SECRET)))
        findings = PayloadAnalyzer(checks=[OnlyThis()]).analyze(token)
        assert [finding.id for finding in findings] == ["JWT-TEST-001"]

    def test_module_helper_matches_analyzer(self) -> None:
        token = parse_jwt(make_token(valid_payload()))
        config = PayloadAnalysisConfig(now=NOW)
        assert analyze_payload(token, config) == PayloadAnalyzer(config).analyze(token)

    def test_invalid_lifetime_threshold(self) -> None:
        with pytest.raises(ValueError, match="max_lifetime_seconds"):
            PayloadAnalysisConfig(max_lifetime_seconds=-1)

    def test_invalid_leeway(self) -> None:
        with pytest.raises(ValueError, match="leeway_seconds"):
            PayloadAnalysisConfig(leeway_seconds=-5)

    def test_invalid_clock(self) -> None:
        with pytest.raises(ValueError, match="now"):
            PayloadAnalysisConfig(now=True)  # type: ignore[arg-type]
