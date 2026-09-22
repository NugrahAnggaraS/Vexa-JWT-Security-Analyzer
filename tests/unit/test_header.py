"""Unit tests for header security and algorithm analysis."""

from __future__ import annotations

import base64
import json

import pytest

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.header import (
    HeaderAnalysisConfig,
    HeaderAnalyzer,
    HeaderCheck,
    analyze_header,
)
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT, parse_jwt


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict | None = None) -> str:
    body = {"sub": "user"} if payload is None else payload
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def analyze(
    header: dict,
    config: HeaderAnalysisConfig | None = None,
    payload: dict | None = None,
) -> list[Finding]:
    return HeaderAnalyzer(config).analyze(parse_jwt(make_token(header, payload)))


def by_id(findings: list[Finding], finding_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.id == finding_id]


class TestAlgorithmAnalysis:
    @pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE", " none "])
    def test_none_algorithm_is_high(self, alg: str) -> None:
        findings = analyze({"alg": alg, "typ": "JWT"})
        match = by_id(findings, "JWT-ALG-001")

        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].confidence is Confidence.HIGH
        assert match[0].title == 'Algorithm "none" detected'
        assert "none" in match[0].evidence.lower()

    def test_none_is_not_also_reported_as_an_allowlist_miss(self) -> None:
        config = HeaderAnalysisConfig(expected_algorithms=frozenset({"RS256"}))
        findings = analyze({"alg": "none", "typ": "JWT"}, config)
        assert [finding.id for finding in findings] == ["JWT-ALG-001"]

    @pytest.mark.parametrize(
        "header",
        [
            {"typ": "JWT"},
            {"alg": None, "typ": "JWT"},
            {"alg": "", "typ": "JWT"},
            {"alg": "   ", "typ": "JWT"},
            {"alg": 256, "typ": "JWT"},
        ],
    )
    def test_missing_or_invalid_alg_is_high(self, header: dict) -> None:
        findings = analyze(header)
        match = by_id(findings, "JWT-ALG-002")
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert match[0].title == "Missing alg parameter"

    def test_weak_sha1_algorithm_is_high(self) -> None:
        findings = analyze({"alg": "HS1", "typ": "JWT"})
        match = by_id(findings, "JWT-ALG-004")
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert "HS1" in match[0].evidence

    def test_unrecognized_algorithm_is_medium(self) -> None:
        findings = analyze({"alg": "ROT13", "typ": "JWT"})
        match = by_id(findings, "JWT-ALG-005")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM

    def test_non_canonical_algorithm_casing(self) -> None:
        findings = analyze({"alg": "hs256", "typ": "JWT"})
        match = by_id(findings, "JWT-ALG-006")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert "canonical=HS256" in match[0].evidence
        assert by_id(findings, "JWT-ALG-005") == []

    def test_symmetric_algorithm_when_asymmetric_is_expected(self) -> None:
        config = HeaderAnalysisConfig(expected_key_type="asymmetric")
        findings = analyze({"alg": "HS256", "typ": "JWT"}, config)
        match = by_id(findings, "JWT-ALG-003")
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert "asymmetric" in match[0].title
        assert "family=symmetric" in match[0].evidence

    def test_asymmetric_algorithm_when_symmetric_is_expected(self) -> None:
        config = HeaderAnalysisConfig(expected_key_type="symmetric")
        findings = analyze({"alg": "RS256", "typ": "JWT"}, config)
        match = by_id(findings, "JWT-ALG-003")
        assert len(match) == 1
        assert "symmetric" in match[0].title
        assert "family=asymmetric" in match[0].evidence

    def test_matching_family_has_no_mismatch(self) -> None:
        config = HeaderAnalysisConfig(expected_key_type="asymmetric")
        findings = analyze({"alg": "RS256", "typ": "JWT", "kid": "key-01"}, config)
        assert findings == []

    def test_algorithm_outside_allowlist_is_high(self) -> None:
        config = HeaderAnalysisConfig(expected_algorithms=frozenset({"RS256", "ES256"}))
        findings = analyze({"alg": "HS256", "typ": "JWT"}, config)
        match = by_id(findings, "JWT-ALG-007")
        assert len(match) == 1
        assert match[0].severity is Severity.HIGH
        assert "HS256" in match[0].evidence

    def test_allowlisted_algorithm_is_clean(self) -> None:
        config = HeaderAnalysisConfig(expected_algorithms=frozenset({"HS256"}))
        assert analyze({"alg": "HS256", "typ": "JWT"}, config) == []

    def test_standard_algorithms_are_clean(self) -> None:
        for alg in ("HS256", "HS384", "HS512", "RS256", "ES256", "PS256", "EdDSA"):
            assert analyze({"alg": alg, "typ": "JWT"}) == []


class TestTypAndCleanHeader:
    def test_recognized_typ_values_are_clean(self) -> None:
        for typ in ("JWT", "jwt", "at+jwt", "application/at+jwt"):
            assert analyze({"alg": "RS256", "typ": typ}) == []

    def test_missing_typ_is_allowed(self) -> None:
        assert analyze({"alg": "RS256"}) == []

    def test_unexpected_typ_is_low(self) -> None:
        findings = analyze({"alg": "RS256", "typ": "JWE"})
        match = by_id(findings, "JWT-HDR-002")
        assert len(match) == 1
        assert match[0].severity is Severity.LOW

    def test_non_string_typ_is_medium(self) -> None:
        findings = analyze({"alg": "RS256", "typ": 1})
        match = by_id(findings, "JWT-HDR-001")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM

    def test_empty_typ_is_low(self) -> None:
        findings = analyze({"alg": "RS256", "typ": "  "})
        assert by_id(findings, "JWT-HDR-002")[0].severity is Severity.LOW

    def test_normal_kid_is_clean(self) -> None:
        assert analyze({"alg": "RS256", "typ": "JWT", "kid": "key-01"}) == []


class TestKidAnalysis:
    @pytest.mark.parametrize(
        ("kid", "category"),
        [
            ("../etc/passwd", "path_traversal"),
            ("..\\windows\\system32", "path_traversal"),
            ("..%2f..%2fetc/passwd", "path_traversal"),
            ("%2e%2e/%2e%2e/secret", "path_traversal"),
            ("key' OR '1'='1", "sql_metacharacter"),
            ('"; DROP TABLE keys;--', "sql_metacharacter"),
            ("abc%00def", "suspicious_encoding"),
            ("line\nbreak", "suspicious_encoding"),
            ("domain\\user", "suspicious_separator"),
        ],
    )
    def test_dangerous_kid_metacharacters(self, kid: str, category: str) -> None:
        findings = analyze({"alg": "RS256", "typ": "JWT", "kid": kid})
        match = by_id(findings, "JWT-KID-001")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert match[0].title == "Suspicious characters detected in kid"
        assert "categories=" in match[0].evidence
        assert category in match[0].evidence

    def test_empty_kid(self) -> None:
        for kid in ("", "   "):
            findings = analyze({"alg": "RS256", "typ": "JWT", "kid": kid})
            match = by_id(findings, "JWT-KID-002")
            assert len(match) == 1
            assert match[0].severity is Severity.MEDIUM
            assert match[0].title == "Empty kid"
            assert by_id(findings, "JWT-KID-001") == []

    def test_excessively_long_kid(self) -> None:
        findings = analyze({"alg": "RS256", "typ": "JWT", "kid": "a" * 257})
        match = by_id(findings, "JWT-KID-003")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert "kid_length=257" in match[0].evidence
        assert "...(truncated)" in match[0].evidence

    def test_kid_at_length_limit_is_clean(self) -> None:
        assert analyze({"alg": "RS256", "typ": "JWT", "kid": "a" * 256}) == []

    def test_custom_kid_length_limit(self) -> None:
        config = HeaderAnalysisConfig(max_kid_length=8)
        findings = analyze({"alg": "RS256", "typ": "JWT", "kid": "key-00001"}, config)
        assert by_id(findings, "JWT-KID-003")

    def test_non_string_kid(self) -> None:
        findings = analyze({"alg": "RS256", "typ": "JWT", "kid": 15})
        match = by_id(findings, "JWT-KID-004")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM


class TestExternalKeyUrls:
    def test_https_jku_warns_without_fetching(self) -> None:
        def fetcher(_url: str) -> bytes:
            raise AssertionError("passive mode must not fetch")

        config = HeaderAnalysisConfig(
            allowed_key_hosts=frozenset({"example.com"}),
            key_fetcher=fetcher,
        )
        url = "https://example.com/.well-known/jwks.json"
        findings = analyze({"alg": "RS256", "typ": "JWT", "jku": url}, config)
        match = by_id(findings, "JWT-JKU-001")

        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert match[0].title == "External JWK URL detected"
        assert "scheme=https" in match[0].evidence
        assert "host=example.com" in match[0].evidence
        assert "issues=external_source" in match[0].evidence
        assert "reason=passive_mode" in match[0].evidence

    def test_http_jku_is_high(self) -> None:
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "jku": "http://example.com/jwks.json"}
        )
        match = by_id(findings, "JWT-JKU-001")
        assert match[0].severity is Severity.HIGH
        assert "cleartext_http" in match[0].evidence
        assert "reason=passive_mode" in match[0].evidence

    def test_invalid_jku_format(self) -> None:
        findings = analyze({"alg": "RS256", "typ": "JWT", "jku": "not a url"})
        match = by_id(findings, "JWT-JKU-001")
        assert match[0].title == "Invalid jku URL"
        assert match[0].severity is Severity.MEDIUM
        assert "invalid_format" in match[0].evidence
        assert "reason=invalid_url" in match[0].evidence

    def test_dangerous_jku_scheme_is_not_fetched(self) -> None:
        def fetcher(_url: str) -> bytes:
            raise AssertionError("dangerous scheme must not be fetched")

        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"evil.com"}),
            key_fetcher=fetcher,
        )
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "jku": "file://evil.com/jwks.json"},
            config,
        )
        match = by_id(findings, "JWT-JKU-001")
        assert match[0].severity is Severity.HIGH
        assert "dangerous_scheme" in match[0].evidence
        assert "reason=insecure_or_invalid_url" in match[0].evidence

    def test_https_x5u_warns(self) -> None:
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "x5u": "https://example.com/cert.pem"}
        )
        match = by_id(findings, "JWT-X5U-001")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert match[0].title == "External certificate URL detected"
        assert "reason=passive_mode" in match[0].evidence

    def test_http_x5u_is_high(self) -> None:
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "x5u": "http://example.com/cert.pem"}
        )
        match = by_id(findings, "JWT-X5U-001")
        assert match[0].severity is Severity.HIGH
        assert "cleartext_http" in match[0].evidence

    def test_credentials_in_jku_are_redacted_and_not_fetched(self) -> None:
        def fetcher(_url: str) -> bytes:
            raise AssertionError("credential URL must not be fetched")

        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"example.com"}),
            key_fetcher=fetcher,
        )
        findings = analyze(
            {
                "alg": "RS256",
                "typ": "JWT",
                "jku": "https://user:s3cret@example.com/jwks.json",
            },
            config,
        )
        evidence = by_id(findings, "JWT-JKU-001")[0].evidence
        assert "s3cret" not in evidence
        assert "user:***" in evidence
        assert "embedded_credentials" in evidence
        assert "reason=url_credentials" in evidence

    def test_inconsistent_jku_and_x5u_hosts(self) -> None:
        findings = analyze(
            {
                "alg": "RS256",
                "typ": "JWT",
                "jku": "https://keys.example.com/jwks.json",
                "x5u": "https://certs.example.net/cert.pem",
            }
        )
        match = by_id(findings, "JWT-HDR-003")
        assert len(match) == 1
        assert match[0].severity is Severity.MEDIUM
        assert "jku_host=keys.example.com" in match[0].evidence
        assert "x5u_host=certs.example.net" in match[0].evidence

    def test_same_key_host_has_no_consistency_finding(self) -> None:
        findings = analyze(
            {
                "alg": "RS256",
                "typ": "JWT",
                "jku": "https://example.com/jwks.json",
                "x5u": "https://example.com/cert.pem",
            }
        )
        assert by_id(findings, "JWT-HDR-003") == []
        assert by_id(findings, "JWT-JKU-001")
        assert by_id(findings, "JWT-X5U-001")


class TestAssessmentMode:
    def test_allowlisted_https_jku_is_fetched_only_in_assessment_mode(self) -> None:
        calls: list[str] = []

        def fetcher(url: str) -> bytes:
            calls.append(url)
            return b'{"keys":[]}'

        url = "https://example.com/.well-known/jwks.json"
        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"Example.COM"}),
            key_fetcher=fetcher,
        )
        findings = analyze({"alg": "RS256", "typ": "JWT", "jku": url}, config)
        evidence = by_id(findings, "JWT-JKU-001")[0].evidence

        assert calls == [url]
        assert "fetch=performed; bytes=11" in evidence

    def test_host_outside_allowlist_is_not_fetched(self) -> None:
        def fetcher(_url: str) -> bytes:
            raise AssertionError("host was not allowlisted")

        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"issuer.example"}),
            key_fetcher=fetcher,
        )
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "jku": "https://evil.example/jwks.json"},
            config,
        )
        assert "reason=host_not_allowlisted" in by_id(findings, "JWT-JKU-001")[0].evidence

    def test_assessment_without_fetcher_does_not_raise(self) -> None:
        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"example.com"}),
        )
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "jku": "https://example.com/jwks.json"},
            config,
        )
        assert "reason=no_fetcher" in by_id(findings, "JWT-JKU-001")[0].evidence

    def test_fetcher_errors_stay_inside_the_finding(self) -> None:
        def fetcher(_url: str) -> bytes:
            raise RuntimeError("connection failed")

        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"example.com"}),
            key_fetcher=fetcher,
        )
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "x5u": "https://example.com/cert.pem"},
            config,
        )
        evidence = by_id(findings, "JWT-X5U-001")[0].evidence
        assert "fetch=error; error_type=RuntimeError" in evidence
        assert "connection failed" not in evidence

    def test_non_bytes_fetcher_result_is_an_error_finding(self) -> None:
        config = HeaderAnalysisConfig(
            assessment_mode=True,
            allowed_key_hosts=frozenset({"example.com"}),
            key_fetcher=lambda _url: "not-bytes",  # type: ignore[arg-type, return-value]
        )
        findings = analyze(
            {"alg": "RS256", "typ": "JWT", "jku": "https://example.com/jwks.json"},
            config,
        )
        assert "invalid_fetcher_result" in by_id(findings, "JWT-JKU-001")[0].evidence


class TestPipeline:
    def test_header_analyzer_is_a_pipeline_stage(self) -> None:
        analyzer = HeaderAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "header"

    def test_base_analyzer_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError):
            BaseAnalyzer()  # type: ignore[abstract]

    def test_checks_run_as_a_chain(self) -> None:
        class OnlyThis(HeaderCheck):
            def check(self, header: dict, config: HeaderAnalysisConfig) -> list[Finding]:
                del header, config
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

        token = parse_jwt(make_token({"alg": "none", "typ": "JWT", "kid": "../x"}))
        findings = HeaderAnalyzer(checks=[OnlyThis()]).analyze(token)
        assert [finding.id for finding in findings] == ["JWT-TEST-001"]

    def test_default_chain_keeps_independent_findings(self) -> None:
        findings = analyze(
            {
                "alg": "none",
                "kid": "../etc/passwd",
                "jku": "https://example.com/jwks.json",
            }
        )
        assert by_id(findings, "JWT-ALG-001")
        assert by_id(findings, "JWT-KID-001")
        assert by_id(findings, "JWT-JKU-001")

    def test_module_helper_matches_analyzer(self) -> None:
        token = parse_jwt(make_token({"alg": "none", "typ": "JWT"}))
        assert analyze_header(token) == HeaderAnalyzer().analyze(token)

    def test_finding_dict_uses_severity_value(self) -> None:
        finding = analyze({"alg": "none", "typ": "JWT"})[0]
        data = finding.to_dict()
        assert data["id"] == "JWT-ALG-001"
        assert data["severity"] == "HIGH"
        assert data["confidence"] == "HIGH"
        assert data["references"]

    def test_invalid_expected_key_type(self) -> None:
        with pytest.raises(ValueError, match="expected_key_type"):
            HeaderAnalysisConfig(expected_key_type="public")

    def test_invalid_kid_length(self) -> None:
        with pytest.raises(ValueError, match="max_kid_length"):
            HeaderAnalysisConfig(max_kid_length=0)

    def test_analyzer_reads_header_not_only_metadata(self) -> None:
        parsed: ParsedJWT = parse_jwt(
            make_token({"alg": "RS256", "typ": "JWT", "jku": "https://example.com/jwks.json"})
        )
        assert parsed.metadata.alg == "RS256"
        assert "jku" not in parsed.metadata.__dict__
        assert by_id(HeaderAnalyzer().analyze(parsed), "JWT-JKU-001")
