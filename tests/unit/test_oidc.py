"""Unit tests for OIDC discovery and OAuth/OIDC token analysis."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.oidc import (
    OidcAnalysisConfig,
    OidcCheck,
    OidcTokenAnalyzer,
    TokenRole,
    classify_token,
    discovery_url,
    format_oidc_discovery,
    format_oidc_token,
    load_oidc_provider,
    parse_oidc_provider,
)
from jwt_analyzer.exceptions import OidcError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import parse_jwt


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def id_payload(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "exp": 2_000_000_000,
        "iat": 1_000_000_000,
        "nonce": "n-1",
    }
    body.update(extra)
    return body


def provider_document(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "jwks_uri": "https://auth.example.com/jwks",
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "profile"],
        "claims_supported": ["sub", "iss"],
    }
    body.update(extra)
    return body


def by_id(findings: list[Finding] | tuple[Finding, ...], finding_id: str) -> list[Finding]:
    return [item for item in findings if item.id == finding_id]


def analyze(header: dict[str, Any], payload: dict[str, Any], config: OidcAnalysisConfig | None = None):
    return OidcTokenAnalyzer(config).inspect(parse_jwt(make_token(header, payload)))


class TestDiscovery:
    def test_parses_provider_metadata(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document()).encode("utf-8"),
            requested_issuer="https://auth.example.com",
        )
        assert provider.issuer == "https://auth.example.com"
        assert provider.jwks_uri == "https://auth.example.com/jwks"
        assert provider.id_token_signing_algs == ("RS256", "ES256")
        assert provider.findings == ()
        text = format_oidc_discovery(provider)
        assert "issuer : https://auth.example.com" in text
        assert "jwks_uri : https://auth.example.com/jwks" in text
        assert "id_token_signing_alg_values_supported : RS256, ES256" in text
        assert "response_types_supported : code" in text
        assert "grant_types_supported : authorization_code" in text
        assert "scopes_supported : openid, profile" in text
        assert "claims_supported : sub, iss" in text

    def test_discovery_url_inserts_the_well_known_suffix(self) -> None:
        assert discovery_url("https://auth.example.com") == (
            "https://auth.example.com/.well-known/openid-configuration"
        )
        assert discovery_url("https://auth.example.com/") == (
            "https://auth.example.com/.well-known/openid-configuration"
        )
        assert discovery_url("https://auth.example.com/tenant") == (
            "https://auth.example.com/tenant/.well-known/openid-configuration"
        )
        full = "https://auth.example.com/.well-known/openid-configuration"
        assert discovery_url(full) == full

    def test_fetcher_is_called_with_the_discovery_url(self) -> None:
        seen: list[str] = []

        def fetcher(url: str) -> bytes:
            seen.append(url)
            return json.dumps(provider_document()).encode("utf-8")

        provider = load_oidc_provider("https://auth.example.com/", fetcher=fetcher)
        assert seen == ["https://auth.example.com/.well-known/openid-configuration"]
        assert provider.issuer == "https://auth.example.com"
        assert provider.findings == ()

    def test_missing_jwks_uri(self) -> None:
        document = provider_document()
        del document["jwks_uri"]
        provider = parse_oidc_provider(json.dumps(document).encode(), requested_issuer="https://auth.example.com")
        assert by_id(provider.findings, "JWT-OIDC-003")[0].severity is Severity.HIGH

    def test_issuer_mismatch_with_the_requested_url(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document()).encode(),
            requested_issuer="https://other.example.com",
        )
        match = by_id(provider.findings, "JWT-OIDC-002")
        assert match[0].severity is Severity.HIGH
        assert "other.example.com" in match[0].evidence

    def test_cleartext_jwks_and_foreign_host(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document(jwks_uri="http://keys.example.net/jwks")).encode(),
            requested_issuer="https://auth.example.com",
        )
        assert by_id(provider.findings, "JWT-OIDC-004")[0].severity is Severity.HIGH
        assert by_id(provider.findings, "JWT-OIDC-005")[0].severity is Severity.MEDIUM

    def test_none_in_the_algorithm_list_is_high(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document(id_token_signing_alg_values_supported=["RS256", "none"])).encode(),
            requested_issuer="https://auth.example.com",
        )
        assert by_id(provider.findings, "JWT-OIDC-007")[0].severity is Severity.HIGH

    def test_wrong_metadata_type_is_not_also_reported_as_missing(self) -> None:
        document = provider_document(id_token_signing_alg_values_supported="RS256", issuer=12, jwks_uri=None)
        provider = parse_oidc_provider(json.dumps(document).encode(), requested_issuer="https://auth.example.com")
        assert by_id(provider.findings, "JWT-OIDC-030")
        assert not by_id(provider.findings, "JWT-OIDC-006")
        assert not by_id(provider.findings, "JWT-OIDC-001")
        assert by_id(provider.findings, "JWT-OIDC-003")

    def test_invalid_issuer_url_is_rejected(self) -> None:
        with pytest.raises(OidcError):
            discovery_url("not a url")


class TestTokenRole:
    def test_nonce_marks_an_id_token(self) -> None:
        report = analyze({"alg": "RS256", "typ": "JWT"}, id_payload())
        assert report.role is TokenRole.ID_TOKEN
        assert report.findings == ()
        assert report.passed == ("issuer", "audience", "expiration", "nonce")
        text = format_oidc_token(report)
        assert "Role : ID Token" in text
        assert "[✓] issuer" in text
        assert "[✓] audience" in text
        assert "[✓] expiration" in text
        assert "[✓] nonce" in text

    def test_at_jwt_marks_an_access_token(self) -> None:
        payload = {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "api",
            "exp": 2_000_000_000,
            "scope": "openid profile",
            "client_id": "app",
        }
        report = analyze({"alg": "RS256", "typ": "at+jwt"}, payload)
        assert report.role is TokenRole.ACCESS_TOKEN
        assert "scope" in report.passed
        assert not by_id(report.findings, "JWT-OIDC-019")
        assert not by_id(report.findings, "JWT-OIDC-015")

    def test_scope_without_at_jwt_is_still_an_access_token(self) -> None:
        payload = {"iss": "https://auth.example.com", "sub": "user", "aud": "api", "scope": "read"}
        report = analyze({"alg": "RS256", "typ": "JWT"}, payload)
        assert report.role is TokenRole.ACCESS_TOKEN
        match = by_id(report.findings, "JWT-OIDC-019")
        assert match[0].severity is Severity.LOW
        assert "[LOW] Access token typ is not at+jwt" in format_oidc_token(report)

    def test_conflicting_role_signals(self) -> None:
        report = analyze({"alg": "RS256", "typ": "at+jwt"}, id_payload(scope="openid"))
        role, conflict = classify_token(parse_jwt(make_token({"alg": "RS256", "typ": "at+jwt"}, id_payload(scope="openid"))))
        assert conflict is True
        assert role is TokenRole.ID_TOKEN
        assert report.role is TokenRole.ID_TOKEN
        assert by_id(report.findings, "JWT-OIDC-021")[0].severity is Severity.MEDIUM

    def test_analyzer_is_a_pipeline_stage(self) -> None:
        analyzer = OidcTokenAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "oidc"
        assert analyzer.analyze(parse_jwt(make_token({"alg": "RS256", "typ": "JWT"}, id_payload()))) == []


class TestOidcClaims:
    def test_multiple_audiences_and_missing_azp(self) -> None:
        report = analyze({"alg": "RS256", "typ": "JWT"}, id_payload(aud=["api", "account"]))
        assert by_id(report.findings, "JWT-OIDC-011")[0].title == "Multiple audiences detected"
        assert by_id(report.findings, "JWT-OIDC-012")[0].severity is Severity.MEDIUM
        assert "audience" in report.passed
        text = format_oidc_token(report)
        assert "[✓] audience" in text
        assert "[WARNING] Multiple audiences detected" in text

    def test_azp_outside_aud_is_high(self) -> None:
        report = analyze({"alg": "RS256", "typ": "JWT"}, id_payload(azp="other-client"))
        match = by_id(report.findings, "JWT-OIDC-013")
        assert match[0].severity is Severity.HIGH
        assert "other-client" not in match[0].evidence

    def test_missing_nonce_on_an_id_token(self) -> None:
        payload = id_payload(at_hash="hash")
        del payload["nonce"]
        report = analyze({"alg": "RS256", "typ": "JWT"}, payload)
        assert by_id(report.findings, "JWT-OIDC-015")[0].severity is Severity.LOW
        required = analyze(
            {"alg": "RS256", "typ": "JWT"},
            payload,
            OidcAnalysisConfig(require_nonce=True),
        )
        assert by_id(required.findings, "JWT-OIDC-015")[0].severity is Severity.MEDIUM

    def test_id_token_missing_expiration_is_high(self) -> None:
        payload = id_payload()
        del payload["exp"]
        report = analyze({"alg": "RS256", "typ": "JWT"}, payload)
        match = by_id(report.findings, "JWT-OIDC-020")
        assert any(item.severity is Severity.HIGH and "claim=exp" in item.evidence for item in match)
        assert "expiration" not in report.passed

    def test_invalid_auth_time_acr_and_amr(self) -> None:
        report = analyze(
            {"alg": "RS256", "typ": "JWT"},
            id_payload(auth_time="yesterday", acr="", amr="pwd"),
        )
        assert by_id(report.findings, "JWT-OIDC-016")
        assert by_id(report.findings, "JWT-OIDC-017")
        assert by_id(report.findings, "JWT-OIDC-018")
        assert "auth_time" not in report.passed
        assert "acr" not in report.passed
        assert "amr" not in report.passed

    def test_valid_amr_and_acr_pass(self) -> None:
        report = analyze(
            {"alg": "RS256", "typ": "JWT"},
            id_payload(auth_time=1_000_000_000, acr="urn:mace:incommon:iap:silver", amr=["pwd", "otp"]),
        )
        assert "auth_time" in report.passed
        assert "acr" in report.passed
        assert "amr" in report.passed

    def test_scope_must_be_a_string(self) -> None:
        report = analyze({"alg": "RS256", "typ": "at+jwt"}, {"scope": ["read"]})
        assert by_id(report.findings, "JWT-OIDC-022")[0].severity is Severity.MEDIUM

    def test_token_issuer_must_match_discovery(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document()).encode(),
            requested_issuer="https://auth.example.com",
        )
        report = analyze(
            {"alg": "RS256", "typ": "JWT"},
            id_payload(iss="https://evil.example.com"),
            OidcAnalysisConfig(discovery=provider),
        )
        match = by_id(report.findings, "JWT-OIDC-008")
        assert match[0].severity is Severity.HIGH
        assert "evil.example.com" in match[0].evidence
        assert "issuer" not in report.passed

    def test_token_algorithm_must_be_advertised(self) -> None:
        provider = parse_oidc_provider(
            json.dumps(provider_document()).encode(),
            requested_issuer="https://auth.example.com",
        )
        report = analyze(
            {"alg": "HS256", "typ": "JWT"},
            id_payload(),
            OidcAnalysisConfig(discovery=provider),
        )
        match = by_id(report.findings, "JWT-OIDC-009")
        assert match[0].severity is Severity.HIGH
        assert "alg=HS256" in match[0].evidence

    def test_expected_audience_is_enforced(self) -> None:
        report = analyze(
            {"alg": "RS256", "typ": "JWT"},
            id_payload(),
            OidcAnalysisConfig(expected_audience="account"),
        )
        assert by_id(report.findings, "JWT-OIDC-025")[0].severity is Severity.HIGH
        assert "audience" not in report.passed

    def test_injected_check_replaces_the_default_chain(self) -> None:
        class FlagCheck(OidcCheck):
            def check(self, token, config) -> list[Finding]:  # type: ignore[no-untyped-def]
                del token, config
                return [
                    Finding(
                        id="JWT-TEST-001",
                        title="Injected",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        description="injected",
                        evidence="injected=true",
                        impact="none",
                        remediation="none",
                    )
                ]

        report = OidcTokenAnalyzer(checks=(FlagCheck(),)).inspect(
            parse_jwt(make_token({"alg": "RS256", "typ": "JWT"}, id_payload(aud=["a", "b"])))
        )
        assert [item.id for item in report.findings] == ["JWT-TEST-001"]
