"""Unit tests for JWT diff and privilege comparison."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from jwt_analyzer.analyzers.compare import (
    ComparisonCheck,
    compare_tokens,
    format_comparison,
)
from jwt_analyzer.exceptions import CompareError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import parse_jwt


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def body(role: str = "user", lifetime: int = 3600, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "iat": 1_000,
        "nbf": 1_000,
        "exp": 1_000 + lifetime,
        "jti": "1",
        "role": role,
    }
    payload.update(extra)
    return payload


def parsed(header: dict[str, Any], payload: dict[str, Any]):
    return parse_jwt(token(header, payload))


def by_id(findings, finding_id: str):
    return [item for item in findings if item.id == finding_id]


class TestComparison:
    def test_diff_shows_algorithm_role_and_lifetime(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT", "kid": "key-01"}, body("user", 3600)),
                parsed({"alg": "HS256", "typ": "JWT", "kid": "key-02"}, body("admin", 86400)),
            ]
        )
        text = format_comparison(report)

        assert "JWT COMPARISON" in text
        assert "Header" in text
        assert "alg:" in text
        assert "token1 = RS256" in text
        assert "token2 = HS256" in text
        assert "kid:" in text
        assert "token1 = key-01" in text
        assert "token2 = key-02" in text
        assert "Payload" in text
        assert "role:" in text
        assert "token1 = user" in text
        assert "token2 = admin" in text
        assert "exp:" in text
        assert "token1 = 3600s" in text
        assert "token2 = 86400s" in text
        assert "iss:" not in text

    def test_user_to_admin_is_privilege_escalation(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("admin")),
            ]
        )
        match = by_id(report.findings, "JWT-CMP-001")
        assert match[0].severity is Severity.HIGH
        assert "role" in match[0].evidence
        assert "user" in match[0].evidence
        assert "admin" in match[0].evidence
        assert "[HIGH] JWT-CMP-001 Privilege escalation" in format_comparison(report)

    def test_admin_to_user_is_not_escalation(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("admin")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
            ]
        )
        assert not by_id(report.findings, "JWT-CMP-001")
        assert "token2 = user" in format_comparison(report)

    def test_nested_roles_are_compared(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("user", realm_access={"roles": ["user"]})),
                parsed({"alg": "RS256", "typ": "JWT"}, body("user", realm_access={"roles": ["admin"]})),
            ]
        )
        match = by_id(report.findings, "JWT-CMP-001")
        assert match[0].severity is Severity.HIGH
        assert "realm_access.roles" in match[0].evidence
        assert "realm_access.roles:" in format_comparison(report)

    def test_asymmetric_to_hmac_is_a_weaker_algorithm(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body()),
                parsed({"alg": "HS256", "typ": "JWT"}, body()),
            ]
        )
        match = by_id(report.findings, "JWT-CMP-002")
        assert match[0].severity is Severity.HIGH
        assert "RS256" in match[0].evidence
        assert "HS256" in match[0].evidence

    def test_algorithm_none_is_weaker(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body()),
                parsed({"alg": "none", "typ": "JWT"}, body()),
            ]
        )
        assert by_id(report.findings, "JWT-CMP-002")[0].severity is Severity.HIGH

    def test_issuer_and_widened_audience(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body(aud="api")),
                parsed({"alg": "RS256", "typ": "JWT"}, body(aud=["api", "admin"], iss="https://other.example.com")),
            ]
        )
        assert by_id(report.findings, "JWT-CMP-003")[0].severity is Severity.MEDIUM
        audience = by_id(report.findings, "JWT-CMP-004")
        assert audience[0].title == "Audience widened"

    def test_identical_tokens_have_no_differences(self) -> None:
        first = parsed({"alg": "RS256", "typ": "JWT"}, body())
        report = compare_tokens([first, first])
        assert report.diffs == ()
        assert report.findings == ()
        assert format_comparison(report).endswith("No differences")

    def test_color_marks_removed_and_added_values(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("admin")),
            ]
        )
        text = format_comparison(report, color=True)
        assert "\033[31muser\033[0m" in text
        assert "\033[32madmin\033[0m" in text
        plain = format_comparison(report, color=False)
        assert "\033[" not in plain

    def test_three_tokens_use_the_first_as_baseline(self) -> None:
        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("admin")),
            ],
            labels=("baseline", "same", "raised"),
        )
        assert by_id(report.findings, "JWT-CMP-001")
        text = format_comparison(report)
        assert "baseline = user" in text
        assert "raised = admin" in text

    def test_fewer_than_two_tokens_is_rejected(self) -> None:
        with pytest.raises(CompareError) as caught:
            compare_tokens([parsed({"alg": "RS256", "typ": "JWT"}, body())])
        assert caught.value.code == "TOO_FEW_TOKENS"

    def test_injected_check_replaces_the_default_chain(self) -> None:
        class FlagCheck(ComparisonCheck):
            def check(self, tokens, labels):  # type: ignore[no-untyped-def]
                del tokens
                return [], [
                    Finding(
                        id="JWT-TEST-001",
                        title="Injected",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        description="injected",
                        evidence=f"labels={','.join(labels)}",
                        impact="none",
                        remediation="none",
                    )
                ]

        report = compare_tokens(
            [
                parsed({"alg": "RS256", "typ": "JWT"}, body("user")),
                parsed({"alg": "RS256", "typ": "JWT"}, body("admin")),
            ],
            checks=(FlagCheck(),),
        )
        assert [item.id for item in report.findings] == ["JWT-TEST-001"]
        assert report.diffs == ()
