"""Unit tests for configuration, modes, ignore rules, and CLI exit codes."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jwt_analyzer.cli import _read_token, run
from jwt_analyzer.config import (
    Settings,
    configure,
    get_settings,
    load_settings,
    severity_at_least,
)
from jwt_analyzer.engine import AnalysisConfig, AnalyzerEngine
from jwt_analyzer.exceptions import ConfigError
from jwt_analyzer.findings import Severity


NOW = 1_700_000_000
YAML = """
analysis:
  max_token_lifetime: 30
  check_sensitive_claims: true
  check_duplicate_claims: true
security:
  severity_threshold: LOW
report:
  format: json
  color: false
ignore:
  - JWT-ALG-001
mode: fast
"""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def claims(**extra: Any) -> dict[str, Any]:
    now = int(time.time())
    body: dict[str, Any] = {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": "id-1",
    }
    body.update(extra)
    return body


def provider_document() -> bytes:
    return json.dumps(
        {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "scopes_supported": ["openid"],
            "claims_supported": ["sub"],
        }
    ).encode("utf-8")


def jwks_document() -> bytes:
    key = {
        "kty": "RSA",
        "kid": "key-01",
        "use": "sig",
        "alg": "RS256",
        "n": b64uint((1 << 1023) + 1),
        "e": "AQAB",
    }
    return json.dumps({"keys": [key]}).encode("utf-8")


class TestConfigFile:
    def test_yaml_and_json_load_the_documented_options(self, tmp_path) -> None:
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(YAML, encoding="utf-8")
        loaded = load_settings(yaml_path)
        assert loaded.mode == "fast"
        assert loaded.max_token_lifetime == 30
        assert loaded.severity_threshold is Severity.LOW
        assert loaded.report_format == "json"
        assert loaded.color is False
        assert loaded.ignore == ("JWT-ALG-001",)

        json_path = tmp_path / "config.json"
        json_path.write_text(
            json.dumps(
                {
                    "analysis": {"max_token_lifetime": 30, "check_sensitive_claims": False},
                    "security": {"severity_threshold": "HIGH"},
                    "report": {"format": "terminal"},
                    "ignore": ["JWT-EXP-001"],
                }
            ),
            encoding="utf-8",
        )
        parsed = load_settings(json_path)
        assert parsed.check_sensitive_claims is False
        assert parsed.report_format == "text"
        assert parsed.ignore == ("JWT-EXP-001",)

    def test_invalid_configuration_raises(self, tmp_path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("security:\n  severity_threshold: EXTREME\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_settings(path)

    def test_shared_settings_can_be_replaced(self) -> None:
        original = get_settings()
        try:
            updated = configure(Settings(mode="assessment", issuer="https://auth.example.com"))
            assert get_settings() is updated
            assert get_settings().issuer == "https://auth.example.com"
        finally:
            configure(original)

    def test_threshold_orders_severities(self) -> None:
        assert severity_at_least(Severity.CRITICAL, Severity.HIGH)
        assert severity_at_least(Severity.HIGH, Severity.HIGH)
        assert not severity_at_least(Severity.MEDIUM, Severity.HIGH)


class TestEngineIgnore:
    def test_ignore_drops_a_finding_before_scoring(self) -> None:
        sample = token({"alg": "none", "typ": "JWT"}, claims(iat=NOW, nbf=NOW, exp=NOW + 60))
        kept = AnalyzerEngine(AnalysisConfig(now=NOW)).run(sample)
        suppressed = AnalyzerEngine(AnalysisConfig(now=NOW, ignore=frozenset({"JWT-ALG-001"}))).run(sample)
        assert any(item.id == "JWT-ALG-001" for item in kept.findings)
        assert all(item.id != "JWT-ALG-001" for item in suppressed.findings)
        assert suppressed.risk.score < kept.risk.score


class TestCliConfig:
    def test_help_lists_commands_and_shared_flags(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["--help"])
        text = capsys.readouterr().out
        assert code == 0
        for name in ("decode", "analyze", "assess", "verify", "compare", "batch", "jwks", "oidc", "report", "version"):
            assert name in text
        assert "--ignore-rule" in text
        assert "--config" in text
        assert "severity threshold" in text
        assert "configuration error" in text

        code = run(["analyze", "--help"])
        analyze_help = capsys.readouterr().out
        assert code == 0
        assert "--ignore-rule" in analyze_help
        assert "--config" in analyze_help
        assert "--severity-threshold" in analyze_help
        assert "Fast mode" in analyze_help or "offline" in analyze_help

    def test_config_is_overridden_by_flags(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        path = tmp_path / ".jwt-analyzer.yaml"
        path.write_text(YAML, encoding="utf-8")
        sample = token({"alg": "RS256", "typ": "JWT"}, claims())

        configured = run(["analyze", sample, "--config", str(path)])
        document = json.loads(capsys.readouterr().out)
        assert configured == 1
        assert any(item["id"] == "JWT-LIFE-001" for item in document["findings"])

        overridden = run(
            [
                "analyze",
                sample,
                "--config",
                str(path),
                "--format",
                "text",
                "--severity-threshold",
                "HIGH",
            ]
        )
        text = capsys.readouterr().out
        assert overridden == 0
        assert "JWT Security Analyzer" in text
        assert "JWT-LIFE-001" in text
        assert not text.lstrip().startswith("{")

    def test_ignore_rule_suppresses_a_high_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        sample = token({"alg": "none", "typ": "JWT"}, claims())
        code = run(["analyze", sample, "--ignore-rule", "JWT-ALG-001", "--format", "json"])
        document = json.loads(capsys.readouterr().out)
        assert code == 0
        assert all(item["id"] != "JWT-ALG-001" for item in document["findings"])

    def test_bad_config_exits_with_configuration_error(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("nope: true\n", encoding="utf-8")
        code = run(["analyze", token({"alg": "RS256", "typ": "JWT"}, claims()), "--config", str(path)])
        captured = capsys.readouterr()
        assert code == 3
        assert captured.out == ""
        assert "Unknown configuration keys" in captured.err

    def test_verbose_logs_to_stderr_and_keeps_json_on_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["analyze", token({"alg": "RS256", "typ": "JWT"}, claims()), "--format", "json", "--verbose"])
        captured = capsys.readouterr()
        assert code == 0
        assert json.loads(captured.out)["schema_version"] == 1
        assert "INFO jwt_analyzer" in captured.err
        assert "mode=fast" in captured.err

    def test_fast_mode_does_not_fetch(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        calls: list[str] = []

        def fetch_url(url: str, **kwargs: object) -> bytes:
            del kwargs
            calls.append(url)
            raise AssertionError(url)

        monkeypatch.setattr("jwt_analyzer.http_client.fetch_url", fetch_url)
        sample = token(
            {"alg": "RS256", "typ": "JWT", "jku": "https://auth.example.com/jwks"},
            claims(),
        )
        code = run(["analyze", sample, "--mode", "fast"])
        assert code == 0
        assert calls == []
        assert "JWT Security Analyzer" in capsys.readouterr().out

    def test_assessment_mode_fetches_discovery_and_jwks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        calls: list[str] = []

        def fetch_url(url: str, **kwargs: object) -> bytes:
            del kwargs
            calls.append(url)
            if url.endswith("openid-configuration"):
                return provider_document()
            if url.endswith("/jwks"):
                return jwks_document()
            raise AssertionError(url)

        monkeypatch.setattr("jwt_analyzer.http_client.fetch_url", fetch_url)
        code = run(
            [
                "assess",
                token({"alg": "RS256", "typ": "JWT", "kid": "key-01"}, claims()),
                "--issuer",
                "https://auth.example.com",
            ]
        )
        captured = capsys.readouterr()
        assert code in {0, 1}
        assert calls == [
            "https://auth.example.com/.well-known/openid-configuration",
            "https://auth.example.com/jwks",
        ]
        assert "JWT Security Analyzer" in captured.out

    def test_decode_version_and_report(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        sample = token({"alg": "RS256", "typ": "JWT"}, claims())
        assert run(["version"]) == 0
        assert capsys.readouterr().out.strip() == "0.1.0"

        assert run(["decode", sample]) == 0
        assert "Algorithm  : RS256" in capsys.readouterr().out

        saved = tmp_path / "report.json"
        assert run(["analyze", sample, "--format", "json", "--output", str(saved)]) == 0
        html_path = tmp_path / "report.html"
        assert run(["report", str(saved), "--format", "html", "--output", str(html_path)]) == 0
        page = html_path.read_text(encoding="utf-8")
        assert page.startswith("<!DOCTYPE html>")
        assert "<script" not in page
        assert "Executive Summary" in page

    def test_unstatable_token_string_stays_a_jwt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(self: object) -> bool:
            del self
            raise OSError(36, "File name too long")

        monkeypatch.setattr("jwt_analyzer.cli.Path.is_file", explode)
        sample = "header.payload.signature"
        assert _read_token(sample) == sample

    def test_long_compact_token_is_not_read_as_a_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        sample = token({"alg": "RS256", "typ": "JWT", "kid": "k" * 180}, claims())
        assert len(sample) > 255
        code = run(["analyze", sample, "--format", "json"])
        captured = capsys.readouterr()
        assert code == 0
        assert "File name too long" not in captured.err
        assert json.loads(captured.out)["schema_version"] == 1

    def test_public_key_verification(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = b64url(json.dumps({"sub": "user"}, separators=(",", ":")).encode())
        signature = private.sign(f"{header}.{payload}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        sample = f"{header}.{payload}.{b64url(signature)}"
        pem = tmp_path / "public.pem"
        pem.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        code = run(["verify", sample, "--public-key", str(pem)])
        assert code == 0
        assert "Signature verification successful" in capsys.readouterr().out

    def test_runtime_error_exits_4(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        class Boom:
            def __init__(self, config: object = None) -> None:
                del config

            def run(self, token: str) -> object:
                del token
                raise RuntimeError("boom")

        monkeypatch.setattr("jwt_analyzer.cli.AnalyzerEngine", Boom)
        code = run(["analyze", token({"alg": "RS256", "typ": "JWT"}, claims())])
        captured = capsys.readouterr()
        assert code == 4
        assert "boom" in captured.err
