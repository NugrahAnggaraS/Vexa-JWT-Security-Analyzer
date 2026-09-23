"""CLI tests for analyze --format json and html."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest

from jwt_analyzer.cli import run


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token(header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}.{b64url(b'sig')}"


def payload(**extra: Any) -> dict[str, Any]:
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


class TestAnalyzeCommand:
    def test_json_format_is_machine_readable(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["analyze", token({"alg": "none", "typ": "JWT"}, payload()), "--format", "json"])
        document = json.loads(capsys.readouterr().out)
        assert code == 1
        assert document["schema_version"] == 1
        assert any(item["id"] == "JWT-ALG-001" and item["severity"] == "CRITICAL" for item in document["findings"])
        assert "risk_score" in document["summary"]

    def test_html_format_writes_a_standalone_file(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        destination = tmp_path / "report.html"
        code = run(
            [
                "analyze",
                token({"alg": "RS256", "typ": "JWT"}, payload()),
                "--format",
                "html",
                "--output",
                str(destination),
            ]
        )
        page = destination.read_text(encoding="utf-8")
        captured = capsys.readouterr()
        assert code == 0
        assert captured.out == ""
        assert page.startswith("<!DOCTYPE html>")
        assert "<script" not in page
        assert "<link" not in page
        assert "Executive Summary" in page
        assert "Risk Score :" in page

    def test_html_flag_accepts_a_path(self, tmp_path) -> None:
        destination = tmp_path / "appendix.html"
        code = run(["analyze", "--html", str(destination), token({"alg": "RS256", "typ": "JWT"}, payload())])
        assert code == 0
        assert "JWT Security Report" in destination.read_text(encoding="utf-8")

    def test_invalid_token_exits_with_invalid_input(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["analyze", "not-a-jwt", "--format", "json"])
        captured = capsys.readouterr()
        assert code == 2
        assert captured.out == ""
        assert captured.err
