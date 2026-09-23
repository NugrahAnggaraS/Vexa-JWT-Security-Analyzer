"""CLI-to-report checks used as a pipeline security gate."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from jwt_analyzer.cli import run


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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


def test_clean_token_writes_json_and_html(tmp_path, capsys) -> None:
    sample = token({"alg": "RS256", "typ": "JWT"}, claims())
    report = tmp_path / "report.json"
    code = run(["analyze", sample, "--severity-threshold", "HIGH", "--format", "json", "--output", str(report)])
    captured = capsys.readouterr()
    document = json.loads(report.read_text(encoding="utf-8"))
    assert code == 0
    assert captured.out == ""
    assert document["schema_version"] == 1
    assert document["summary"]["risk_score_max"] == 100
    assert "manual security assessment" in document["disclaimer"]

    page = tmp_path / "report.html"
    assert run(["report", str(report), "--format", "html", "--output", str(page)]) == 0
    html = page.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "<script" not in html
    assert "Executive Summary" in html
    assert "Security Findings" in html


def test_high_finding_fails_the_gate(tmp_path) -> None:
    sample = token({"alg": "none", "typ": "JWT"}, claims())
    report = tmp_path / "report.json"
    code = run(
        [
            "analyze",
            sample,
            "--severity-threshold",
            "HIGH",
            "--format",
            "json",
            "--output",
            str(report),
        ]
    )
    document = json.loads(report.read_text(encoding="utf-8"))
    assert code == 1
    assert any(item["id"] == "JWT-ALG-001" and item["severity"] == "CRITICAL" for item in document["findings"])


def test_ignore_rule_lets_the_gate_pass(capsys) -> None:
    sample = token({"alg": "none", "typ": "JWT"}, claims())
    code = run(["analyze", sample, "--ignore-rule", "JWT-ALG-001", "--format", "json"])
    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert all(item["id"] != "JWT-ALG-001" for item in document["findings"])


def test_malformed_token_is_invalid_input(capsys) -> None:
    code = run(["analyze", "not-a-jwt", "--format", "json"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert captured.err.strip()
