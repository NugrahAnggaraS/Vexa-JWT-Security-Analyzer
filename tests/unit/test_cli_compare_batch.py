"""CLI tests for token comparison and batch analysis."""

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


def payload(role: str, lifetime: int = 3600) -> dict[str, Any]:
    return {
        "iss": "https://auth.example.com",
        "sub": "user",
        "aud": "api",
        "iat": 1_000,
        "nbf": 1_000,
        "exp": 1_000 + lifetime,
        "jti": "1",
        "role": role,
    }


def secure() -> str:
    now = int(time.time())
    return token(
        {"alg": "RS256", "typ": "JWT"},
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "api",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
            "jti": "id-1",
        },
    )


class TestCompareCommand:
    def test_prints_a_colored_diff_for_a_role_change(self, capsys: pytest.CaptureFixture[str]) -> None:
        user = token({"alg": "RS256", "typ": "JWT"}, payload("user", 3600))
        admin = token({"alg": "RS256", "typ": "JWT"}, payload("admin", 86400))
        code = run(["compare", "--color", user, admin])
        output = capsys.readouterr().out

        assert code == 1
        assert "token1 = \033[31muser\033[0m" in output
        assert "token2 = \033[32madmin\033[0m" in output
        assert "token1 = \033[31m3600s\033[0m" in output
        assert "token2 = \033[32m86400s\033[0m" in output
        assert "Privilege escalation" in output

    def test_file_names_are_the_diff_labels(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        first = tmp_path / "user.jwt"
        second = tmp_path / "admin.jwt"
        first.write_text(token({"alg": "RS256", "typ": "JWT"}, payload("user")), encoding="utf-8")
        second.write_text(token({"alg": "RS256", "typ": "JWT"}, payload("admin")), encoding="utf-8")
        code = run(["compare", "--no-color", str(first), str(second)])
        output = capsys.readouterr().out

        assert code == 1
        assert "user.jwt = user" in output
        assert "admin.jwt = admin" in output
        assert "\033[" not in output

    def test_one_token_is_invalid_input(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["compare", token({"alg": "RS256", "typ": "JWT"}, payload("user"))])
        captured = capsys.readouterr()
        assert code == 2
        assert "two tokens" in captured.err.lower()


class TestBatchCommand:
    def test_file_prints_an_aggregate_report(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        path = tmp_path / "tokens.txt"
        none = token({"alg": "none", "typ": "JWT"}, json.loads(json.dumps({
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "api",
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "exp": int(time.time()) + 60,
            "jti": "id-2",
        })))
        path.write_text(f"{secure()}\n{none}\n", encoding="utf-8")
        code = run(["batch", "--file", str(path), "--workers", "2"])
        output = capsys.readouterr().out

        assert code == 1
        assert "TOKEN ANALYSIS" in output
        assert "Tokens     : 2" in output
        assert "Secure     : 1" in output
        assert "Critical   : 1" in output
        assert "Summary" in output

    def test_directory_is_accepted(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        folder = tmp_path / "tokens"
        folder.mkdir()
        (folder / "token-001.jwt").write_text(secure(), encoding="utf-8")
        code = run(["batch", str(folder)])
        output = capsys.readouterr().out
        assert code == 0
        assert "token-001.jwt" in output
        assert "✓ Secure" in output

    def test_missing_source_is_invalid_input(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["batch", str(tmp_path / "missing")])
        captured = capsys.readouterr()
        assert code == 2
        assert "not found" in captured.err.lower()
