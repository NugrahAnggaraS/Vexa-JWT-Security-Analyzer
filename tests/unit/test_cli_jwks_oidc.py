"""CLI tests for JWKS listing, OIDC discovery, and --jwks-url verification."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jwt_analyzer.cli import run


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def jwks_bytes(keys: list[dict[str, Any]]) -> bytes:
    return json.dumps({"keys": keys}).encode("utf-8")


def rsa_token(private: rsa.RSAPrivateKey, kid: str = "key-01") -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    payload = b64url(json.dumps({"sub": "user"}, separators=(",", ":")).encode())
    signing = f"{header}.{payload}".encode("ascii")
    signature = private.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{b64url(signature)}"


def provider_document() -> bytes:
    return json.dumps(
        {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "scopes_supported": ["openid"],
            "claims_supported": ["sub"],
        }
    ).encode("utf-8")


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_jwk(private: rsa.RSAPrivateKey) -> dict[str, Any]:
    numbers = private.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": "key-01",
        "use": "sig",
        "alg": "RS256",
        "n": b64uint(numbers.n),
        "e": b64uint(numbers.e),
    }


class TestJwksCommand:
    def test_prints_key_metadata(self, tmp_path, capsys: pytest.CaptureFixture[str], rsa_private: rsa.RSAPrivateKey) -> None:
        path = tmp_path / "jwks.json"
        path.write_bytes(jwks_bytes([rsa_jwk(rsa_private)]))
        code = run(["jwks", str(path)])
        output = capsys.readouterr().out

        assert code == 0
        assert "kid    : key-01" in output
        assert "kty    : RSA" in output
        assert "use    : sig" in output
        assert "alg    : RS256" in output
        assert "Findings : none" in output

    def test_warns_about_a_suspicious_key(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        key = {
            "kty": "RSA",
            "kid": "key-01",
            "use": "sig",
            "alg": "RS256",
            "n": b64uint((1 << 1023) + 1),
            "e": "AQAB",
            "d": "cHJpdmF0ZS1tYXRlcmlhbC1tdXN0LXN0YXktaGlkZGVu",
        }
        path = tmp_path / "jwks.json"
        path.write_bytes(jwks_bytes([key]))
        code = run(["jwks", str(path)])
        captured = capsys.readouterr()

        assert code == 1
        assert "JWT-JWKS-008" in captured.out
        assert "Private key material published" in captured.out
        assert key["d"] not in captured.out

    def test_missing_file_is_invalid_input(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["jwks", str(tmp_path / "missing.json")])
        captured = capsys.readouterr()
        assert code == 2
        assert "not found" in captured.err.lower()


class TestVerifyCommand:
    def test_jwks_url_selects_the_key_by_kid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        rsa_private: rsa.RSAPrivateKey,
    ) -> None:
        body = jwks_bytes([rsa_jwk(rsa_private)])

        def fetch_url(url: str, **kwargs: object) -> bytes:
            assert url == "https://auth.example.com/jwks.json"
            assert kwargs["timeout"]
            return body

        monkeypatch.setattr("jwt_analyzer.http_client.fetch_url", fetch_url)
        code = run(["verify", rsa_token(rsa_private), "--jwks-url", "https://auth.example.com/jwks.json"])
        output = capsys.readouterr().out

        assert code == 0
        assert "[✓] Matching key found" in output
        assert "[✓] Signature verified" in output

    def test_requires_a_jwks_location(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run(["verify", "header.payload.signature"])
        captured = capsys.readouterr()
        assert code == 2
        assert "--jwks-url" in captured.err


class TestOidcCommand:
    def test_prints_provider_and_supported_algorithms(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def fetch_url(url: str, **kwargs: object) -> bytes:
            del kwargs
            assert url == "https://auth.example.com/.well-known/openid-configuration"
            return provider_document()

        monkeypatch.setattr("jwt_analyzer.http_client.fetch_url", fetch_url)
        code = run(["oidc", "https://auth.example.com"])
        output = capsys.readouterr().out

        assert code == 0
        assert "issuer : https://auth.example.com" in output
        assert "id_token_signing_alg_values_supported : RS256, ES256" in output
        assert "jwks_uri : https://auth.example.com/jwks" in output

    def test_compares_token_issuer_with_discovery(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr("jwt_analyzer.http_client.fetch_url", lambda url, **kwargs: provider_document())
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = b64url(
            json.dumps(
                {
                    "iss": "https://evil.example.com",
                    "sub": "user",
                    "aud": "api",
                    "exp": 2_000_000_000,
                    "iat": 1_000_000_000,
                    "nonce": "n-1",
                }
            ).encode()
        )
        token = f"{header}.{payload}.{b64url(b'sig')}"
        code = run(["oidc", "https://auth.example.com", "--token", token])
        output = capsys.readouterr().out

        assert code == 1
        assert "Role : ID Token" in output
        assert "Token issuer does not match the OpenID Provider" in output
