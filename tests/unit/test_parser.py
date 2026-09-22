"""Unit tests for JWT parser and compact JWS structure validation."""

from __future__ import annotations

import base64
import json

import pytest

from jwt_analyzer.exceptions import JWTParseError
from jwt_analyzer.parser import JWTParser, parse_jwt

# jwt.io HS256 example (signature is not verified by the parser).
JWT_IO_EXAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, signature: bytes | str = b"sig") -> str:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    if isinstance(signature, str):
        signature_seg = signature
    else:
        signature_seg = b64url(signature)
    return f"{header_seg}.{payload_seg}.{signature_seg}"


class TestValidTokens:
    def test_parse_standard_jwt_io_example(self) -> None:
        parsed = parse_jwt(JWT_IO_EXAMPLE)

        assert parsed.header["alg"] == "HS256"
        assert parsed.header["typ"] == "JWT"
        assert parsed.payload["sub"] == "1234567890"
        assert parsed.payload["name"] == "John Doe"
        assert parsed.payload["iat"] == 1516239022
        assert parsed.metadata.alg == "HS256"
        assert parsed.metadata.typ == "JWT"
        assert parsed.metadata.sub == "1234567890"
        assert parsed.metadata.iat == 1516239022
        assert parsed.custom_claims == {"name": "John Doe"}
        assert parsed.signature

    def test_extracts_all_registered_claims_and_header_fields(self) -> None:
        token = make_token(
            {"alg": "RS256", "typ": "JWT", "kid": "key-01", "cty": "JWT"},
            {
                "iss": "https://auth.example.com",
                "sub": "user-123",
                "aud": ["api", "admin"],
                "exp": 1_900_000_000,
                "iat": 1_700_000_000,
                "nbf": 1_700_000_100,
                "jti": "token-id-1",
            },
        )
        parsed = parse_jwt(token)

        assert parsed.metadata.alg == "RS256"
        assert parsed.metadata.typ == "JWT"
        assert parsed.metadata.kid == "key-01"
        assert parsed.metadata.cty == "JWT"
        assert parsed.metadata.iss == "https://auth.example.com"
        assert parsed.metadata.sub == "user-123"
        assert parsed.metadata.aud == ["api", "admin"]
        assert parsed.metadata.exp == 1_900_000_000
        assert parsed.metadata.iat == 1_700_000_000
        assert parsed.metadata.nbf == 1_700_000_100
        assert parsed.metadata.jti == "token-id-1"
        assert parsed.custom_claims == {}

    def test_extracts_custom_claims(self) -> None:
        token = make_token(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "abc", "role": "admin", "tenant": "acme", "permissions": ["read"]},
        )
        parsed = parse_jwt(token)

        assert parsed.custom_claims == {
            "role": "admin",
            "tenant": "acme",
            "permissions": ["read"],
        }
        assert "sub" not in parsed.custom_claims

    def test_unsecured_jwt_with_empty_signature(self) -> None:
        token = make_token({"alg": "none", "typ": "JWT"}, {"sub": "anon"}, signature=b"")
        parsed = parse_jwt(token)

        assert parsed.metadata.alg == "none"
        assert parsed.signature == b""
        assert parsed.signature_segment == ""

    def test_string_audience_is_preserved(self) -> None:
        token = make_token({"alg": "HS256"}, {"aud": "api"})
        parsed = parse_jwt(token)
        assert parsed.metadata.aud == "api"

    def test_strips_surrounding_whitespace(self) -> None:
        token = make_token({"alg": "HS256"}, {"sub": "x"})
        parsed = parse_jwt(f"  \n{token}\n  ")
        assert parsed.payload["sub"] == "x"

    def test_readable_output_contains_metadata(self) -> None:
        token = make_token(
            {"alg": "HS256", "typ": "JWT", "kid": "k1"},
            {"iss": "https://issuer", "role": "admin"},
        )
        text = parse_jwt(token).to_readable()

        assert "Algorithm  : HS256" in text
        assert "Type       : JWT" in text
        assert "Key ID     : k1" in text
        assert "Issuer     : https://issuer" in text
        assert "Custom Claims:" in text
        assert "role: admin" in text

    def test_to_dict_includes_header_payload_and_custom_claims(self) -> None:
        token = make_token({"alg": "HS256"}, {"sub": "u1", "plan": "pro"})
        data = parse_jwt(token).to_dict()

        assert data["header"]["alg"] == "HS256"
        assert data["payload"]["sub"] == "u1"
        assert data["metadata"]["sub"] == "u1"
        assert data["custom_claims"] == {"plan": "pro"}

    def test_parser_class_matches_module_helper(self) -> None:
        token = make_token({"alg": "HS256"}, {"sub": "same"})
        assert JWTParser().parse(token).payload == parse_jwt(token).payload


class TestMalformedTokens:
    def test_empty_string(self) -> None:
        with pytest.raises(JWTParseError, match="Token is empty") as exc:
            parse_jwt("")
        assert exc.value.code == "EMPTY_TOKEN"

    def test_whitespace_only(self) -> None:
        with pytest.raises(JWTParseError, match="Token is empty"):
            parse_jwt("   \n\t  ")

    def test_none_token(self) -> None:
        with pytest.raises(JWTParseError, match="Token is empty") as exc:
            parse_jwt(None)  # type: ignore[arg-type]
        assert exc.value.code == "EMPTY_TOKEN"

    def test_non_string_token(self) -> None:
        with pytest.raises(JWTParseError, match="Token must be a string") as exc:
            parse_jwt(12345)  # type: ignore[arg-type]
        assert exc.value.code == "INVALID_TYPE"

    @pytest.mark.parametrize(
        ("token", "found"),
        [
            ("onlyone", 1),
            ("header.payload", 2),
            ("a.b.c.d", 4),
        ],
    )
    def test_wrong_segment_count(self, token: str, found: int) -> None:
        with pytest.raises(
            JWTParseError,
            match=rf"Expected 3 segments, found {found}",
        ) as exc:
            parse_jwt(token)
        assert exc.value.code == "INVALID_SEGMENT_COUNT"

    def test_jwe_five_segments_is_out_of_scope(self) -> None:
        with pytest.raises(JWTParseError, match="out of scope") as exc:
            parse_jwt("a.b.c.d.e")
        assert exc.value.code == "JWE_UNSUPPORTED"
        assert "Expected 3 segments, found 5" in str(exc.value)

    def test_invalid_base64url_characters_in_header(self) -> None:
        token = "+++.e30.e30"
        with pytest.raises(JWTParseError, match="Invalid base64url encoding in header") as exc:
            parse_jwt(token)
        assert exc.value.code == "INVALID_BASE64URL"

    def test_padded_base64url_is_rejected(self) -> None:
        header = b64url(b'{"alg":"HS256"}') + "="
        payload = b64url(b'{"sub":"x"}')
        token = f"{header}.{payload}.e30"
        with pytest.raises(JWTParseError, match="Invalid base64url encoding in header"):
            parse_jwt(token)

    def test_invalid_base64url_length_in_payload(self) -> None:
        header = b64url(b'{"alg":"HS256"}')
        token = f"{header}.abcde.e30"
        with pytest.raises(JWTParseError, match="Invalid base64url encoding in payload"):
            parse_jwt(token)

    def test_invalid_json_in_payload(self) -> None:
        header = b64url(b'{"alg":"HS256"}')
        payload = b64url(b"{not-json")
        token = f"{header}.{payload}.e30"
        with pytest.raises(JWTParseError, match="Invalid JSON in payload") as exc:
            parse_jwt(token)
        assert exc.value.code == "INVALID_JSON"

    def test_header_json_array_is_rejected(self) -> None:
        header = b64url(b'["HS256"]')
        payload = b64url(b'{"sub":"x"}')
        token = f"{header}.{payload}.e30"
        with pytest.raises(JWTParseError, match="Header must be a JSON object") as exc:
            parse_jwt(token)
        assert exc.value.code == "INVALID_JSON_TYPE"

    def test_payload_json_array_is_rejected(self) -> None:
        header = b64url(b'{"alg":"HS256"}')
        payload = b64url(b'["claim"]')
        token = f"{header}.{payload}.e30"
        with pytest.raises(JWTParseError, match="Payload must be a JSON object"):
            parse_jwt(token)

    def test_empty_header_segment(self) -> None:
        payload = b64url(b'{"sub":"x"}')
        with pytest.raises(JWTParseError, match="Invalid JSON in header") as exc:
            parse_jwt(f".{payload}.e30")
        assert exc.value.code == "INVALID_JSON"

    def test_non_utf8_header(self) -> None:
        header = b64url(b"\xff\xfe")
        payload = b64url(b'{"sub":"x"}')
        with pytest.raises(JWTParseError, match="Header is not valid UTF-8") as exc:
            parse_jwt(f"{header}.{payload}.e30")
        assert exc.value.code == "INVALID_UTF8"

    def test_error_message_is_informative(self) -> None:
        with pytest.raises(JWTParseError) as exc:
            parse_jwt("a.b")
        assert str(exc.value) == "Expected 3 segments, found 2"
