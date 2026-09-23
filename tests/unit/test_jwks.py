"""Unit tests for JWKS parsing, key checks, and kid-based verification."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.jwks import (
    FileJwksSource,
    JwkCheck,
    JwksAnalysisConfig,
    JwksAnalyzer,
    UrlJwksSource,
    format_jwks_analysis,
    get_jwks_source,
    load_jwks,
    match_token,
    parse_jwks,
)
from jwt_analyzer.exceptions import JwksError, RemoteFetchError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.http_client import SafeRedirectHandler, validate_remote_url
from jwt_analyzer.parser import parse_jwt


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def jwks_bytes(keys: list[dict[str, Any]]) -> bytes:
    return json.dumps({"keys": keys}).encode("utf-8")


def rsa_jwk(private: rsa.RSAPrivateKey, kid: str = "key-01", alg: str = "RS256", **extra: Any) -> dict[str, Any]:
    numbers = private.public_key().public_numbers()
    key = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": b64uint(numbers.n),
        "e": b64uint(numbers.e),
    }
    key.update(extra)
    return key


def placeholder_rsa_jwk(kid: str = "key-01", bits: int = 2048, **extra: Any) -> dict[str, Any]:
    key = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64uint((1 << (bits - 1)) + 1),
        "e": b64uint(65537),
    }
    key.update(extra)
    return key


def segments(header: dict[str, Any], payload: dict[str, Any]) -> tuple[bytes, str]:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}".encode("ascii"), f"{header_seg}.{payload_seg}"


def rsa_token(private: rsa.RSAPrivateKey, alg: str = "RS256", kid: str = "key-01", payload: dict | None = None) -> str:
    body = {"sub": "user"} if payload is None else payload
    hash_alg = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}[alg]
    signing, prefix = segments({"alg": alg, "typ": "JWT", "kid": kid}, body)
    signature = private.sign(signing, padding.PKCS1v15(), hash_alg())
    return f"{prefix}.{b64url(signature)}"


def ec_token(private: ec.EllipticCurvePrivateKey, kid: str = "ec-1") -> str:
    signing, prefix = segments({"alg": "ES256", "typ": "JWT", "kid": kid}, {"sub": "user"})
    der = private.sign(signing, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der)
    raw = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    return f"{prefix}.{b64url(raw)}"


def hmac_token(secret: bytes, kid: str = "h1") -> str:
    import hashlib
    import hmac

    signing, prefix = segments({"alg": "HS256", "typ": "JWT", "kid": kid}, {"sub": "user"})
    signature = hmac.new(secret, signing, hashlib.sha256).digest()
    return f"{prefix}.{b64url(signature)}"


def by_id(findings: list[Finding] | tuple[Finding, ...], finding_id: str) -> list[Finding]:
    return [item for item in findings if item.id == finding_id]


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_private() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class TestJwksParsing:
    def test_parses_rsa_metadata(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private)]))
        key = document.keys[0]

        assert key.kid == "key-01"
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.modulus_bits == 2048
        assert key.e == "AQAB"
        assert document.all_findings == ()

        text = format_jwks_analysis(document)
        assert "JWKS Analysis" in text
        assert "kid    : key-01" in text
        assert "kty    : RSA" in text
        assert "use    : sig" in text
        assert "alg    : RS256" in text
        assert "n      : present (2048 bits)" in text
        assert "e      : AQAB" in text
        assert "Findings : none" in text

    def test_rejects_invalid_json(self) -> None:
        with pytest.raises(JwksError) as caught:
            parse_jwks(b"{")
        assert caught.value.code == "INVALID_JWKS"

    def test_rejects_a_document_without_a_keys_array(self) -> None:
        with pytest.raises(JwksError):
            parse_jwks(b'{"keys": {}}')

    def test_rejects_too_many_keys(self) -> None:
        keys = [placeholder_rsa_jwk(kid=str(index)) for index in range(129)]
        with pytest.raises(JwksError) as caught:
            parse_jwks(jwks_bytes(keys))
        assert caught.value.code == "TOO_MANY_KEYS"

    def test_invalid_key_entry_does_not_drop_the_rest(self) -> None:
        document = parse_jwks(jwks_bytes(["nope", placeholder_rsa_jwk()]))
        assert by_id(document.keys[0].findings, "JWT-JWKS-014")
        assert document.keys[1].kid == "key-01"

    def test_injected_check_replaces_the_default_chain(self) -> None:
        class FlagCheck(JwkCheck):
            def check(self, key: dict, index: int) -> list[Finding]:
                del key, index
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

        document = parse_jwks(jwks_bytes([{"kty": "RSA"}]), key_checks=(FlagCheck(),))
        assert by_id(document.keys[0].findings, "JWT-TEST-001")
        assert not by_id(document.all_findings, "JWT-JWKS-005")


class TestKeyConfiguration:
    def test_weak_modulus_is_high(self) -> None:
        document = parse_jwks(jwks_bytes([placeholder_rsa_jwk(bits=1024)]))
        match = by_id(document.all_findings, "JWT-JWKS-007")
        assert match[0].severity is Severity.HIGH
        assert "modulus_bits=1024" in match[0].evidence

    def test_incomplete_rsa_parameters(self) -> None:
        document = parse_jwks(jwks_bytes([{"kty": "RSA", "kid": "key-01", "use": "sig", "n": b64uint(65537)}]))
        match = by_id(document.all_findings, "JWT-JWKS-005")
        assert match[0].severity is Severity.HIGH
        assert "e" in match[0].evidence

    def test_incomplete_ec_key(self) -> None:
        document = parse_jwks(jwks_bytes([{"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": b64uint(1)}]))
        match = by_id(document.all_findings, "JWT-JWKS-006")
        assert "y" in match[0].evidence

    def test_algorithm_does_not_match_key_type(self) -> None:
        key = placeholder_rsa_jwk(alg="ES256")
        document = parse_jwks(jwks_bytes([key]))
        match = by_id(document.all_findings, "JWT-JWKS-004")
        assert match[0].severity is Severity.HIGH
        assert "alg=ES256" in match[0].evidence

    def test_duplicate_kid(self) -> None:
        document = parse_jwks(jwks_bytes([placeholder_rsa_jwk("same"), placeholder_rsa_jwk("same")]))
        match = by_id(document.findings, "JWT-JWKS-002")
        assert match[0].severity is Severity.HIGH
        assert "kid=same" in match[0].evidence

    def test_private_material_is_critical_and_not_echoed(self) -> None:
        secret = "cHJpdmF0ZS1leHBvbmVudC1tdXN0LXN0YXktaGlkZGVu"
        key = placeholder_rsa_jwk(d=secret)
        document = parse_jwks(jwks_bytes([key]))
        match = by_id(document.all_findings, "JWT-JWKS-008")
        assert match[0].severity is Severity.CRITICAL
        assert "parameters=d" in match[0].evidence
        assert secret not in match[0].evidence
        assert secret not in match[0].description

    def test_published_symmetric_key_is_high_and_not_echoed(self) -> None:
        secret = b"super-secret-value"
        encoded = b64url(secret)
        document = parse_jwks(
            jwks_bytes([{"kty": "oct", "kid": "h1", "use": "sig", "alg": "HS256", "k": encoded}])
        )
        match = by_id(document.all_findings, "JWT-JWKS-009")
        assert match[0].title == "Symmetric key published in JWKS"
        assert match[0].severity is Severity.HIGH
        assert encoded not in match[0].evidence
        assert "super-secret-value" not in match[0].evidence
        text = format_jwks_analysis(document)
        assert "k      : present" in text
        assert encoded not in text

    def test_use_and_key_ops_conflict(self) -> None:
        key = placeholder_rsa_jwk(key_ops=["encrypt"])
        document = parse_jwks(jwks_bytes([key]))
        match = by_id(document.all_findings, "JWT-JWKS-010")
        assert match[0].severity is Severity.HIGH
        assert "use=sig" in match[0].evidence

    def test_none_algorithm_on_a_key_is_high(self) -> None:
        key = placeholder_rsa_jwk(alg="none")
        document = parse_jwks(jwks_bytes([key]))
        assert by_id(document.all_findings, "JWT-JWKS-018")[0].severity is Severity.HIGH

    def test_rotation_set_is_informational(self) -> None:
        document = parse_jwks(jwks_bytes([placeholder_rsa_jwk("one"), placeholder_rsa_jwk("two")]))
        match = by_id(document.findings, "JWT-JWKS-013")
        assert match[0].severity is Severity.INFO
        assert "signing_keys=2" in match[0].evidence

    def test_no_signature_keys(self) -> None:
        document = parse_jwks(jwks_bytes([{"kty": "RSA", "kid": "enc", "use": "enc", "n": b64uint((1 << 2047) + 1), "e": "AQAB"}]))
        assert by_id(document.findings, "JWT-JWKS-012")[0].severity is Severity.HIGH

    def test_missing_kid_on_several_keys(self) -> None:
        key = placeholder_rsa_jwk()
        del key["kid"]
        other = placeholder_rsa_jwk("kept")
        document = parse_jwks(jwks_bytes([key, other]))
        match = by_id(document.findings, "JWT-JWKS-001")
        assert match[0].severity is Severity.MEDIUM


class TestVerification:
    def test_matching_kid_verifies_rsa(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private)]))
        token = parse_jwt(rsa_token(rsa_private))
        report = match_token(token, document)

        assert report.matched is True
        assert report.algorithm_matches is True
        assert report.key_type_matches is True
        assert report.signature_valid is True
        assert by_id(report.findings, "JWT-JWKS-024")[0].severity is Severity.INFO
        text = format_jwks_analysis(document, report)
        assert "[✓] Matching key found" in text
        assert "[✓] Algorithm matches" in text
        assert "[✓] Key type matches" in text
        assert "[✓] Signature verified" in text

    def test_analyzer_is_a_pipeline_stage(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private)]))
        analyzer = JwksAnalyzer(JwksAnalysisConfig(document=document))
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "jwks"
        findings = analyzer.analyze(parse_jwt(rsa_token(rsa_private)))
        assert by_id(findings, "JWT-JWKS-024")

    def test_passive_analyzer_does_not_fetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise AssertionError("JWKS was fetched")

        monkeypatch.setattr("jwt_analyzer.analyzers.jwks.load_jwks", boom)
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "user"}
        token = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}.{b64url(b'sig')}"
        assert JwksAnalyzer().analyze(parse_jwt(token)) == []

    def test_unknown_kid(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private, kid="key-01")]))
        report = match_token(parse_jwt(rsa_token(rsa_private, kid="missing")), document)
        assert report.matched is False
        assert report.signature_valid is None
        assert by_id(report.findings, "JWT-JWKS-020")[0].severity is Severity.HIGH
        assert "[WARNING] No matching key found" in format_jwks_analysis(document, report)

    def test_wrong_key_fails_verification(
        self,
        rsa_private: rsa.RSAPrivateKey,
        other_rsa_private: rsa.RSAPrivateKey,
    ) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private)]))
        report = match_token(parse_jwt(rsa_token(other_rsa_private)), document)
        assert report.signature_valid is False
        assert by_id(report.findings, "JWT-JWKS-025")
        assert "[WARNING] Signature verification failed" in format_jwks_analysis(document, report)

    def test_duplicate_kid_is_not_used(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private, kid="same"), rsa_jwk(rsa_private, kid="same")]))
        report = match_token(parse_jwt(rsa_token(rsa_private, kid="same")), document)
        assert report.signature_valid is None
        assert by_id(report.findings, "JWT-JWKS-026")
        assert "[WARNING] Ambiguous JWKS key" in format_jwks_analysis(document, report)

    def test_hmac_token_is_not_checked_with_an_rsa_key(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private)]))
        report = match_token(parse_jwt(hmac_token(b"secret", kid="key-01")), document)
        assert report.key_type_matches is False
        assert report.signature_valid is None
        assert by_id(report.findings, "JWT-JWKS-023")
        assert not by_id(report.findings, "JWT-JWKS-025")
        assert not by_id(report.findings, "JWT-JWKS-016")

    def test_key_algorithm_constraint_blocks_verification(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private, alg="RS384")]))
        report = match_token(parse_jwt(rsa_token(rsa_private, alg="RS256")), document)
        assert report.algorithm_matches is False
        assert report.key_type_matches is True
        assert report.signature_valid is None
        assert by_id(report.findings, "JWT-JWKS-022")

    def test_only_key_can_be_selected_without_kid(self, rsa_private: rsa.RSAPrivateKey) -> None:
        key = rsa_jwk(rsa_private)
        del key["kid"]
        signing, prefix = segments({"alg": "RS256", "typ": "JWT"}, {"sub": "user"})
        signature = rsa_private.sign(signing, padding.PKCS1v15(), hashes.SHA256())
        token = parse_jwt(f"{prefix}.{b64url(signature)}")
        document = parse_jwks(jwks_bytes([key]))
        report = match_token(token, document)
        assert report.signature_valid is True
        assert by_id(document.findings, "JWT-JWKS-001")[0].severity is Severity.LOW

    def test_encryption_key_is_not_used_to_verify(self, rsa_private: rsa.RSAPrivateKey) -> None:
        document = parse_jwks(jwks_bytes([rsa_jwk(rsa_private, use="enc")]))
        report = match_token(parse_jwt(rsa_token(rsa_private)), document)
        assert report.signing_key is False
        assert report.signature_valid is None
        assert by_id(report.findings, "JWT-JWKS-027")

    def test_ec_key_verifies_es256(self, ec_private: ec.EllipticCurvePrivateKey) -> None:
        numbers = ec_private.public_key().public_numbers()
        key = {
            "kty": "EC",
            "kid": "ec-1",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }
        document = parse_jwks(jwks_bytes([key]))
        report = match_token(parse_jwt(ec_token(ec_private)), document)
        assert report.signature_valid is True
        text = format_jwks_analysis(document, report)
        assert "crv    : P-256" in text
        assert "x      : present" in text
        assert "[✓] Signature verified" in text

    def test_published_hmac_secret_verifies_and_stays_high(self) -> None:
        secret = b"correct-secret"
        document = parse_jwks(
            jwks_bytes([{"kty": "oct", "kid": "h1", "use": "sig", "alg": "HS256", "k": b64url(secret)}])
        )
        report = match_token(parse_jwt(hmac_token(secret)), document)
        assert report.signature_valid is True
        assert by_id(document.all_findings, "JWT-JWKS-009")[0].severity is Severity.HIGH


class TestLocations:
    def test_local_file_does_not_call_the_fetcher(self, tmp_path, rsa_private: rsa.RSAPrivateKey) -> None:
        path = tmp_path / "jwks.json"
        path.write_bytes(jwks_bytes([rsa_jwk(rsa_private)]))

        def boom(url: str) -> bytes:
            raise AssertionError(url)

        document = load_jwks(str(path), fetcher=boom)
        assert document.keys[0].kid == "key-01"
        assert isinstance(get_jwks_source(str(path)), FileJwksSource)

    def test_http_url_is_fetched_and_flagged(self) -> None:
        seen: list[str] = []

        def fetcher(url: str) -> bytes:
            seen.append(url)
            return jwks_bytes([placeholder_rsa_jwk()])

        document = load_jwks("http://example.com/jwks.json", fetcher=fetcher)
        assert seen == ["http://example.com/jwks.json"]
        assert by_id(document.findings, "JWT-JWKS-015")[0].severity is Severity.MEDIUM
        assert isinstance(get_jwks_source("https://example.com/jwks.json"), UrlJwksSource)

    def test_file_scheme_is_rejected(self) -> None:
        with pytest.raises(JwksError) as caught:
            get_jwks_source("file:///tmp/jwks.json")
        assert caught.value.code == "UNSUPPORTED_SCHEME"

    def test_windows_drive_path_is_a_file(self) -> None:
        source = get_jwks_source(r"C:\keys\jwks.json")
        assert isinstance(source, FileJwksSource)

    def test_url_credentials_are_rejected(self) -> None:
        with pytest.raises(JwksError):
            load_jwks("https://user:secret@example.com/jwks.json", fetcher=lambda url: b"{}")

    def test_redirect_to_a_file_url_is_blocked(self) -> None:
        handler = SafeRedirectHandler()
        request = Request("https://example.com/jwks.json")
        with pytest.raises(RemoteFetchError):
            handler.redirect_request(request, None, 302, "Found", {}, "file:///etc/passwd")

    def test_https_url_without_credentials_is_allowed(self) -> None:
        validate_remote_url("https://example.com/.well-known/jwks.json")


