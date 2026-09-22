"""Unit tests for signature verification and offline HMAC secret search."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.crypto import (
    CandidateTester,
    CryptoAnalysisConfig,
    CryptoAnalyzer,
    ECDSAVerifier,
    HMACVerifier,
    RSAVerifier,
    SignatureStatus,
    get_verifier,
    read_secret,
    read_wordlist,
)
from jwt_analyzer.findings import Finding, Severity
from jwt_analyzer.parser import parse_jwt

_HMAC = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_RSA_HASH = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
_EC_HASH = {"ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512}
_EC_SIZE = {"ES256": 32, "ES384": 48, "ES512": 66}
_EC_CURVE = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def segments(header: dict, payload: dict) -> tuple[bytes, str]:
    header_seg = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing = f"{header_seg}.{payload_seg}".encode("ascii")
    return signing, f"{header_seg}.{payload_seg}"


def token_with_signature(header: dict, payload: dict, signature: bytes) -> str:
    _signing, prefix = segments(header, payload)
    return f"{prefix}.{b64url(signature)}"


def hmac_token(alg: str, secret: bytes, payload: dict | None = None) -> str:
    body = {"sub": "user"} if payload is None else payload
    signing, prefix = segments({"alg": alg, "typ": "JWT"}, body)
    signature = hmac.new(secret, signing, _HMAC[alg]).digest()
    return f"{prefix}.{b64url(signature)}"


def rsa_token(private: rsa.RSAPrivateKey, alg: str) -> str:
    signing, prefix = segments({"alg": alg, "typ": "JWT"}, {"sub": "user"})
    signature = private.sign(signing, padding_pkcs(), _RSA_HASH[alg]())
    return f"{prefix}.{b64url(signature)}"


def ec_token(private: ec.EllipticCurvePrivateKey, alg: str) -> str:
    signing, prefix = segments({"alg": alg, "typ": "JWT"}, {"sub": "user"})
    der = private.sign(signing, ec.ECDSA(_EC_HASH[alg]()))
    r_value, s_value = decode_dss_signature(der)
    size = _EC_SIZE[alg]
    raw = r_value.to_bytes(size, "big") + s_value.to_bytes(size, "big")
    return f"{prefix}.{b64url(raw)}"


def padding_pkcs():
    from cryptography.hazmat.primitives.asymmetric import padding

    return padding.PKCS1v15()


def public_pem(private) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def certificate_pem(private: rsa.RSAPrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vexa-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(private, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def by_id(findings: tuple[Finding, ...] | list[Finding], finding_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.id == finding_id]


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestValidSignatures:
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_correct_secret_is_valid(self, alg: str) -> None:
        secret = b"correct-secret"
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(secret=secret, key_label="secret.txt")
        ).inspect(parse_jwt(hmac_token(alg, secret)))

        assert report.signature_status is SignatureStatus.VALID
        assert report.signature_status.value == "VALID"
        assert report.key_label == "secret.txt"
        assert report.message == "Signature verification successful"
        success = by_id(report.findings, "JWT-SIG-005")
        assert success[0].severity is Severity.INFO
        assert "signature=VALID" in success[0].evidence
        assert "secret.txt" in success[0].evidence

    @pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
    def test_correct_public_key_is_valid(self, rsa_private: rsa.RSAPrivateKey, alg: str) -> None:
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=public_pem(rsa_private), key_label="public.pem")
        ).inspect(parse_jwt(rsa_token(rsa_private, alg)))

        assert report.signature_status is SignatureStatus.VALID
        assert report.key_label == "public.pem"
        assert "signature=VALID" in by_id(report.findings, "JWT-SIG-005")[0].evidence

    def test_certificate_pem_verifies_rs256(self, rsa_private: rsa.RSAPrivateKey) -> None:
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=certificate_pem(rsa_private), key_label="cert.pem")
        ).inspect(parse_jwt(rsa_token(rsa_private, "RS256")))
        assert report.signature_status is SignatureStatus.VALID

    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
    def test_correct_ec_public_key_is_valid(self, alg: str) -> None:
        private = ec.generate_private_key(_EC_CURVE[alg]())
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=public_pem(private))
        ).inspect(parse_jwt(ec_token(private, alg)))
        assert report.signature_status is SignatureStatus.VALID

    def test_secret_file_round_trip(self, tmp_path) -> None:
        secret_path = tmp_path / "secret.txt"
        secret_path.write_bytes(b"correct-secret\n")
        secret = read_secret(str(secret_path))
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=secret)).inspect(
            parse_jwt(hmac_token("HS256", b"correct-secret"))
        )
        assert secret == b"correct-secret"
        assert report.signature_status is SignatureStatus.VALID


class TestInvalidSignatures:
    def test_wrong_secret_is_invalid(self) -> None:
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"wrong")).inspect(
            parse_jwt(hmac_token("HS256", b"correct-secret"))
        )
        assert report.signature_status is SignatureStatus.INVALID
        failed = by_id(report.findings, "JWT-SIG-001")
        assert failed[0].severity is Severity.MEDIUM
        assert "signature=INVALID" in failed[0].evidence
        assert by_id(report.findings, "JWT-SIG-002") == []

    def test_tampered_signature_is_invalid(self) -> None:
        token = hmac_token("HS256", b"correct-secret")
        head, payload, signature = token.split(".")
        flipped = bytearray(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
        flipped[0] ^= 0x01
        tampered = f"{head}.{payload}.{b64url(bytes(flipped))}"
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"correct-secret")).inspect(parse_jwt(tampered))
        assert report.signature_status is SignatureStatus.INVALID

    def test_empty_signature_is_invalid(self) -> None:
        signing, prefix = segments({"alg": "HS256", "typ": "JWT"}, {"sub": "user"})
        del signing
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"correct-secret")).inspect(parse_jwt(f"{prefix}."))
        assert report.signature_status is SignatureStatus.INVALID

    def test_wrong_rsa_key_is_invalid(
        self,
        rsa_private: rsa.RSAPrivateKey,
        other_rsa_private: rsa.RSAPrivateKey,
    ) -> None:
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=public_pem(other_rsa_private))
        ).inspect(parse_jwt(rsa_token(rsa_private, "RS256")))
        assert report.signature_status is SignatureStatus.INVALID

    def test_public_key_is_not_used_as_hmac_secret(self, rsa_private: rsa.RSAPrivateKey) -> None:
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=public_pem(rsa_private))
        ).inspect(parse_jwt(hmac_token("HS256", b"correct-secret")))
        assert report.signature_status is SignatureStatus.MISMATCH
        assert by_id(report.findings, "JWT-SIG-003")[0].severity is Severity.HIGH

    def test_secret_is_not_used_for_rsa(self, rsa_private: rsa.RSAPrivateKey) -> None:
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"correct-secret")).inspect(
            parse_jwt(rsa_token(rsa_private, "RS256"))
        )
        assert report.signature_status is SignatureStatus.MISMATCH
        assert by_id(report.findings, "JWT-SIG-003")

    def test_wrong_ec_curve_is_a_mismatch(self) -> None:
        private = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP384R1())
        report = CryptoAnalyzer(CryptoAnalysisConfig(public_key_pem=public_pem(other))).inspect(
            parse_jwt(ec_token(private, "ES256"))
        )
        assert report.signature_status is SignatureStatus.MISMATCH

    def test_none_algorithm_is_not_valid(self) -> None:
        _signing, prefix = segments({"alg": "none", "typ": "JWT"}, {"sub": "user"})
        report = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"correct-secret")).inspect(parse_jwt(f"{prefix}."))
        assert report.signature_status is SignatureStatus.ERROR
        assert report.signature_status is not SignatureStatus.VALID
        assert by_id(report.findings, "JWT-SIG-007")

    def test_bad_pem_does_not_raise(self, rsa_private: rsa.RSAPrivateKey) -> None:
        report = CryptoAnalyzer(CryptoAnalysisConfig(public_key_pem=b"not a key")).inspect(
            parse_jwt(rsa_token(rsa_private, "RS256"))
        )
        assert report.signature_status is SignatureStatus.ERROR
        assert by_id(report.findings, "JWT-SIG-004")

    def test_no_key_skips_verification(self) -> None:
        report = CryptoAnalyzer().inspect(parse_jwt(hmac_token("HS256", b"correct-secret")))
        assert report.signature_status is SignatureStatus.SKIPPED
        assert report.findings == ()


class TestWeakSecrets:
    def test_wordlist_finds_hmac_secret_and_reports_high(self) -> None:
        secret = b"correct-secret"
        wordlist_path_entries = ("nope", "correct-secret", "later")
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(wordlist=wordlist_path_entries, max_workers=2)
        ).inspect(parse_jwt(hmac_token("HS256", secret)))

        assert report.signature_status is SignatureStatus.VALID
        assert report.matched_secret == secret
        assert report.stopped_reason == "completed"
        high = by_id(report.findings, "JWT-SIG-002")
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH
        assert high[0].title == "JWT uses a weak signing secret"
        assert "source=wordlist" in high[0].evidence
        assert secret not in high[0].evidence.encode("utf-8")

    def test_wordlist_file_finds_secret(self, tmp_path) -> None:
        path = tmp_path / "wordlist.txt"
        path.write_bytes(b"\xef\xbb\xbfnope\ncorrect-secret\n")
        report = CryptoAnalyzer(CryptoAnalysisConfig(wordlist=read_wordlist(str(path)))).inspect(
            parse_jwt(hmac_token("HS512", b"correct-secret"))
        )
        assert report.matched_secret == b"correct-secret"
        assert by_id(report.findings, "JWT-SIG-002")[0].severity is Severity.HIGH

    def test_wordlist_miss_is_not_a_high_finding(self) -> None:
        report = CryptoAnalyzer(CryptoAnalysisConfig(wordlist=("alpha", "beta"))).inspect(
            parse_jwt(hmac_token("HS256", b"correct-secret"))
        )
        assert report.signature_status is SignatureStatus.INVALID
        assert report.matched_secret is None
        assert report.candidates_checked == 2
        assert by_id(report.findings, "JWT-SIG-002") == []
        assert by_id(report.findings, "JWT-SIG-006")

    def test_wordlist_is_not_used_for_rsa(self, rsa_private: rsa.RSAPrivateKey) -> None:
        calls: list[bytes] = []

        class Spy(CandidateTester):
            def matches(self, token, candidate: bytes) -> bool:
                calls.append(candidate)
                return False

        report = CryptoAnalyzer(
            CryptoAnalysisConfig(public_key_pem=public_pem(rsa_private), wordlist=("secret", "other")),
            candidate_tester=Spy(),
        ).inspect(parse_jwt(rsa_token(rsa_private, "RS256")))

        assert calls == []
        assert report.signature_status is SignatureStatus.VALID
        assert report.candidates_checked == 0
        assert by_id(report.findings, "JWT-SIG-008")
        assert by_id(report.findings, "JWT-SIG-002") == []

    def test_zero_timeout_stops_before_candidates(self) -> None:
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(wordlist=("a", "b", "correct-secret"), timeout_seconds=0, max_workers=1)
        ).inspect(parse_jwt(hmac_token("HS256", b"correct-secret")))
        assert report.signature_status is SignatureStatus.INCOMPLETE
        assert report.stopped_reason == "timeout"
        assert report.candidates_checked == 0
        assert report.matched_secret is None

    def test_preset_cancel_stops_before_candidates(self) -> None:
        cancel = threading.Event()
        cancel.set()
        report = CryptoAnalyzer(
            CryptoAnalysisConfig(wordlist=("a", "correct-secret"), cancel_event=cancel, max_workers=1)
        ).inspect(parse_jwt(hmac_token("HS256", b"correct-secret")))
        assert report.stopped_reason == "cancelled"
        assert report.candidates_checked == 0
        assert report.signature_status is SignatureStatus.INCOMPLETE

    def test_async_scan_can_be_cancelled_without_blocking_the_caller(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class Gate(CandidateTester):
            def matches(self, token, candidate: bytes) -> bool:
                if candidate == b"first":
                    started.set()
                    release.wait(2)
                return candidate == b"correct-secret"

        cancel = threading.Event()
        analyzer = CryptoAnalyzer(
            CryptoAnalysisConfig(
                wordlist=("first", "correct-secret"),
                cancel_event=cancel,
                max_workers=1,
            ),
            candidate_tester=Gate(),
        )
        future = analyzer.inspect_async(parse_jwt(hmac_token("HS256", b"correct-secret")))
        assert started.wait(1)
        cancel.set()
        release.set()
        report = future.result(timeout=2)

        assert report.stopped_reason == "cancelled"
        assert report.matched_secret is None
        assert report.candidates_checked == 1


class TestVerifierStrategy:
    def test_factory_returns_the_algorithm_strategy(self) -> None:
        assert isinstance(get_verifier("HS256"), HMACVerifier)
        assert isinstance(get_verifier("RS256"), RSAVerifier)
        assert isinstance(get_verifier("ES256"), ECDSAVerifier)

    def test_factory_rejects_none_and_unknown_algorithms(self) -> None:
        with pytest.raises(ValueError):
            get_verifier("none")
        with pytest.raises(ValueError):
            get_verifier("HS1")

    def test_analyzer_is_a_pipeline_stage(self) -> None:
        analyzer = CryptoAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "crypto"

    def test_analyze_returns_the_report_findings(self) -> None:
        token = parse_jwt(hmac_token("HS256", b"correct-secret"))
        analyzer = CryptoAnalyzer(CryptoAnalysisConfig(secret=b"correct-secret"))
        assert analyzer.analyze(token) == list(analyzer.inspect(token).findings)

    def test_invalid_worker_count(self) -> None:
        with pytest.raises(ValueError, match="max_workers"):
            CryptoAnalysisConfig(max_workers=0)

    def test_negative_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds"):
            CryptoAnalysisConfig(timeout_seconds=-1)

    def test_wordlist_must_be_a_sequence_of_candidates(self) -> None:
        with pytest.raises(ValueError, match="wordlist"):
            CryptoAnalysisConfig(wordlist="secret")  # type: ignore[arg-type]
