"""Signature verification and offline HMAC secret checks.

Pipeline stage:

    Input -> Parser -> HeaderAnalyzer -> PayloadAnalyzer -> CryptoAnalyzer

``get_verifier`` selects ``HMACVerifier``, ``RSAVerifier``, or ``ECDSAVerifier``.
A public key is never used as an HMAC secret, and a symmetric secret is never
used to verify RSA or ECDSA.

Wordlist search stays on the supplied token. It runs only for HS256, HS384,
and HS512, honors a cancel event and a timeout between candidates, and can
run off the caller thread through ``inspect_async``.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT

RFC_7515 = "https://www.rfc-editor.org/rfc/rfc7515"
RFC_7518 = "https://www.rfc-editor.org/rfc/rfc7518"

_HMAC_ALGS = frozenset({"HS256", "HS384", "HS512"})
_RSA_ALGS = frozenset({"RS256", "RS384", "RS512"})
_EC_ALGS = frozenset({"ES256", "ES384", "ES512"})
_SUPPORTED = _HMAC_ALGS | _RSA_ALGS | _EC_ALGS

_HMAC_DIGEST = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_ASYMMETRIC_HASH = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
    "ES256": hashes.SHA256,
    "ES384": hashes.SHA384,
    "ES512": hashes.SHA512,
}
_EC_COORDINATE_BYTES = {"ES256": 32, "ES384": 48, "ES512": 66}
_EC_CURVES = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}


class SignatureStatus(str, Enum):
    """Outcome of a local signature check."""

    VALID = "VALID"
    INVALID = "INVALID"
    SKIPPED = "SKIPPED"
    MISMATCH = "MISMATCH"
    ERROR = "ERROR"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class CryptoReport:
    """Signature status plus any findings from this stage."""

    algorithm: Optional[str]
    signature_status: SignatureStatus
    key_label: str
    findings: tuple[Finding, ...]
    message: str
    matched_secret: Optional[bytes] = None
    candidates_checked: int = 0
    stopped_reason: Optional[str] = None


@dataclass(frozen=True)
class CryptoAnalysisConfig:
    """Local key material and limits for signature analysis.

    ``secret`` is the HMAC key (``--secret``). ``public_key_pem`` is a PEM
    public key or certificate (``--public-key``). ``wordlist`` entries are
    HMAC candidates only. ``timeout_seconds`` and ``cancel_event`` stop a
    wordlist search between candidates. ``None`` timeout means no limit.
    """

    secret: Optional[bytes] = None
    public_key_pem: Optional[bytes] = None
    wordlist: Optional[Sequence[bytes]] = None
    key_label: str = ""
    timeout_seconds: Optional[float] = None
    max_workers: int = 4
    cancel_event: Optional[Any] = None

    def __post_init__(self) -> None:
        object_set = object.__setattr__
        if self.secret is not None:
            object_set(self, "secret", _as_bytes(self.secret, "secret"))
        if self.public_key_pem is not None:
            object_set(self, "public_key_pem", _as_bytes(self.public_key_pem, "public_key_pem"))
        if self.wordlist is not None:
            if isinstance(self.wordlist, (str, bytes, bytearray)):
                raise ValueError("wordlist must be a sequence of candidates")
            object_set(self, "wordlist", tuple(_as_bytes(item, "wordlist entry") for item in self.wordlist))
        if isinstance(self.max_workers, bool) or not isinstance(self.max_workers, int) or self.max_workers < 1:
            raise ValueError("max_workers must be an integer greater than zero")
        if self.timeout_seconds is not None:
            if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
                raise ValueError("timeout_seconds must be a non-negative number or None")
            if self.timeout_seconds < 0:
                raise ValueError("timeout_seconds must be a non-negative number or None")
        if self.cancel_event is not None and not hasattr(self.cancel_event, "is_set"):
            raise ValueError("cancel_event must have an is_set method")


class BaseVerifier(ABC):
    """Strategy that checks one JWS signature algorithm."""

    algorithm: str

    @abstractmethod
    def verify(self, token: ParsedJWT, key: Any) -> bool:
        """Return True when ``key`` produces this token's signature."""


class HMACVerifier(BaseVerifier):
    """Verify HS256, HS384, and HS512 with a shared secret."""

    def __init__(self, algorithm: str) -> None:
        if algorithm not in _HMAC_ALGS:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
        self.algorithm = algorithm

    def verify(self, token: ParsedJWT, key: Any) -> bool:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("HMAC key must be bytes")
        digestmod = _HMAC_DIGEST[self.algorithm]
        expected = hmac.new(bytes(key), signing_input(token), digestmod).digest()
        signature = token.signature
        if len(signature) != len(expected):
            return False
        return hmac.compare_digest(expected, signature)


class RSAVerifier(BaseVerifier):
    """Verify RS256, RS384, and RS512 with an RSA public key."""

    def __init__(self, algorithm: str) -> None:
        if algorithm not in _RSA_ALGS:
            raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
        self.algorithm = algorithm

    def verify(self, token: ParsedJWT, key: Any) -> bool:
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("RSA verification requires an RSA public key")
        hash_alg = _ASYMMETRIC_HASH[self.algorithm]()
        try:
            key.verify(token.signature, signing_input(token), padding.PKCS1v15(), hash_alg)
        except (InvalidSignature, ValueError):
            return False
        return True


class ECDSAVerifier(BaseVerifier):
    """Verify ES256, ES384, and ES512. JWS signatures are raw R || S."""

    def __init__(self, algorithm: str) -> None:
        if algorithm not in _EC_ALGS:
            raise ValueError(f"Unsupported ECDSA algorithm: {algorithm}")
        self.algorithm = algorithm

    def verify(self, token: ParsedJWT, key: Any) -> bool:
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("ECDSA verification requires an EC public key")
        if not isinstance(key.curve, _EC_CURVES[self.algorithm]):
            raise TypeError("EC key curve does not match the algorithm")
        der = _jws_ecdsa_to_der(token.signature, _EC_COORDINATE_BYTES[self.algorithm])
        if der is None:
            return False
        hash_alg = _ASYMMETRIC_HASH[self.algorithm]()
        try:
            key.verify(der, signing_input(token), ec.ECDSA(hash_alg))
        except (InvalidSignature, ValueError):
            return False
        return True


class CandidateTester(ABC):
    """Strategy used by the wordlist worker for one HMAC candidate."""

    @abstractmethod
    def matches(self, token: ParsedJWT, candidate: bytes) -> bool:
        """Return True when ``candidate`` verifies the token."""


class HMACCandidateTester(CandidateTester):
    """Default tester. It only returns True for a real HMAC verification."""

    def matches(self, token: ParsedJWT, candidate: bytes) -> bool:
        algorithm = _algorithm(token)
        if algorithm not in _HMAC_ALGS:
            return False
        return HMACVerifier(algorithm).verify(token, candidate)


def get_verifier(algorithm: str) -> BaseVerifier:
    """Return the verification strategy for a JWS ``alg`` value."""
    if algorithm in _HMAC_ALGS:
        return HMACVerifier(algorithm)
    if algorithm in _RSA_ALGS:
        return RSAVerifier(algorithm)
    if algorithm in _EC_ALGS:
        return ECDSAVerifier(algorithm)
    raise ValueError(f"Unsupported algorithm: {algorithm}")


class CryptoAnalyzer(BaseAnalyzer):
    """Verify a supplied key and, for HMAC, search a local wordlist."""

    def __init__(
        self,
        config: Optional[CryptoAnalysisConfig] = None,
        candidate_tester: Optional[CandidateTester] = None,
    ) -> None:
        self.config = config if config is not None else CryptoAnalysisConfig()
        self.candidate_tester = candidate_tester or HMACCandidateTester()

    @property
    def name(self) -> str:
        return "crypto"

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        return list(self.inspect(token).findings)

    def inspect(self, token: ParsedJWT) -> CryptoReport:
        """Run verification and return the signature status with findings."""
        config = self.config
        algorithm = _algorithm(token)
        if not _verification_requested(config):
            return _report(algorithm, SignatureStatus.SKIPPED, config.key_label, (), "Signature check skipped")

        if _is_none(algorithm):
            finding = _finding(
                "JWT-SIG-007",
                "Unsecured algorithm cannot be verified",
                Severity.MEDIUM,
                "alg none does not provide a signature to verify.",
                f"algorithm={algorithm}",
                "A token with alg none can be forged without a key.",
                "Reject alg none and require a signature from an allowlisted algorithm.",
            )
            return _report(algorithm, SignatureStatus.ERROR, _label(config, "none"), (finding,), "Unsecured algorithm")

        if algorithm not in _SUPPORTED:
            finding = _finding(
                "JWT-SIG-004",
                "Unsupported signature algorithm",
                Severity.MEDIUM,
                "This stage verifies HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, and ES512.",
                f"algorithm={algorithm or '-'}",
                "The signature was not checked.",
                "Use a supported algorithm or skip cryptographic verification for this token.",
            )
            return _report(algorithm, SignatureStatus.ERROR, _label(config, "key"), (finding,), "Unsupported algorithm")

        findings: list[Finding] = []
        status = SignatureStatus.SKIPPED
        label = _label(config, "secret" if algorithm in _HMAC_ALGS else "public-key")
        explicit = _verify_explicit(token, algorithm, config)
        if explicit is not None:
            status = explicit.status
            label = explicit.label or label
            findings.extend(explicit.findings)

        matched: Optional[bytes] = None
        checked = 0
        stopped: Optional[str] = None
        if config.wordlist is not None:
            if algorithm not in _HMAC_ALGS:
                findings.append(_wordlist_skipped(algorithm))
            else:
                hit = _search_wordlist(token, config, self.candidate_tester)
                checked = hit.checked
                stopped = hit.reason
                if hit.match is not None:
                    matched = hit.match
                    status = SignatureStatus.VALID
                    findings = [item for item in findings if item.id != "JWT-SIG-001"]
                    findings.append(_weak_secret_finding(algorithm, checked))
                    if not any(item.id == "JWT-SIG-005" for item in findings):
                        findings.append(_success_finding(algorithm, label or "wordlist"))
                elif hit.reason in {"timeout", "cancelled"} and status is SignatureStatus.SKIPPED:
                    status = SignatureStatus.INCOMPLETE
                elif hit.reason == "completed" and status is SignatureStatus.SKIPPED:
                    status = SignatureStatus.INVALID
                    findings.append(_wordlist_miss(algorithm, checked))

        message = _status_message(status)
        return CryptoReport(
            algorithm=algorithm,
            signature_status=status,
            key_label=label,
            findings=tuple(findings),
            message=message,
            matched_secret=matched,
            candidates_checked=checked,
            stopped_reason=stopped,
        )

    def inspect_async(self, token: ParsedJWT) -> Future[CryptoReport]:
        """Start ``inspect`` on a worker thread so the caller is not blocked."""
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="crypto-scan")
        future = pool.submit(self.inspect, token)
        future.add_done_callback(lambda _done: pool.shutdown(wait=False))
        return future


def signing_input(token: ParsedJWT) -> bytes:
    """Return the JWS signing input: ASCII ``base64url(header).base64url(payload)``."""
    return f"{token.header_segment}.{token.payload_segment}".encode("ascii")


def load_public_key_pem(pem: bytes) -> Any:
    """Load a PEM public key or an X.509 certificate's public key."""
    data = pem.strip()
    try:
        return serialization.load_pem_public_key(data)
    except ValueError:
        pass
    try:
        certificate = x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise ValueError("Public key PEM could not be parsed") from exc
    return certificate.public_key()


def read_secret(path: str) -> bytes:
    """Read a secret file and drop a single trailing newline editors often add."""
    data = Path(path).read_bytes()
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


def read_public_key(path: str) -> bytes:
    """Read a PEM public key or certificate file."""
    return Path(path).read_bytes()


def read_wordlist(path: str) -> tuple[bytes, ...]:
    """Read a UTF-8 wordlist. Each line is one HMAC candidate."""
    raw = Path(path).read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8")
    return tuple(line.encode("utf-8") for line in text.splitlines())


@dataclass(frozen=True)
class _ExplicitVerification:
    status: SignatureStatus
    findings: tuple[Finding, ...]
    label: str


@dataclass(frozen=True)
class _SearchHit:
    match: Optional[bytes]
    checked: int
    reason: str


def _verify_explicit(
    token: ParsedJWT,
    algorithm: str,
    config: CryptoAnalysisConfig,
) -> Optional[_ExplicitVerification]:
    label = _label(config, "secret" if algorithm in _HMAC_ALGS else "public-key")
    if algorithm in _HMAC_ALGS and config.secret is not None:
        valid = HMACVerifier(algorithm).verify(token, config.secret)
        status = SignatureStatus.VALID if valid else SignatureStatus.INVALID
        finding = _success_finding(algorithm, label) if valid else _failure_finding(algorithm, label, "secret")
        return _ExplicitVerification(status, (finding,), label)

    if algorithm in _HMAC_ALGS and config.public_key_pem is not None and config.secret is None:
        if config.wordlist is None:
            return _ExplicitVerification(SignatureStatus.MISMATCH, (_mismatch_finding(algorithm, "public-key"),), label)

    if algorithm in _RSA_ALGS | _EC_ALGS and config.public_key_pem is not None:
        try:
            key = load_public_key_pem(config.public_key_pem)
        except ValueError:
            finding = _finding(
                "JWT-SIG-004",
                "Public key could not be loaded",
                Severity.MEDIUM,
                "The PEM data is not a public key or an X.509 certificate.",
                f"algorithm={algorithm}; key={label}",
                "The signature was not checked.",
                "Pass a PEM public key or certificate in --public-key.",
            )
            return _ExplicitVerification(SignatureStatus.ERROR, (finding,), label)
        if not _key_matches_algorithm(algorithm, key):
            return _ExplicitVerification(
                SignatureStatus.MISMATCH,
                (_mismatch_finding(algorithm, "public-key"),),
                label,
            )
        valid = get_verifier(algorithm).verify(token, key)
        status = SignatureStatus.VALID if valid else SignatureStatus.INVALID
        finding = _success_finding(algorithm, label) if valid else _failure_finding(algorithm, label, "public-key")
        return _ExplicitVerification(status, (finding,), label)

    if algorithm in _RSA_ALGS | _EC_ALGS and config.secret is not None and config.public_key_pem is None:
        return _ExplicitVerification(SignatureStatus.MISMATCH, (_mismatch_finding(algorithm, "secret"),), label)
    return None


def _key_matches_algorithm(algorithm: str, key: Any) -> bool:
    if algorithm in _RSA_ALGS:
        return isinstance(key, rsa.RSAPublicKey)
    if algorithm in _EC_ALGS:
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, _EC_CURVES[algorithm])
    return False


def _search_wordlist(
    token: ParsedJWT,
    config: CryptoAnalysisConfig,
    tester: CandidateTester,
) -> _SearchHit:
    candidates = tuple(config.wordlist or ())
    cancel = config.cancel_event
    deadline = None if config.timeout_seconds is None else time.monotonic() + float(config.timeout_seconds)
    if cancel is not None and cancel.is_set():
        return _SearchHit(None, 0, "cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        return _SearchHit(None, 0, "timeout")
    if not candidates:
        return _SearchHit(None, 0, "completed")

    checked = 0
    match: Optional[bytes] = None
    reason = "completed"
    workers = config.max_workers
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hmac-wordlist") as executor:
        index = 0
        while index < len(candidates):
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
                break
            if deadline is not None and time.monotonic() >= deadline:
                reason = "timeout"
                break
            chunk = candidates[index : index + workers]
            index += len(chunk)
            futures = [executor.submit(_check_candidate, tester, token, candidate) for candidate in chunk]
            for future in as_completed(futures):
                candidate, ok = future.result()
                checked += 1
                if ok and match is None:
                    match = candidate
            if match is not None:
                reason = "completed"
                break
    return _SearchHit(match, checked, reason)


def _check_candidate(tester: CandidateTester, token: ParsedJWT, candidate: bytes) -> tuple[bytes, bool]:
    return candidate, tester.matches(token, candidate)


def _jws_ecdsa_to_der(signature: bytes, coordinate_bytes: int) -> Optional[bytes]:
    if len(signature) != coordinate_bytes * 2:
        return None
    r = int.from_bytes(signature[:coordinate_bytes], "big")
    s = int.from_bytes(signature[coordinate_bytes:], "big")
    return encode_dss_signature(r, s)


def _algorithm(token: ParsedJWT) -> Optional[str]:
    alg = token.header.get("alg")
    if isinstance(alg, str):
        return alg
    return None


def _is_none(algorithm: Optional[str]) -> bool:
    return isinstance(algorithm, str) and algorithm.strip().lower() == "none"


def _verification_requested(config: CryptoAnalysisConfig) -> bool:
    return config.secret is not None or config.public_key_pem is not None or config.wordlist is not None


def _label(config: CryptoAnalysisConfig, fallback: str) -> str:
    return config.key_label or fallback


def _as_bytes(value: Any, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, bytes):
        return value
    raise ValueError(f"{name} must be bytes or str")


def _report(
    algorithm: Optional[str],
    status: SignatureStatus,
    label: str,
    findings: tuple[Finding, ...],
    message: str,
) -> CryptoReport:
    return CryptoReport(
        algorithm=algorithm,
        signature_status=status,
        key_label=label,
        findings=findings,
        message=message,
    )


def _status_message(status: SignatureStatus) -> str:
    messages = {
        SignatureStatus.VALID: "Signature verification successful",
        SignatureStatus.INVALID: "Signature verification failed",
        SignatureStatus.SKIPPED: "Signature check skipped",
        SignatureStatus.MISMATCH: "Key type does not match algorithm",
        SignatureStatus.ERROR: "Signature check failed",
        SignatureStatus.INCOMPLETE: "Signature check did not finish",
    }
    return messages[status]


def _success_finding(algorithm: str, label: str) -> Finding:
    return _finding(
        "JWT-SIG-005",
        "Signature verification successful",
        Severity.INFO,
        "The supplied key produced this token's signature.",
        f"algorithm={algorithm}; signature=VALID; key={label}",
        "The signature matches the supplied key.",
        "Continue checking claims, lifetime, and key distribution.",
    )


def _failure_finding(algorithm: str, label: str, source: str) -> Finding:
    return _finding(
        "JWT-SIG-001",
        "Signature verification failed",
        Severity.MEDIUM,
        "The supplied key did not produce this token's signature.",
        f"algorithm={algorithm}; signature=INVALID; key={label}; source={source}",
        "The token is not authentic under the supplied key.",
        "Confirm the key, the algorithm, and that the token was not modified.",
    )


def _weak_secret_finding(algorithm: str, checked: int) -> Finding:
    return _finding(
        "JWT-SIG-002",
        "JWT uses a weak signing secret",
        Severity.HIGH,
        "An entry in the local wordlist verified this HMAC signature.",
        f"algorithm={algorithm}; signature=VALID; source=wordlist; candidates_checked={checked}",
        "Anyone with the same wordlist can forge tokens for this issuer.",
        "Replace the HMAC secret with a long random value and rotate tokens.",
        references=(RFC_7518,),
    )


def _mismatch_finding(algorithm: str, supplied: str) -> Finding:
    return _finding(
        "JWT-SIG-003",
        "Key type does not match algorithm",
        Severity.HIGH,
        "The supplied key type does not match alg, so verification was refused.",
        f"algorithm={algorithm}; supplied={supplied}",
        "Verifying with the wrong key type enables algorithm confusion.",
        "Use an HMAC secret for HS* algorithms and a public key for RS* or ES*.",
        references=(RFC_7518,),
    )


def _wordlist_skipped(algorithm: str) -> Finding:
    return _finding(
        "JWT-SIG-008",
        "Wordlist ignored for non-HMAC algorithm",
        Severity.INFO,
        "Offline secret search runs only for HS256, HS384, and HS512.",
        f"algorithm={algorithm}; source=wordlist",
        "No dictionary search was performed.",
        "Remove the wordlist or verify this token with its public key.",
    )


def _wordlist_miss(algorithm: str, checked: int) -> Finding:
    return _finding(
        "JWT-SIG-006",
        "No weak secret found",
        Severity.INFO,
        "No wordlist entry verified this HMAC signature.",
        f"algorithm={algorithm}; signature=INVALID; source=wordlist; candidates_checked={checked}",
        "The scan did not recover a signing secret from the supplied list.",
        "Treat the secret as unknown. A larger list is still an offline check of this token only.",
    )


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: tuple[str, ...] = (RFC_7515,),
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        references=references,
    )
