"""JWKS parsing, key-configuration checks, and kid-based verification.

Pipeline stage:

    Input -> Parser -> HeaderAnalyzer -> PayloadAnalyzer -> CryptoAnalyzer -> JwksAnalyzer

``get_jwks_source`` is the factory for a local file or an HTTP(S) URL.
Key checks are strategies. Signature verification reuses ``get_verifier``
so an HMAC secret is never applied to an RSA or EC key.

A URL is fetched only when the caller passes that location. Passive
analysis leaves ``JwksAnalysisConfig.location`` empty and this stage
returns no findings.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.analyzers.crypto import get_verifier
from jwt_analyzer.exceptions import JwksError, RemoteFetchError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.http_client import DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS, read_remote
from jwt_analyzer.parser import ParsedJWT

RFC_7515 = "https://www.rfc-editor.org/rfc/rfc7515"
RFC_7517 = "https://www.rfc-editor.org/rfc/rfc7517"
RFC_7518 = "https://www.rfc-editor.org/rfc/rfc7518"

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_MAX_KEYS = 128
_MIN_RSA_BITS = 2048

_KTY_CANONICAL = {"rsa": "RSA", "ec": "EC", "oct": "oct", "okp": "OKP"}
_RSA_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
_EC_CURVE_FOR_ALG = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
_HMAC_ALGS = frozenset({"HS256", "HS384", "HS512"})
_VERIFIABLE = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}) | _HMAC_ALGS
_EC_CLASSES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
_SIG_OPS = frozenset({"sign", "verify"})
_ENC_OPS = frozenset({"encrypt", "decrypt", "wrapKey", "unwrapKey"})

_CHECKLIST_IDS = frozenset(
    {
        "JWT-JWKS-020",
        "JWT-JWKS-021",
        "JWT-JWKS-022",
        "JWT-JWKS-023",
        "JWT-JWKS-024",
        "JWT-JWKS-025",
        "JWT-JWKS-026",
        "JWT-JWKS-027",
        "JWT-JWKS-030",
    }
)


@dataclass(frozen=True)
class JwkRecord:
    """One JWK plus the findings that apply to that key alone."""

    index: int
    kid: Optional[str]
    kty: Optional[str]
    canonical_kty: Optional[str]
    use: Optional[str]
    alg: Optional[str]
    key_ops: tuple[str, ...]
    n: Optional[str]
    e: Optional[str]
    x: Optional[str]
    y: Optional[str]
    crv: Optional[str]
    modulus_bits: Optional[int]
    findings: tuple[Finding, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class JwksDocument:
    """A parsed JSON Web Key Set and the findings about the set."""

    source: str
    keys: tuple[JwkRecord, ...]
    findings: tuple[Finding, ...] = ()

    @property
    def all_findings(self) -> tuple[Finding, ...]:
        """Document findings followed by each key's findings."""
        items = list(self.findings)
        for key in self.keys:
            items.extend(key.findings)
        return tuple(items)


@dataclass(frozen=True)
class JwksMatchReport:
    """Result of selecting a JWKS key for one token and verifying it."""

    document: JwksDocument
    token_kid: Optional[str]
    token_alg: Optional[str]
    key: Optional[JwkRecord]
    matched: bool
    algorithm_matches: Optional[bool]
    key_type_matches: Optional[bool]
    signature_valid: Optional[bool]
    signing_key: Optional[bool]
    findings: tuple[Finding, ...]
    message: str


@dataclass(frozen=True)
class JwksAnalysisConfig:
    """JWKS input for the analyzer stage.

    Pass ``document`` when the set is already loaded. Pass ``location`` to
    read a file or URL. When both are set, ``document`` is used and nothing
    is fetched. With neither, the stage stays passive.
    """

    document: Optional[JwksDocument] = None
    location: Optional[str] = None
    fetcher: Optional[Callable[[str], bytes]] = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise ValueError("timeout_seconds must be a positive number")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive number")
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int) or self.max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")


class JwksSource(ABC):
    """Strategy that reads the bytes of one JWKS document."""

    def __init__(self, location: str) -> None:
        self.location = location

    @abstractmethod
    def read(
        self,
        *,
        fetcher: Optional[Callable[[str], bytes]],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        """Return the document body."""

    def findings(self) -> tuple[Finding, ...]:
        """Findings that come from the location itself, such as cleartext HTTP."""
        return ()


class FileJwksSource(JwksSource):
    """Read a JWKS document from a local path."""

    def read(
        self,
        *,
        fetcher: Optional[Callable[[str], bytes]],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        del fetcher, timeout
        path = Path(self.location)
        if not path.is_file():
            raise JwksError(f"JWKS file not found: {self.location}", code="NOT_FOUND")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise JwksError(f"Could not read JWKS file: {self.location}", code="NOT_FOUND") from exc
        if len(data) > max_bytes:
            raise JwksError("JWKS file exceeds the size limit", code="TOO_LARGE")
        return data


class UrlJwksSource(JwksSource):
    """Fetch a JWKS document from an HTTP(S) URL the caller named."""

    def read(
        self,
        *,
        fetcher: Optional[Callable[[str], bytes]],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        try:
            return read_remote(self.location, fetcher=fetcher, timeout=timeout, max_bytes=max_bytes)
        except RemoteFetchError as exc:
            raise JwksError(exc.message, code=exc.code) from exc

    def findings(self) -> tuple[Finding, ...]:
        if urlsplit(self.location).scheme.lower() != "http":
            return ()
        return (
            _finding(
                "JWT-JWKS-015",
                "JWKS URL uses cleartext HTTP",
                Severity.MEDIUM,
                "The JWKS document was loaded over HTTP, so a network attacker can swap the keys.",
                f"url={self.location}; scheme=http",
                "Verification would trust keys that were not protected in transit.",
                "Publish the JWKS on HTTPS and pass that URL.",
            ),
        )


class JwkCheck(ABC):
    """Strategy that inspects one JWK object."""

    @abstractmethod
    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        """Return findings for this key. Do not raise for a weak key."""


class JwksDocumentCheck(ABC):
    """Strategy that inspects the key set as a whole."""

    @abstractmethod
    def check(self, keys: Sequence[JwkRecord]) -> list[Finding]:
        """Return findings that need more than one key."""


class KidParameterCheck(JwkCheck):
    """Reject a ``kid`` that is present but not a string."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        if "kid" not in key or key.get("kid") is None:
            return []
        kid = key.get("kid")
        if isinstance(kid, str):
            if kid.strip() == "":
                return [
                    _finding(
                        "JWT-JWKS-001",
                        "Empty kid",
                        Severity.MEDIUM,
                        "A JWKS key identifier is present but empty.",
                        f"index={index}; kid=",
                        "Key selection may fall back to the wrong key.",
                        "Set kid to a unique non-empty identifier or omit it.",
                    )
                ]
            return []
        return [
            _finding(
                "JWT-JWKS-001",
                "Invalid kid",
                Severity.MEDIUM,
                "A JWKS kid must be a string.",
                f"index={index}; kid_type={type(kid).__name__}",
                "Verifiers may coerce the identifier into an unexpected lookup.",
                "Publish kid as a string.",
            )
        ]


class KeyTypeCheck(JwkCheck):
    """Require a recognized ``kty`` and note a non-canonical spelling."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        raw = key.get("kty")
        kid = _kid_evidence(key, index)
        if not isinstance(raw, str) or not raw.strip():
            return [
                _finding(
                    "JWT-JWKS-003",
                    "Missing kty",
                    Severity.MEDIUM,
                    "Every JWK needs a kty parameter.",
                    f"{kid}; kty={_preview(raw)}",
                    "The key cannot be selected for verification.",
                    "Set kty to RSA, EC, or oct.",
                )
            ]
        canonical = canonical_kty(raw)
        if canonical is None:
            return [
                _finding(
                    "JWT-JWKS-003",
                    "Unsupported key type",
                    Severity.MEDIUM,
                    "kty is not a key type this analyzer can evaluate.",
                    f"{kid}; kty={_preview(raw)}",
                    "The key cannot be matched to a JWS algorithm.",
                    "Use RSA, EC, or oct, or remove the key from the published set.",
                )
            ]
        findings: list[Finding] = []
        if raw.strip() != canonical:
            findings.append(
                _finding(
                    "JWT-JWKS-017",
                    "Non-canonical kty",
                    Severity.LOW,
                    "JWK key types are case-sensitive. This value only matches after case folding.",
                    f"{kid}; kty={_preview(raw)}; canonical={canonical}",
                    "A strict parser will ignore the key.",
                    f"Publish kty as {canonical}.",
                )
            )
        if canonical == "OKP":
            findings.append(
                _finding(
                    "JWT-JWKS-003",
                    "Unsupported key type",
                    Severity.INFO,
                    "OKP keys are recognized but this stage does not verify EdDSA.",
                    f"{kid}; kty={canonical}",
                    "An EdDSA token cannot be checked against this key here.",
                    "Verify EdDSA with a dedicated OKP verifier.",
                )
            )
        return findings


class AlgorithmConsistencyCheck(JwkCheck):
    """Compare ``alg`` with ``kty`` and reject ``none`` on a published key."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        alg = key.get("alg")
        if alg is None:
            return []
        kid = _kid_evidence(key, index)
        if not isinstance(alg, str) or not alg.strip():
            return [
                _finding(
                    "JWT-JWKS-004",
                    "Invalid alg",
                    Severity.MEDIUM,
                    "When alg is present on a JWK it must be a non-empty string.",
                    f"{kid}; alg_type={type(alg).__name__}",
                    "The key may be selected for the wrong signature algorithm.",
                    "Omit alg or set it to the algorithm this key is used with.",
                )
            ]
        if alg.strip().lower() == "none":
            return [
                _finding(
                    "JWT-JWKS-018",
                    'Key advertises algorithm "none"',
                    Severity.HIGH,
                    "A published verification key must not advertise the unsecured algorithm.",
                    f"{kid}; alg={_preview(alg)}",
                    "A verifier that trusts this key metadata may accept unsigned tokens.",
                    "Remove alg none from the JWKS and reject unsigned tokens.",
                    references=(RFC_7517, RFC_7518),
                )
            ]
        canonical = canonical_kty(key.get("kty")) if isinstance(key.get("kty"), str) else None
        if canonical is None:
            return []
        if _family_matches(canonical, alg.strip(), key.get("crv") if isinstance(key.get("crv"), str) else None):
            return []
        return [
            _finding(
                "JWT-JWKS-004",
                "Algorithm does not match key type",
                Severity.HIGH,
                "The alg value cannot be used with this kty.",
                f"{kid}; kty={canonical}; alg={alg.strip()}",
                "Callers may verify with the wrong key type and accept a confused algorithm.",
                "Set alg to an algorithm that matches kty, or remove alg.",
                references=(RFC_7517, RFC_7518),
            )
        ]


class RsaParameterCheck(JwkCheck):
    """Require RSA public parameters and a modulus of at least 2048 bits."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        if canonical_kty(key.get("kty")) != "RSA":
            return []
        kid = _kid_evidence(key, index)
        findings: list[Finding] = []
        missing = [name for name in ("n", "e") if not isinstance(key.get(name), str) or not key.get(name)]
        if missing:
            findings.append(
                _finding(
                    "JWT-JWKS-005",
                    "Incomplete RSA key",
                    Severity.HIGH,
                    "An RSA public key needs modulus n and exponent e as base64url strings.",
                    f"{kid}; missing={','.join(missing)}",
                    "The key cannot verify an RSA signature.",
                    "Publish both n and e, and keep private members out of the JWKS.",
                )
            )
            return findings
        try:
            modulus_bits = b64url_uint(str(key.get("n"))).bit_length()
            b64url_uint(str(key.get("e")))
        except ValueError:
            findings.append(
                _finding(
                    "JWT-JWKS-005",
                    "Incomplete RSA key",
                    Severity.HIGH,
                    "RSA n and e must be base64url unsigned integers.",
                    f"{kid}; parameters=n,e",
                    "The key cannot be imported for verification.",
                    "Encode n and e with base64url and no whitespace.",
                )
            )
            return findings
        if modulus_bits < _MIN_RSA_BITS:
            findings.append(
                _finding(
                    "JWT-JWKS-007",
                    "Weak RSA modulus",
                    Severity.HIGH,
                    f"The RSA modulus is shorter than {_MIN_RSA_BITS} bits.",
                    f"{kid}; modulus_bits={modulus_bits}; minimum={_MIN_RSA_BITS}",
                    "A short modulus can be factored, which forges every token this key signs.",
                    f"Rotate to an RSA key of at least {_MIN_RSA_BITS} bits.",
                    references=(RFC_7517, RFC_7518),
                )
            )
        return findings


class EcParameterCheck(JwkCheck):
    """Require EC public coordinates on a curve this stage can verify."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        if canonical_kty(key.get("kty")) != "EC":
            return []
        kid = _kid_evidence(key, index)
        findings: list[Finding] = []
        missing = [name for name in ("crv", "x", "y") if not isinstance(key.get(name), str) or not str(key.get(name))]
        if missing:
            return [
                _finding(
                    "JWT-JWKS-006",
                    "Incomplete EC key",
                    Severity.HIGH,
                    "An EC public key needs crv, x, and y.",
                    f"{kid}; missing={','.join(missing)}",
                    "The key cannot verify an ECDSA signature.",
                    "Publish crv, x, and y for a P-256, P-384, or P-521 key.",
                )
            ]
        crv = str(key.get("crv"))
        if crv not in _EC_CLASSES:
            findings.append(
                _finding(
                    "JWT-JWKS-019",
                    "Unsupported EC curve",
                    Severity.MEDIUM,
                    "crv is not a curve this analyzer verifies.",
                    f"{kid}; crv={_preview(crv)}",
                    "The key cannot be matched to ES256, ES384, or ES512.",
                    "Use P-256, P-384, or P-521.",
                )
            )
        alg = key.get("alg")
        if isinstance(alg, str) and alg in _EC_CURVE_FOR_ALG and crv in _EC_CLASSES:
            expected = _EC_CURVE_FOR_ALG[alg]
            if crv != expected:
                findings.append(
                    _finding(
                        "JWT-JWKS-019",
                        "EC curve does not match alg",
                        Severity.HIGH,
                        "The curve and the advertised algorithm select different signature sizes.",
                        f"{kid}; crv={crv}; alg={alg}; expected_crv={expected}",
                        "Verification would use the wrong curve for this algorithm.",
                        f"Use {expected} with {alg}, or change alg.",
                        references=(RFC_7518,),
                    )
                )
        for name in ("x", "y"):
            try:
                decode_b64url(str(key.get(name)))
            except ValueError:
                findings.append(
                    _finding(
                        "JWT-JWKS-006",
                        "Incomplete EC key",
                        Severity.HIGH,
                        "EC coordinates must be base64url strings.",
                        f"{kid}; parameter={name}",
                        "The key cannot be imported.",
                        "Encode x and y with base64url.",
                    )
                )
                break
        return findings


class SymmetricKeyCheck(JwkCheck):
    """Flag an oct key, and require ``k`` when one is published."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        if canonical_kty(key.get("kty")) != "oct":
            return []
        kid = _kid_evidence(key, index)
        material = key.get("k")
        if not isinstance(material, str) or not material:
            return [
                _finding(
                    "JWT-JWKS-009",
                    "Incomplete symmetric key",
                    Severity.HIGH,
                    "An oct key needs the k parameter, but a public JWKS should not contain one.",
                    f"{kid}; kty=oct",
                    "The key cannot verify HMAC, and publishing k would disclose the secret.",
                    "Do not publish HMAC secrets in a JWKS. Verify HMAC with a local secret.",
                )
            ]
        try:
            decode_b64url(material)
        except ValueError:
            return [
                _finding(
                    "JWT-JWKS-009",
                    "Incomplete symmetric key",
                    Severity.HIGH,
                    "The oct key parameter k is not valid base64url.",
                    f"{kid}; kty=oct",
                    "The secret could not be read, and it is still present in a published set.",
                    "Remove symmetric keys from the JWKS.",
                )
            ]
        return [
            _finding(
                "JWT-JWKS-009",
                "Symmetric key published in JWKS",
                Severity.HIGH,
                "An oct key carries the HMAC secret. A JWKS is a public document.",
                f"{kid}; kty=oct; parameter=k",
                "Anyone who can read this JWKS can forge HS256, HS384, and HS512 tokens.",
                "Remove k from the published set and store the HMAC secret locally.",
                references=(RFC_7517,),
            )
        ]


class PrivateMaterialCheck(JwkCheck):
    """Detect private JWK members that must not be published."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        present = [name for name in ("d", "p", "q", "dp", "dq", "qi", "oth") if name in key and key.get(name) not in (None, "")]
        if not present:
            return []
        return [
            _finding(
                "JWT-JWKS-008",
                "Private key material published",
                Severity.CRITICAL,
                "The JWK contains private key members. A JWKS is shared with verifiers and is not a private key store.",
                f"{_kid_evidence(key, index)}; parameters={','.join(present)}",
                "Anyone who can read this document can forge tokens for this key.",
                "Remove private members, rotate the key, and publish only the public parameters.",
                references=(RFC_7517,),
            )
        ]


class UseAndOpsCheck(JwkCheck):
    """Detect ``use`` and ``key_ops`` values that contradict each other."""

    def check(self, key: Mapping[str, Any], index: int) -> list[Finding]:
        kid = _kid_evidence(key, index)
        findings: list[Finding] = []
        use = key.get("use")
        if use is not None and (not isinstance(use, str) or use not in {"sig", "enc"}):
            findings.append(
                _finding(
                    "JWT-JWKS-010",
                    "Invalid use",
                    Severity.MEDIUM,
                    "JWK use is sig or enc when it is present.",
                    f"{kid}; use={_preview(use)}",
                    "The key may be selected for the wrong operation.",
                    "Set use to sig for verification keys or enc for encryption keys.",
                )
            )
        ops = key.get("key_ops")
        if ops is None:
            return findings
        if not isinstance(ops, list) or not all(isinstance(item, str) for item in ops):
            findings.append(
                _finding(
                    "JWT-JWKS-010",
                    "Invalid key_ops",
                    Severity.MEDIUM,
                    "key_ops must be an array of strings.",
                    f"{kid}; key_ops_type={type(ops).__name__}",
                    "Operation restrictions on the key will be ignored or misread.",
                    "Publish key_ops as an array of registered operation names.",
                )
            )
            return findings
        if isinstance(use, str) and use in {"sig", "enc"} and ops:
            allowed = _SIG_OPS if use == "sig" else _ENC_OPS
            if set(ops).isdisjoint(allowed):
                findings.append(
                    _finding(
                        "JWT-JWKS-010",
                        "Inconsistent use and key_ops",
                        Severity.HIGH,
                        "use and key_ops describe different operations.",
                        f"{kid}; use={use}; key_ops={','.join(ops)}",
                        "A verifier and an encrypting party can disagree about what the key is for.",
                        "Align use and key_ops, or publish only one of them.",
                        references=(RFC_7517,),
                    )
                )
        return findings


class MissingKidCheck(JwksDocumentCheck):
    """Warn when keys that need to be selected have no kid."""

    def check(self, keys: Sequence[JwkRecord]) -> list[Finding]:
        findings: list[Finding] = []
        severity = Severity.LOW if len(keys) == 1 else Severity.MEDIUM
        for key in keys:
            if key.kid:
                continue
            if _raw_kid_is_invalid(key):
                continue
            findings.append(
                _finding(
                    "JWT-JWKS-001",
                    "Missing kid",
                    severity,
                    "The key has no kid, so a token cannot name it.",
                    f"index={key.index}; keys={len(keys)}",
                    "With more than one key, verification cannot tell which key the token used.",
                    "Assign a unique kid to every published key.",
                )
            )
        return findings


class DuplicateKidCheck(JwksDocumentCheck):
    """Reject two keys that share one kid."""

    def check(self, keys: Sequence[JwkRecord]) -> list[Finding]:
        groups: dict[str, list[int]] = {}
        for key in keys:
            if not key.kid:
                continue
            groups.setdefault(key.kid, []).append(key.index)
        findings: list[Finding] = []
        for kid, indexes in groups.items():
            if len(indexes) < 2:
                continue
            rendered = ",".join(str(index) for index in indexes)
            findings.append(
                _finding(
                    "JWT-JWKS-002",
                    "Duplicate kid",
                    Severity.HIGH,
                    "More than one key uses the same kid.",
                    f"kid={_preview(kid)}; indexes={rendered}",
                    "A verifier can pick either key and accept a signature the issuer did not intend.",
                    "Keep kid unique across the published set.",
                    references=(RFC_7517,),
                )
            )
        return findings


class SigningKeySetCheck(JwksDocumentCheck):
    """Report a set with no signature keys, and note a rotation set."""

    def check(self, keys: Sequence[JwkRecord]) -> list[Finding]:
        signing = [key for key in keys if is_signing_key(key)]
        if not signing:
            return [
                _finding(
                    "JWT-JWKS-012",
                    "JWKS has no signature keys",
                    Severity.HIGH,
                    "None of the keys are marked for signature use.",
                    f"keys={len(keys)}; signing_keys=0",
                    "Tokens cannot be verified from this document.",
                    "Publish at least one key with use sig, or omit use for a verification key.",
                )
            ]
        if len(signing) >= 2:
            kids = ",".join(key.kid or f"index:{key.index}" for key in signing)
            return [
                _finding(
                    "JWT-JWKS-013",
                    "Multiple signing keys published",
                    Severity.INFO,
                    "More than one signing key is present. That is the usual shape of a rotation set.",
                    f"signing_keys={len(signing)}; kids={kids}",
                    "Verifiers must select the key by kid instead of using the first key.",
                    "Keep retired keys only while tokens signed with them are still accepted.",
                )
            ]
        return []


class JwksAnalyzer(BaseAnalyzer):
    """Match a token ``kid`` to a JWKS key and verify the signature."""

    def __init__(self, config: Optional[JwksAnalysisConfig] = None) -> None:
        self.config = config if config is not None else JwksAnalysisConfig()

    @property
    def name(self) -> str:
        return "jwks"

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        document = self._load()
        if document is None:
            return []
        report = match_token(token, document)
        return list(document.all_findings + report.findings)

    def inspect(self, token: ParsedJWT) -> Optional[JwksMatchReport]:
        """Verify ``token`` against the configured JWKS.

        Returns ``None`` when no JWKS was configured.
        """
        document = self._load()
        if document is None:
            return None
        return match_token(token, document)

    def _load(self) -> Optional[JwksDocument]:
        if self.config.document is not None:
            return self.config.document
        if not self.config.location:
            return None
        return load_jwks(
            self.config.location,
            fetcher=self.config.fetcher,
            timeout=self.config.timeout_seconds,
            max_bytes=self.config.max_bytes,
        )


def get_jwks_source(location: str) -> JwksSource:
    """Return the reader for a filesystem path or an HTTP(S) URL."""
    text = location.strip() if isinstance(location, str) else ""
    if not text:
        raise JwksError("JWKS location is empty", code="EMPTY_LOCATION")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme in {"http", "https"}:
        if not parts.hostname:
            raise JwksError("JWKS URL has no host", code="INVALID_URL")
        return UrlJwksSource(text)
    if scheme and len(scheme) > 1:
        raise JwksError(f"Unsupported JWKS location scheme: {parts.scheme}", code="UNSUPPORTED_SCHEME")
    return FileJwksSource(text)


def load_jwks(
    location: str,
    *,
    fetcher: Optional[Callable[[str], bytes]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    key_checks: Optional[Sequence[JwkCheck]] = None,
    document_checks: Optional[Sequence[JwksDocumentCheck]] = None,
) -> JwksDocument:
    """Load a JWKS from a URL or a local file and evaluate its keys."""
    source = get_jwks_source(location)
    data = source.read(fetcher=fetcher, timeout=timeout, max_bytes=max_bytes)
    document = parse_jwks(data, source=location, key_checks=key_checks, document_checks=document_checks)
    extra = source.findings()
    if not extra:
        return document
    return replace(document, findings=document.findings + extra)


def parse_jwks(
    data: bytes,
    *,
    source: str = "jwks",
    key_checks: Optional[Sequence[JwkCheck]] = None,
    document_checks: Optional[Sequence[JwksDocumentCheck]] = None,
) -> JwksDocument:
    """Parse JWKS bytes and run the key-check chain."""
    parsed = _load_json_object(data)
    keys_value = parsed.get("keys")
    if not isinstance(keys_value, list):
        raise JwksError("JWKS document must be an object with a keys array", code="INVALID_JWKS")
    if len(keys_value) > _MAX_KEYS:
        raise JwksError(f"JWKS contains more than {_MAX_KEYS} keys", code="TOO_MANY_KEYS")
    checks = tuple(key_checks) if key_checks is not None else _default_key_checks()
    records = tuple(_record_from_key(item, index, checks) for index, item in enumerate(keys_value))
    set_checks = tuple(document_checks) if document_checks is not None else _default_document_checks()
    findings: list[Finding] = []
    for check in set_checks:
        findings.extend(check.check(records))
    return JwksDocument(source=source, keys=records, findings=tuple(findings))


def match_token(token: ParsedJWT, document: JwksDocument) -> JwksMatchReport:
    """Find the JWKS key for ``token`` by kid and verify the signature."""
    alg = token.header.get("alg")
    token_alg = alg if isinstance(alg, str) else None
    kid_value = token.header.get("kid") if "kid" in token.header else None
    if kid_value is not None and not isinstance(kid_value, str):
        finding = _finding(
            "JWT-JWKS-020",
            "No matching key found",
            Severity.HIGH,
            "The token kid is not a string, so it cannot select a JWKS key.",
            f"kid_type={type(kid_value).__name__}",
            "The signature was not checked.",
            "Set the token kid to the string identifier of a published key.",
        )
        return _match_report(document, None, token_alg, None, False, None, None, None, None, (finding,), "No matching key found")

    kid = kid_value if isinstance(kid_value, str) and kid_value else None
    if kid is None:
        return _match_without_kid(token, document, token_alg)
    chosen = [key for key in document.keys if key.kid == kid]
    if not chosen:
        finding = _finding(
            "JWT-JWKS-020",
            "No matching key found",
            Severity.HIGH,
            "No JWKS key uses the token kid.",
            f"kid={_preview(kid)}; keys={len(document.keys)}",
            "The signature was not checked.",
            "Publish the signing key under this kid, or reissue the token with a current kid.",
        )
        return _match_report(document, kid, token_alg, None, False, None, None, None, None, (finding,), "No matching key found")
    if len(chosen) > 1:
        finding = _finding(
            "JWT-JWKS-026",
            "Ambiguous JWKS key",
            Severity.HIGH,
            "Several keys share the token kid, so none was used for verification.",
            f"kid={_preview(kid)}; matches={len(chosen)}",
            "The signature was not checked.",
            "Publish a single key for each kid.",
        )
        return _match_report(document, kid, token_alg, None, False, None, None, None, None, (finding,), "Ambiguous JWKS key")
    return _verify_chosen(token, document, chosen[0], kid, token_alg)


def format_jwks_analysis(
    document: JwksDocument,
    match: Optional[JwksMatchReport] = None,
) -> str:
    """Render key metadata, suspicious-key findings, and an optional match checklist."""
    lines = [
        "JWKS Analysis",
        "──────────────────────",
        f"Source : {document.source}",
        f"Keys   : {len(document.keys)}",
    ]
    if not document.keys:
        lines.append("")
        lines.append("(no keys)")
    for key in document.keys:
        lines.append("")
        lines.extend(_format_key(key))
    visible = [item for item in document.all_findings if item.id not in _CHECKLIST_IDS]
    if match is not None:
        visible.extend(item for item in match.findings if item.id not in _CHECKLIST_IDS)
    lines.append("")
    if visible:
        lines.append("Findings")
        lines.append("──────────────────────")
        for item in visible:
            lines.append(f"[{item.severity.value}] {item.id} {item.title}")
            lines.append(item.evidence)
    else:
        lines.append("Findings : none")
    if match is not None:
        lines.append("")
        lines.extend(_format_checklist(match))
    return "\n".join(lines)


def canonical_kty(value: Any) -> Optional[str]:
    """Return the registered spelling of ``kty``, if it is recognized."""
    if not isinstance(value, str):
        return None
    return _KTY_CANONICAL.get(value.strip().lower())


def is_signing_key(key: JwkRecord) -> bool:
    """Return True when the key can be considered for signature verification."""
    if key.canonical_kty not in {"RSA", "EC", "oct"}:
        return False
    if key.use == "enc":
        return False
    return True


def decode_b64url(segment: str) -> bytes:
    """Decode an unpadded base64url string."""
    if not isinstance(segment, str) or not _B64URL_RE.fullmatch(segment):
        raise ValueError("invalid base64url")
    if len(segment) % 4 == 1:
        raise ValueError("invalid base64url")
    padded = segment + ("=" * ((4 - len(segment) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url") from exc


def b64url_uint(segment: str) -> int:
    """Decode a JWK unsigned integer."""
    raw = decode_b64url(segment)
    if not raw:
        raise ValueError("empty integer")
    return int.from_bytes(raw, "big")


def _default_key_checks() -> tuple[JwkCheck, ...]:
    return (
        KidParameterCheck(),
        KeyTypeCheck(),
        AlgorithmConsistencyCheck(),
        RsaParameterCheck(),
        EcParameterCheck(),
        SymmetricKeyCheck(),
        PrivateMaterialCheck(),
        UseAndOpsCheck(),
    )


def _default_document_checks() -> tuple[JwksDocumentCheck, ...]:
    return (MissingKidCheck(), DuplicateKidCheck(), SigningKeySetCheck())


def _record_from_key(item: Any, index: int, checks: Sequence[JwkCheck]) -> JwkRecord:
    if not isinstance(item, dict):
        finding = _finding(
            "JWT-JWKS-014",
            "Invalid JWKS key entry",
            Severity.MEDIUM,
            "Each member of keys must be a JSON object.",
            f"index={index}; value_type={type(item).__name__}",
            "This entry cannot be used to verify a token.",
            "Remove the entry or replace it with a JWK object.",
        )
        return JwkRecord(
            index=index,
            kid=None,
            kty=None,
            canonical_kty=None,
            use=None,
            alg=None,
            key_ops=(),
            n=None,
            e=None,
            x=None,
            y=None,
            crv=None,
            modulus_bits=None,
            findings=(finding,),
            raw={},
        )
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check.check(item, index))
    kty = item.get("kty") if isinstance(item.get("kty"), str) else None
    use = item.get("use") if isinstance(item.get("use"), str) else None
    alg = item.get("alg") if isinstance(item.get("alg"), str) and item.get("alg").strip() else None
    kid = item.get("kid") if isinstance(item.get("kid"), str) and item.get("kid") else None
    ops_value = item.get("key_ops")
    key_ops = tuple(entry for entry in ops_value if isinstance(entry, str)) if isinstance(ops_value, list) else ()
    n_value = item.get("n") if isinstance(item.get("n"), str) else None
    e_value = item.get("e") if isinstance(item.get("e"), str) else None
    modulus_bits = None
    if n_value:
        try:
            modulus_bits = b64url_uint(n_value).bit_length()
        except ValueError:
            modulus_bits = None
    return JwkRecord(
        index=index,
        kid=kid,
        kty=kty,
        canonical_kty=canonical_kty(kty),
        use=use,
        alg=alg.strip() if isinstance(alg, str) else None,
        key_ops=key_ops,
        n=n_value,
        e=e_value,
        x=item.get("x") if isinstance(item.get("x"), str) else None,
        y=item.get("y") if isinstance(item.get("y"), str) else None,
        crv=item.get("crv") if isinstance(item.get("crv"), str) else None,
        modulus_bits=modulus_bits,
        findings=tuple(findings),
        raw=dict(item),
    )


def _match_without_kid(
    token: ParsedJWT,
    document: JwksDocument,
    token_alg: Optional[str],
) -> JwksMatchReport:
    signing = [key for key in document.keys if is_signing_key(key)]
    if len(document.keys) == 1:
        return _verify_chosen(token, document, document.keys[0], None, token_alg)
    if len(signing) == 1 and all(not key.kid for key in document.keys):
        return _verify_chosen(token, document, signing[0], None, token_alg)
    finding = _finding(
        "JWT-JWKS-026",
        "Ambiguous JWKS key",
        Severity.HIGH,
        "The token has no kid and the JWKS has more than one key.",
        f"keys={len(document.keys)}; signing_keys={len(signing)}",
        "The signature was not checked.",
        "Send kid on the token and publish a unique kid on each key.",
    )
    return _match_report(document, None, token_alg, None, False, None, None, None, None, (finding,), "Ambiguous JWKS key")


def _verify_chosen(
    token: ParsedJWT,
    document: JwksDocument,
    key: JwkRecord,
    kid: Optional[str],
    token_alg: Optional[str],
) -> JwksMatchReport:
    findings = [
        _finding(
            "JWT-JWKS-021",
            "Matching key found",
            Severity.INFO,
            "A JWKS key was selected for this token.",
            f"kid={kid or '-'}; index={key.index}; kty={key.canonical_kty or '-'}",
            "The selected key is the one used for the signature check.",
            "Confirm this kid is still an active signing key.",
        )
    ]
    if key.use == "enc" or not is_signing_key(key):
        findings.append(
            _finding(
                "JWT-JWKS-027",
                "Key is not a signing key",
                Severity.HIGH,
                "The key selected by kid is not marked for signatures.",
                f"kid={kid or '-'}; use={key.use or '-'}; kty={key.canonical_kty or '-'}",
                "The signature was not checked with an encryption or unsupported key.",
                "Point kid at a key whose use is sig or absent.",
            )
        )
        return _match_report(
            document, kid, token_alg, key, True, None, None, None, False, tuple(findings), "Key is not a signing key"
        )
    if token_alg is None or token_alg.strip().lower() == "none":
        shown = token_alg or "-"
        finding_id = "JWT-JWKS-030" if token_alg and token_alg.strip().lower() == "none" else "JWT-JWKS-028"
        title = "Unsecured algorithm cannot be verified" if finding_id == "JWT-JWKS-030" else "Unsupported algorithm for JWKS verification"
        findings.append(
            _finding(
                finding_id,
                title,
                Severity.MEDIUM,
                "This stage only verifies HS*, RS256, RS384, RS512, ES256, ES384, and ES512.",
                f"algorithm={shown}; kid={kid or '-'}",
                "The signature was not checked.",
                "Use a supported signing algorithm.",
            )
        )
        return _match_report(document, kid, token_alg, key, True, False, None, None, True, tuple(findings), title)

    family_ok = _family_matches(key.canonical_kty, token_alg, key.crv)
    curve_ok = _curve_matches(token_alg, key.crv)
    alg_constrained = bool(key.alg) and key.alg != token_alg
    if not family_ok:
        findings.append(
            _finding(
                "JWT-JWKS-023",
                "Key type does not match algorithm",
                Severity.HIGH,
                "The JWKS key type cannot verify the token algorithm.",
                f"algorithm={token_alg}; kty={key.canonical_kty or '-'}; kid={kid or '-'}",
                "Verification was refused so a public key is not used as an HMAC secret.",
                "Verify with a key whose kty matches alg.",
                references=(RFC_7517, RFC_7518),
            )
        )
        return _match_report(
            document, kid, token_alg, key, True, None, False, None, True, tuple(findings), "Key type does not match algorithm"
        )
    if not curve_ok or alg_constrained:
        expected = key.alg or _EC_CURVE_FOR_ALG.get(token_alg, "-")
        findings.append(
            _finding(
                "JWT-JWKS-022",
                "Algorithm does not match",
                Severity.HIGH,
                "The token alg does not match the algorithm or curve advertised by the key.",
                f"token_alg={token_alg}; key_alg={key.alg or '-'}; crv={key.crv or '-'}; kid={kid or '-'}",
                "The signature was not checked with a key constrained to a different algorithm.",
                f"Use a key whose alg is {token_alg}, or re-sign the token with {expected}.",
                references=(RFC_7518,),
            )
        )
        return _match_report(
            document, kid, token_alg, key, True, False, True, None, True, tuple(findings), "Algorithm does not match"
        )
    if token_alg not in _VERIFIABLE:
        findings.append(
            _finding(
                "JWT-JWKS-028",
                "Unsupported algorithm for JWKS verification",
                Severity.MEDIUM,
                "The key type fits, but this stage does not verify this algorithm.",
                f"algorithm={token_alg}; kid={kid or '-'}",
                "The signature was not checked.",
                "Use RS256, RS384, RS512, ES256, ES384, ES512, or an HMAC algorithm with a local secret.",
            )
        )
        return _match_report(
            document,
            kid,
            token_alg,
            key,
            True,
            True,
            True,
            None,
            True,
            tuple(findings),
            "Unsupported algorithm for JWKS verification",
        )
    try:
        material = _verification_material(key, token_alg)
        valid = get_verifier(token_alg).verify(token, material)
    except (ValueError, TypeError) as exc:
        findings.append(
            _finding(
                "JWT-JWKS-016",
                "Key material could not be loaded",
                Severity.MEDIUM,
                "The selected JWK could not be turned into a verification key.",
                f"kid={kid or '-'}; algorithm={token_alg}; error={type(exc).__name__}",
                "The signature was not checked.",
                "Publish a complete public key for this algorithm.",
            )
        )
        return _match_report(
            document, kid, token_alg, key, True, True, True, None, True, tuple(findings), "Key material could not be loaded"
        )
    if valid:
        findings.append(
            _finding(
                "JWT-JWKS-024",
                "Signature verified",
                Severity.INFO,
                "The JWKS key selected by kid produced this token's signature.",
                f"algorithm={token_alg}; signature=VALID; kid={kid or '-'}",
                "The signature matches the published key.",
                "Continue checking issuer, audience, and token lifetime.",
                references=(RFC_7515, RFC_7517),
            )
        )
        message = "Signature verified"
    else:
        findings.append(
            _finding(
                "JWT-JWKS-025",
                "Signature verification failed",
                Severity.MEDIUM,
                "The JWKS key selected by kid did not produce this token's signature.",
                f"algorithm={token_alg}; signature=INVALID; kid={kid or '-'}",
                "The token is not authentic under the published key.",
                "Confirm the token was not modified and that kid still identifies this key.",
                references=(RFC_7515, RFC_7517),
            )
        )
        message = "Signature verification failed"
    return _match_report(document, kid, token_alg, key, True, True, True, valid, True, tuple(findings), message)


def _verification_material(key: JwkRecord, algorithm: str) -> Any:
    if key.canonical_kty == "oct":
        secret = key.raw.get("k")
        if not isinstance(secret, str):
            raise ValueError("missing oct key")
        return decode_b64url(secret)
    if key.canonical_kty == "RSA":
        modulus = b64url_uint(str(key.n))
        exponent = b64url_uint(str(key.e))
        return RSAPublicNumbers(exponent, modulus).public_key()
    if key.canonical_kty == "EC":
        curve_name = _EC_CURVE_FOR_ALG.get(algorithm)
        curve_type = _EC_CLASSES.get(key.crv or "")
        if curve_name is None or curve_type is None or curve_name != key.crv:
            raise ValueError("curve does not match algorithm")
        x_value = b64url_uint(str(key.x))
        y_value = b64url_uint(str(key.y))
        return EllipticCurvePublicNumbers(x_value, y_value, curve_type()).public_key()
    raise ValueError("unsupported key type")


def _family_matches(kty: Optional[str], algorithm: str, crv: Optional[str]) -> bool:
    del crv
    if kty == "RSA":
        return algorithm in _RSA_ALGS
    if kty == "EC":
        return algorithm in _EC_CURVE_FOR_ALG
    if kty == "oct":
        return algorithm in _HMAC_ALGS
    return False


def _curve_matches(algorithm: str, crv: Optional[str]) -> bool:
    expected = _EC_CURVE_FOR_ALG.get(algorithm)
    if expected is None:
        return True
    if not crv:
        return True
    return crv == expected


def _match_report(
    document: JwksDocument,
    kid: Optional[str],
    alg: Optional[str],
    key: Optional[JwkRecord],
    matched: bool,
    algorithm_matches: Optional[bool],
    key_type_matches: Optional[bool],
    signature_valid: Optional[bool],
    signing_key: Optional[bool],
    findings: tuple[Finding, ...],
    message: str,
) -> JwksMatchReport:
    return JwksMatchReport(
        document=document,
        token_kid=kid,
        token_alg=alg,
        key=key,
        matched=matched,
        algorithm_matches=algorithm_matches,
        key_type_matches=key_type_matches,
        signature_valid=signature_valid,
        signing_key=signing_key,
        findings=findings,
        message=message,
    )


def _format_key(key: JwkRecord) -> list[str]:
    lines = [
        _line("kid", key.kid or "-"),
        _line("kty", key.kty or "-"),
        _line("use", key.use or "-"),
        _line("alg", key.alg or "-"),
        _line("key_ops", ", ".join(key.key_ops) if key.key_ops else "-"),
    ]
    if key.canonical_kty == "RSA" or key.n or key.e:
        if key.modulus_bits:
            lines.append(_line("n", f"present ({key.modulus_bits} bits)"))
        elif key.n:
            lines.append(_line("n", "present"))
        else:
            lines.append(_line("n", "-"))
        lines.append(_line("e", key.e if key.e and len(key.e) <= 16 else ("present" if key.e else "-")))
    if key.canonical_kty == "EC" or key.crv or key.x or key.y:
        lines.append(_line("crv", key.crv or "-"))
        lines.append(_line("x", "present" if key.x else "-"))
        lines.append(_line("y", "present" if key.y else "-"))
    if key.canonical_kty == "oct":
        lines.append(_line("k", "present" if key.raw.get("k") else "-"))
    return lines


def _format_checklist(match: JwksMatchReport) -> list[str]:
    lines: list[str] = []
    if match.matched:
        lines.append("[✓] Matching key found")
    elif any(item.id == "JWT-JWKS-026" for item in match.findings):
        lines.append("[WARNING] Ambiguous JWKS key")
        return lines
    else:
        lines.append("[WARNING] No matching key found")
        return lines
    if match.signing_key is False:
        lines.append("[WARNING] Key is not a signing key")
        return lines
    if match.key_type_matches is True:
        lines.append("[✓] Key type matches")
    elif match.key_type_matches is False:
        lines.append("[WARNING] Key type does not match")
    if match.algorithm_matches is True:
        lines.append("[✓] Algorithm matches")
    elif match.algorithm_matches is False:
        lines.append("[WARNING] Algorithm does not match")
    if match.signature_valid is True:
        lines.append("[✓] Signature verified")
    elif match.signature_valid is False:
        lines.append("[WARNING] Signature verification failed")
    elif match.algorithm_matches is True and match.key_type_matches is True:
        lines.append("[WARNING] Signature was not checked")
    return lines


def _line(label: str, value: str) -> str:
    return f"{label:<7}: {value}"


def _load_json_object(data: bytes) -> dict[str, Any]:
    if not data:
        raise JwksError("JWKS document is empty", code="INVALID_JWKS")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise JwksError("JWKS document is not valid UTF-8", code="INVALID_JWKS") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JwksError(f"JWKS document is not valid JSON: {exc.msg}", code="INVALID_JWKS") from exc
    if not isinstance(parsed, dict):
        raise JwksError("JWKS document must be a JSON object", code="INVALID_JWKS")
    return parsed


def _raw_kid_is_invalid(key: JwkRecord) -> bool:
    return any(item.id == "JWT-JWKS-001" and item.title in {"Invalid kid", "Empty kid"} for item in key.findings)


def _kid_evidence(key: Mapping[str, Any], index: int) -> str:
    kid = key.get("kid")
    if isinstance(kid, str) and kid:
        return f"index={index}; kid={_preview(kid)}"
    return f"index={index}"


def _preview(value: Any, limit: int = 80) -> str:
    text = value if isinstance(value, str) else repr(value)
    collapsed = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "...(truncated)"


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: tuple[str, ...] = (RFC_7517,),
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
