"""Payload, claim, expiration, and sensitive-data analysis.

Pipeline stage:

    Input -> Parser -> HeaderAnalyzer -> PayloadAnalyzer -> (later analyzers)

Each check is a strategy in a fixed chain. The chain reads the decoded
payload and, for duplicate keys, parses the raw payload segment again.
``json.loads`` keeps only the last value, so duplicate detection uses a
pair-preserving parse. No check prints a sensitive claim value in clear text.
"""

from __future__ import annotations

import json
import math
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT, decode_base64url

RFC_7519 = "https://www.rfc-editor.org/rfc/rfc7519"
RFC_8259 = "https://www.rfc-editor.org/rfc/rfc8259#section-4"

# Registered claims from the issue. ``exp`` is reported with its own id.
DEFAULT_REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "jti"})

SENSITIVE_KEYWORDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "authorization",
        "credit_card",
        "card_number",
    }
)

_STRING_CLAIMS = frozenset({"iss", "sub", "jti"})
_TIME_CLAIMS = frozenset({"exp", "iat", "nbf"})
_REGISTERED_CLAIMS = _STRING_CLAIMS | _TIME_CLAIMS | {"aud"}

_MISSING_SEVERITY = {
    "exp": Severity.HIGH,
    "iss": Severity.MEDIUM,
    "sub": Severity.MEDIUM,
    "aud": Severity.MEDIUM,
    "iat": Severity.MEDIUM,
    "nbf": Severity.LOW,
    "jti": Severity.LOW,
}

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


@dataclass(frozen=True)
class PayloadAnalysisConfig:
    """Policy for payload analysis.

    ``required_claims`` selects which claims produce a missing-claim finding.
    The default set is the registered claims from the claim analysis. Missing
    ``exp`` is always reported as high when it is in that set.

    ``max_lifetime_seconds`` is the lifetime threshold (``exp - iat``).
    ``leeway_seconds`` tolerates small clock skew for expired, not-yet-valid,
    and future ``iat`` checks. Temporal ordering ignores leeway.

    ``now`` fixes the clock for tests. ``None`` uses the current time.
    """

    required_claims: frozenset[str] = field(
        default_factory=lambda: DEFAULT_REQUIRED_CLAIMS
    )
    max_lifetime_seconds: float = 3600
    leeway_seconds: float = 0
    now: Optional[float] = None
    check_sensitive_claims: bool = True
    check_duplicate_claims: bool = True
    sensitive_keywords: frozenset[str] = field(
        default_factory=lambda: SENSITIVE_KEYWORDS
    )

    def __post_init__(self) -> None:
        if any(not isinstance(claim, str) or not claim.strip() for claim in self.required_claims):
            raise ValueError("required_claims must contain non-empty strings")
        if not _is_non_negative_number(self.max_lifetime_seconds):
            raise ValueError("max_lifetime_seconds must be a non-negative number")
        if not _is_non_negative_number(self.leeway_seconds):
            raise ValueError("leeway_seconds must be a non-negative number")
        if self.now is not None and _numeric(self.now) is None:
            raise ValueError("now must be a finite number or None")
        if any(not isinstance(keyword, str) or not keyword.strip() for keyword in self.sensitive_keywords):
            raise ValueError("sensitive_keywords must contain non-empty strings")
        object.__setattr__(self, "required_claims", frozenset(self.required_claims))
        object.__setattr__(
            self,
            "sensitive_keywords",
            frozenset(keyword.strip().lower() for keyword in self.sensitive_keywords),
        )

    def current_time(self) -> float:
        """Return the configured clock, or the current Unix time."""
        if self.now is None:
            return time.time()
        return float(self.now)


class PayloadCheck(ABC):
    """Strategy that inspects one aspect of a JWT payload."""

    @abstractmethod
    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        """Return findings for this check. Do not raise for weak claims."""


class DuplicateClaimCheck(PayloadCheck):
    """Section 20: report repeated JSON keys the standard parser would collapse."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        if not config.check_duplicate_claims:
            return []
        raw = decode_base64url(token.payload_segment, "payload")
        duplicates = find_duplicate_keys(raw.decode("utf-8"))
        return [_duplicate_finding(path, key) for path, key in duplicates]


class ClaimPresenceCheck(PayloadCheck):
    """Report required claims that are absent or JSON null."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for claim in sorted(config.required_claims):
            if _is_present(token.payload, claim):
                continue
            if claim == "exp":
                findings.append(_missing_expiration())
            else:
                findings.append(_missing_claim(claim))
        return findings


class ClaimTypeCheck(PayloadCheck):
    """Validate JSON types of registered claims when they are present."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        del config
        findings: list[Finding] = []
        for claim in sorted(_REGISTERED_CLAIMS):
            if not _is_present(token.payload, claim):
                continue
            value = token.payload[claim]
            if _has_valid_type(claim, value):
                continue
            findings.append(
                _type_finding(claim, value),
            )
        return findings


class ClaimValueCheck(PayloadCheck):
    """Reject empty strings and empty audiences after the type check passes."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        del config
        findings: list[Finding] = []
        payload = token.payload
        for claim in sorted(_STRING_CLAIMS):
            value = payload.get(claim)
            if isinstance(value, str) and value.strip() == "":
                findings.append(_empty_value_finding(claim, "empty"))
        aud = payload.get("aud")
        if isinstance(aud, str) and aud.strip() == "":
            findings.append(_empty_value_finding("aud", "empty"))
        elif isinstance(aud, list) and _aud_elements_are_strings(aud):
            if not aud:
                findings.append(_empty_value_finding("aud", "empty_array"))
            elif any(item.strip() == "" for item in aud):
                findings.append(_empty_value_finding("aud", "empty_element"))
        return findings


class ExpirationStateCheck(PayloadCheck):
    """Compare ``exp``, ``nbf``, and ``iat`` with the configured clock."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        payload = token.payload
        now = config.current_time()
        leeway = float(config.leeway_seconds)
        findings: list[Finding] = []

        exp = _numeric(payload.get("exp")) if _is_present(payload, "exp") else None
        nbf = _numeric(payload.get("nbf")) if _is_present(payload, "nbf") else None
        iat = _numeric(payload.get("iat")) if _is_present(payload, "iat") else None

        if exp is not None and now >= exp + leeway:
            findings.append(
                Finding(
                    id="JWT-EXP-002",
                    title="Token has expired",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The current time is on or after the exp claim.",
                    evidence=f"exp={_num(exp)}; now={_num(now)}; leeway_seconds={_num(leeway)}",
                    impact="Verifiers that honor exp must reject this token.",
                    remediation="Issue a new token. Do not disable expiration checks in the verifier.",
                    references=(RFC_7519,),
                )
            )
        if nbf is not None and now < nbf - leeway:
            findings.append(
                Finding(
                    id="JWT-EXP-003",
                    title="Token is not yet valid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The current time is before the nbf claim.",
                    evidence=f"nbf={_num(nbf)}; now={_num(now)}; leeway_seconds={_num(leeway)}",
                    impact="The token should be rejected until nbf.",
                    remediation="Check the issuer clock and the not-before value.",
                    references=(RFC_7519,),
                )
            )
        if iat is not None and iat > now + leeway:
            findings.append(
                Finding(
                    id="JWT-EXP-005",
                    title="Issued-at is in the future",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The iat claim is later than the current time.",
                    evidence=f"iat={_num(iat)}; now={_num(now)}; leeway_seconds={_num(leeway)}",
                    impact="A future issued-at can hide clock skew or a forged timestamp.",
                    remediation="Synchronize the issuer clock and reject iat values outside the allowed skew.",
                    references=(RFC_7519,),
                )
            )
        return findings


class TemporalOrderCheck(PayloadCheck):
    """Require ``iat <= nbf <= exp`` for the time claims that are present."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        del config
        payload = token.payload
        exp = _numeric(payload.get("exp")) if _is_present(payload, "exp") else None
        nbf = _numeric(payload.get("nbf")) if _is_present(payload, "nbf") else None
        iat = _numeric(payload.get("iat")) if _is_present(payload, "iat") else None

        relations: list[str] = []
        if iat is not None and nbf is not None and iat > nbf:
            relations.append("iat > nbf")
        if nbf is not None and exp is not None and nbf > exp:
            relations.append("nbf > exp")
        if iat is not None and exp is not None and iat > exp:
            relations.append("iat > exp")
        if not relations:
            return []
        rendered = ", ".join(relations)
        return [
            Finding(
                id="JWT-EXP-004",
                title="Inconsistent temporal claims",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Time claims must satisfy iat <= nbf <= exp when they are present.",
                evidence=f"relations={rendered}",
                impact="The token has an empty or contradictory validity window.",
                remediation="Issue tokens with iat <= nbf <= exp and reject claims that break that order.",
                references=(RFC_7519,),
            )
        ]


class LifetimeCheck(PayloadCheck):
    """Flag ``exp - iat`` when it exceeds the configured threshold."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        payload = token.payload
        exp = _numeric(payload.get("exp")) if _is_present(payload, "exp") else None
        iat = _numeric(payload.get("iat")) if _is_present(payload, "iat") else None
        if exp is None or iat is None:
            return []
        lifetime = exp - iat
        if lifetime <= config.max_lifetime_seconds:
            return []
        now = config.current_time()
        expired = now >= exp + float(config.leeway_seconds)
        return [
            Finding(
                id="JWT-LIFE-001",
                title="Excessive token lifetime",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "Token lifetime is exp minus iat and is above the configured maximum."
                ),
                evidence=(
                    f"lifetime_seconds={_num(lifetime)}; "
                    f"max_lifetime_seconds={_num(config.max_lifetime_seconds)}; "
                    f"iat={_num(iat)}; exp={_num(exp)}; token_expired={str(expired).lower()}"
                ),
                impact="A long-lived token stays useful to an attacker after it is stolen.",
                remediation="Shorten the token lifetime or raise the threshold only for an accepted issuer policy.",
                references=(RFC_7519,),
            )
        ]


class SensitiveDataCheck(PayloadCheck):
    """Section 10: find sensitive claim names and mask their values."""

    def check(
        self,
        token: ParsedJWT,
        config: PayloadAnalysisConfig,
    ) -> list[Finding]:
        if not config.check_sensitive_claims:
            return []
        findings: list[Finding] = []
        _walk_sensitive(token.payload, "payload", config.sensitive_keywords, findings)
        return findings


class PayloadAnalyzer(BaseAnalyzer):
    """Run the payload-analysis chain and collect its findings."""

    def __init__(
        self,
        config: Optional[PayloadAnalysisConfig] = None,
        checks: Optional[Sequence[PayloadCheck]] = None,
    ) -> None:
        self.config = config if config is not None else PayloadAnalysisConfig()
        self.checks: tuple[PayloadCheck, ...] = (
            tuple(checks) if checks is not None else _default_checks()
        )

    @property
    def name(self) -> str:
        return "payload"

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        findings: list[Finding] = []
        for check in self.checks:
            findings.extend(check.check(token, self.config))
        return findings


def analyze_payload(
    token: ParsedJWT,
    config: Optional[PayloadAnalysisConfig] = None,
) -> list[Finding]:
    """Analyze a parsed JWT payload with the default check chain."""
    return PayloadAnalyzer(config).analyze(token)


def find_duplicate_keys(payload_json: str) -> list[tuple[str, str]]:
    """Return ``(path, key)`` for every repeated key in a JSON object tree.

    The path is the object that contains the repeated key, such as ``payload``
    or ``payload.user``. Standard ``json.loads`` cannot report these keys.
    """
    parsed = json.loads(payload_json, object_pairs_hook=_Pairs.from_pairs)
    found: list[tuple[str, str]] = []
    _walk_duplicates(parsed, "payload", found)
    return found


class _Pairs(dict):
    """JSON object that remembers keys seen more than once."""

    def __init__(self) -> None:
        super().__init__()
        self.duplicate_keys: list[str] = []

    @classmethod
    def from_pairs(cls, pairs: list[tuple[Any, Any]]) -> "_Pairs":
        obj = cls()
        for key, value in pairs:
            text = key if isinstance(key, str) else str(key)
            if text in obj and text not in obj.duplicate_keys:
                obj.duplicate_keys.append(text)
            obj[text] = value
        return obj


def _default_checks() -> tuple[PayloadCheck, ...]:
    return (
        DuplicateClaimCheck(),
        ClaimPresenceCheck(),
        ClaimTypeCheck(),
        ClaimValueCheck(),
        ExpirationStateCheck(),
        TemporalOrderCheck(),
        LifetimeCheck(),
        SensitiveDataCheck(),
    )


def _missing_expiration() -> Finding:
    return Finding(
        id="JWT-EXP-001",
        title="Token has no expiration claim",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="The payload does not contain an exp claim.",
        evidence="claim=exp",
        impact="The token can be replayed until the signing key changes.",
        remediation="Require the issuer to set exp and reject tokens that omit it.",
        references=(RFC_7519,),
    )


def _missing_claim(claim: str) -> Finding:
    return Finding(
        id="JWT-CLM-001",
        title="Missing required claim",
        severity=_MISSING_SEVERITY.get(claim, Severity.MEDIUM),
        confidence=Confidence.HIGH,
        description=f"The required claim {claim} is absent or null.",
        evidence=f"claim={claim}",
        impact="The verifier cannot apply the policy that depends on this claim.",
        remediation=f"Configure the issuer to include {claim}, or remove it from required_claims if it is optional.",
        references=(RFC_7519,),
    )


def _type_finding(claim: str, value: Any) -> Finding:
    expected = {
        "iss": "string",
        "sub": "string",
        "jti": "string",
        "aud": "string or array of strings",
        "exp": "NumericDate",
        "iat": "NumericDate",
        "nbf": "NumericDate",
    }[claim]
    return Finding(
        id="JWT-CLM-002",
        title="Invalid claim type",
        severity=Severity.HIGH if claim in _TIME_CLAIMS else Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=f"The {claim} claim does not have the JSON type required for that claim.",
        evidence=f"claim={claim}; expected={expected}; actual_type={_json_type(value)}",
        impact="Verifiers may ignore the claim or coerce it into an unexpected value.",
        remediation=f"Encode {claim} as {expected}.",
        references=(RFC_7519,),
    )


def _empty_value_finding(claim: str, reason: str) -> Finding:
    return Finding(
        id="JWT-CLM-003",
        title="Invalid claim value",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=f"The {claim} claim is present but empty.",
        evidence=f"claim={claim}; reason={reason}",
        impact="An empty identity, audience, or token id does not constrain the token.",
        remediation=f"Set {claim} to a non-empty value or omit it.",
        references=(RFC_7519,),
    )


def _duplicate_finding(path: str, key: str) -> Finding:
    return Finding(
        id="JWT-DUP-001",
        title=f"Duplicate claim detected: {key}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            "The same JSON key appears more than once. This is a formatting anomaly: "
            "common parsers keep only the last value, so two verifiers can disagree."
        ),
        evidence=f"claim={key}; path={path}.{key}; anomaly=duplicate_json_key",
        impact="One service may authorize the first value while another authorizes the last.",
        remediation="Reject payloads with duplicate keys before claim checks. Emit each claim once.",
        references=(RFC_8259,),
    )


def _sensitive_finding(path: str, keyword: str, value: Any) -> Finding:
    return Finding(
        id="JWT-SEC-001",
        title="Potential sensitive information found",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="A payload claim name matches a sensitive-data keyword. The value is masked.",
        evidence=f"claim={path.rsplit('.', 1)[-1]}; path={path}; keyword={keyword}; value={_mask(value)}",
        impact="Anyone who can read the token can read this claim, including logs and browsers.",
        remediation="Remove secrets from the payload. Pass them through a confidential channel.",
        references=(),
    )


def _walk_sensitive(
    node: Any,
    path: str,
    keywords: frozenset[str],
    findings: list[Finding],
) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            name = key if isinstance(key, str) else str(key)
            child = f"{path}.{name}"
            keyword = match_sensitive_keyword(name, keywords)
            if keyword is not None:
                findings.append(_sensitive_finding(child, keyword, value))
            _walk_sensitive(value, child, keywords, findings)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk_sensitive(item, f"{path}[{index}]", keywords, findings)


def _walk_duplicates(node: Any, path: str, found: list[tuple[str, str]]) -> None:
    if isinstance(node, _Pairs):
        for key in node.duplicate_keys:
            found.append((path, key))
        for key, value in node.items():
            _walk_duplicates(value, f"{path}.{key}", found)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk_duplicates(item, f"{path}[{index}]", found)


def match_sensitive_keyword(key: str, keywords: frozenset[str]) -> Optional[str]:
    """Return the longest keyword bounded by separators inside ``key``."""
    normalized = _normalize_claim_name(key)
    padded = f"_{normalized}_"
    ordered = sorted(keywords, key=lambda item: (-len(item), item))
    for keyword in ordered:
        needle = f"_{keyword.replace('-', '_').lower()}_"
        if needle in padded:
            return keyword.replace("-", "_").lower()
    return None


def _normalize_claim_name(key: str) -> str:
    snake = _CAMEL_BOUNDARY_RE.sub("_", key)
    return snake.replace("-", "_").lower()


def _mask(value: Any) -> str:
    """Render a claim value without revealing its contents."""
    if isinstance(value, str):
        return f"***; length={len(value)}"
    if isinstance(value, bool):
        return "***; kind=bool"
    if isinstance(value, (int, float)):
        return "***; kind=number"
    if isinstance(value, dict):
        return "***; kind=object"
    if isinstance(value, list):
        return "***; kind=array"
    if value is None:
        return "***; kind=null"
    return "***; kind=other"


def _is_present(payload: Mapping[str, Any], claim: str) -> bool:
    return claim in payload and payload[claim] is not None


def _has_valid_type(claim: str, value: Any) -> bool:
    if claim in _STRING_CLAIMS:
        return isinstance(value, str)
    if claim in _TIME_CLAIMS:
        return _numeric(value) is not None
    if claim == "aud":
        if isinstance(value, str):
            return True
        return isinstance(value, list) and _aud_elements_are_strings(value)
    return True


def _aud_elements_are_strings(value: list[Any]) -> bool:
    return all(isinstance(item, str) for item in value)


def _numeric(value: Any) -> Optional[float]:
    """Return a finite NumericDate. Booleans are not numbers here."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _is_non_negative_number(value: Any) -> bool:
    number = _numeric(value)
    return number is not None and number >= 0


def _num(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return str(value)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
