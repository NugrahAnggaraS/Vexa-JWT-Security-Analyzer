"""Header security and algorithm analysis.

Pipeline stage:

    Input -> Parser -> HeaderAnalyzer -> (later analyzers)

Each header check is a strategy in a fixed chain. Checks only read the
decoded header. A network fetch is attempted only when assessment mode is
on, the URL is HTTPS, its host is on the explicit allowlist, and the caller
supplied a fetcher. Passive analysis never calls that fetcher.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.parser import ParsedJWT

RFC_7515 = "https://www.rfc-editor.org/rfc/rfc7515"
RFC_7518 = "https://www.rfc-editor.org/rfc/rfc7518"
RFC_7519 = "https://www.rfc-editor.org/rfc/rfc7519"
RFC_8725 = "https://www.rfc-editor.org/rfc/rfc8725"

# Registered JWS algorithms (RFC 7518) plus EdDSA (RFC 8037) and ES256K.
_SYMMETRIC = frozenset({"HS256", "HS384", "HS512", "HS1"})
_ASYMMETRIC = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
        "ES256K",
        "RS1",
        "ES1",
        "PS1",
    }
)
_WEAK = frozenset({"HS1", "RS1", "ES1", "PS1"})
_KNOWN = _SYMMETRIC | _ASYMMETRIC
_CANONICAL_BY_FOLD = {name.lower(): name for name in _KNOWN}

_ACCEPTED_TYP = frozenset(
    {"JWT", "jwt", "at+jwt", "application/at+jwt", "application/jwt"}
)

_DANGEROUS_SCHEMES = frozenset(
    {
        "file",
        "ftp",
        "ftps",
        "gopher",
        "data",
        "javascript",
        "jar",
        "dict",
        "ldap",
        "ldaps",
    }
)

_PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|\.\.;/|%2e%2e(?:%2f|%5c|/|\\)?|\.\.%2f|\.\.%5c|%252e%252e)",
    re.IGNORECASE,
)
_SQL_META_RE = re.compile(
    r"""(?:'|\"|;|--|/\*|\*/|#|`|\b(?:UNION|SELECT|INSERT|DELETE|DROP|OR|AND)\b)""",
    re.IGNORECASE,
)
_SUSPICIOUS_ENCODING_RE = re.compile(
    r"(?:%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\x00|[\r\n])"
)

_URI_COPY = {
    "jku": {
        "id": "JWT-JKU-001",
        "title": "External JWK URL detected",
        "invalid_title": "Invalid jku URL",
        "resource": "JSON Web Key Set",
    },
    "x5u": {
        "id": "JWT-X5U-001",
        "title": "External certificate URL detected",
        "invalid_title": "Invalid x5u URL",
        "resource": "X.509 certificate",
    },
}

KeyFetcher = Callable[[str], bytes]


@dataclass(frozen=True)
class HeaderAnalysisConfig:
    """Policy for header analysis.

    ``expected_key_type`` is ``symmetric`` or ``asymmetric`` when the caller
    knows which family the issuer should use. A symmetric ``alg`` on an
    asymmetric expectation is reported as a mismatch.

    ``assessment_mode`` does not fetch by itself. Fetching also requires
    ``key_fetcher`` and an HTTPS host listed in ``allowed_key_hosts``.
    """

    expected_key_type: Optional[str] = None
    expected_algorithms: frozenset[str] = field(default_factory=frozenset)
    assessment_mode: bool = False
    allowed_key_hosts: frozenset[str] = field(default_factory=frozenset)
    key_fetcher: Optional[KeyFetcher] = None
    max_kid_length: int = 256

    def __post_init__(self) -> None:
        if self.expected_key_type is not None:
            normalized = self.expected_key_type.strip().lower()
            if normalized not in {"symmetric", "asymmetric"}:
                raise ValueError(
                    "expected_key_type must be 'symmetric', 'asymmetric', or None"
                )
            object.__setattr__(self, "expected_key_type", normalized)
        if self.max_kid_length < 1:
            raise ValueError("max_kid_length must be positive")
        hosts = frozenset(host.strip().lower() for host in self.allowed_key_hosts)
        object.__setattr__(self, "allowed_key_hosts", hosts)


class HeaderCheck(ABC):
    """Strategy that inspects one aspect of a JOSE header."""

    @abstractmethod
    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        """Return findings for this check. Do not raise for weak headers."""


class AlgorithmCheck(HeaderCheck):
    """Section 6 and the ``alg`` portion of section 11."""

    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        if "alg" not in header or header["alg"] is None:
            return [_missing_alg("parameter is absent")]

        alg = header["alg"]
        if not isinstance(alg, str):
            return [
                _missing_alg(f"parameter type is {type(alg).__name__}, expected string")
            ]
        if alg.strip() == "":
            return [_missing_alg("parameter is empty")]

        stripped = alg.strip()
        if stripped.lower() == "none":
            return [_none_finding(alg)]

        findings: list[Finding] = []
        canonical = _CANONICAL_BY_FOLD.get(stripped.lower())
        if canonical is None:
            findings.append(_unrecognized_alg(alg))
            return findings

        if stripped != canonical:
            findings.append(_non_canonical_alg(alg, canonical))

        if canonical in _WEAK:
            findings.append(_weak_alg(alg, canonical))

        family = "symmetric" if canonical in _SYMMETRIC else "asymmetric"
        expected = config.expected_key_type
        if expected is not None and family != expected:
            findings.append(_family_mismatch(alg, family, expected))

        if config.expected_algorithms and stripped not in config.expected_algorithms:
            if canonical not in config.expected_algorithms:
                findings.append(_allowlist_mismatch(alg, config.expected_algorithms))

        return findings


class TypCheck(HeaderCheck):
    """Validate ``typ`` when it is present. Absence is allowed by RFC 7519."""

    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        del config  # typ rules are not configurable
        if "typ" not in header or header["typ"] is None:
            return []

        typ = header["typ"]
        if not isinstance(typ, str):
            return [
                Finding(
                    id="JWT-HDR-001",
                    title="Invalid typ parameter",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The typ header parameter must be a string when present.",
                    evidence=f"typ_type={type(typ).__name__}",
                    impact="Verifiers may mis-handle the token media type.",
                    remediation="Set typ to a string such as JWT or omit the parameter.",
                    references=(RFC_7519,),
                )
            ]
        if typ.strip() == "":
            return [
                Finding(
                    id="JWT-HDR-002",
                    title="Empty typ parameter",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The typ header parameter is present but empty.",
                    evidence="typ=",
                    impact="Consumers cannot confirm this object is a JWT.",
                    remediation="Set typ to JWT or remove the empty parameter.",
                    references=(RFC_7519,),
                )
            ]
        if typ not in _ACCEPTED_TYP:
            return [
                Finding(
                    id="JWT-HDR-002",
                    title="Unexpected typ value",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="The typ value is not a recognized JWT media type.",
                    evidence=f"typ={_preview(typ)}",
                    impact="The token may be intended for a different JOSE object type.",
                    remediation="Use JWT for JWTs or at+jwt for access tokens.",
                    references=(RFC_7519,),
                )
            ]
        return []


class KidCheck(HeaderCheck):
    """Section 12: detect dangerous ``kid`` values without using them."""

    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        if "kid" not in header or header["kid"] is None:
            return []

        kid = header["kid"]
        if not isinstance(kid, str):
            return [
                Finding(
                    id="JWT-KID-004",
                    title="Invalid kid parameter",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The kid header parameter must be a string.",
                    evidence=f"kid_type={type(kid).__name__}",
                    impact="Key lookup may coerce the value into an unexpected query or path.",
                    remediation="Set kid to the identifier of a known key.",
                    references=(RFC_7515,),
                )
            ]

        findings: list[Finding] = []
        if kid.strip() == "":
            findings.append(
                Finding(
                    id="JWT-KID-002",
                    title="Empty kid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The kid header parameter is empty.",
                    evidence="kid=",
                    impact="Key selection may fall back to a default or the first key.",
                    remediation="Omit kid or set it to a non-empty key identifier.",
                    references=(RFC_7515,),
                )
            )
            return findings

        if len(kid) > config.max_kid_length:
            findings.append(
                Finding(
                    id="JWT-KID-003",
                    title="Excessively long kid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="The kid value exceeds the configured maximum length.",
                    evidence=(
                        f"kid_length={len(kid)}; "
                        f"max_kid_length={config.max_kid_length}; "
                        f"kid={_preview(kid)}"
                    ),
                    impact="Oversized key identifiers can be abused as injection payloads.",
                    remediation="Use a short, opaque key identifier from the issuer.",
                    references=(RFC_7515,),
                )
            )

        categories = _kid_categories(kid)
        if categories:
            findings.append(
                Finding(
                    id="JWT-KID-001",
                    title="Suspicious characters detected in kid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        "The kid value contains characters associated with path traversal, "
                        "query injection, or unexpected encoding."
                    ),
                    evidence=(
                        f"categories={','.join(categories)}; kid={_preview(kid)}"
                    ),
                    impact=(
                        "If the verifier uses kid in a file path, SQL query, or command, "
                        "an attacker can influence which key is loaded."
                    ),
                    remediation=(
                        "Treat kid as an opaque identifier. Reject traversal, quotes, "
                        "comment markers, and encoded control characters before lookup."
                    ),
                    references=(RFC_7515, RFC_8725),
                )
            )
        return findings


class ExternalUriCheck(HeaderCheck):
    """Sections 13 and 14: inspect ``jku`` or ``x5u`` without fetching by default."""

    def __init__(self, parameter: str) -> None:
        if parameter not in _URI_COPY:
            raise ValueError("parameter must be 'jku' or 'x5u'")
        self.parameter = parameter

    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        if self.parameter not in header or header[self.parameter] is None:
            return []

        copy = _URI_COPY[self.parameter]
        value = header[self.parameter]
        if not isinstance(value, str):
            return [
                Finding(
                    id=copy["id"],
                    title=copy["invalid_title"],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"The {self.parameter} header parameter must be a URI string.",
                    evidence=f"{self.parameter}_type={type(value).__name__}; fetch=not_attempted; reason=invalid_value",
                    impact=f"The {_article_resource(copy['resource'])} location cannot be validated.",
                    remediation=f"Remove {self.parameter} or set it to an HTTPS URL.",
                    references=(RFC_7515, RFC_8725),
                )
            ]

        severity, issues, host, scheme = _classify_key_url(value)
        fetch = _fetch_status(value.strip(), host, scheme, issues, config)
        title = copy["title"] if "invalid_format" not in issues else copy["invalid_title"]
        shown = _redact_url(value.strip())
        return [
            Finding(
                id=copy["id"],
                title=title,
                severity=severity,
                confidence=Confidence.HIGH,
                description=(
                    f"The token declares an external {copy['resource']} via {self.parameter}. "
                    "Passive mode only inspects the URL."
                ),
                evidence=(
                    f"parameter={self.parameter}; url={shown}; scheme={scheme or '-'}; "
                    f"host={host or '-'}; issues={','.join(issues)}; {fetch}"
                ),
                impact=(
                    "An attacker who controls this header can point verification at "
                    "a key they generated, or expose the client to an unsafe URL."
                ),
                remediation=(
                    f"Do not trust {self.parameter} from the token. Pin keys locally "
                    "or allowlist the issuer's HTTPS host explicitly."
                ),
                references=(RFC_7515, RFC_8725),
            )
        ]


class KeySourceConsistencyCheck(HeaderCheck):
    """Warn when ``jku`` and ``x5u`` name different hosts."""

    def check(
        self,
        header: Mapping[str, Any],
        config: HeaderAnalysisConfig,
    ) -> list[Finding]:
        del config
        jku = header.get("jku")
        x5u = header.get("x5u")
        if not isinstance(jku, str) or not isinstance(x5u, str):
            return []
        jku_host = _hostname(jku)
        x5u_host = _hostname(x5u)
        if not jku_host or not x5u_host or jku_host == x5u_host:
            return []
        return [
            Finding(
                id="JWT-HDR-003",
                title="Inconsistent external key hosts",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="jku and x5u point at different hosts.",
                evidence=f"jku_host={jku_host}; x5u_host={x5u_host}",
                impact="Verification material is being pulled from more than one origin.",
                remediation="Publish JWKS and certificates on the same trusted host.",
                references=(RFC_7515,),
            )
        ]


class HeaderAnalyzer(BaseAnalyzer):
    """Run the header-analysis chain and collect its findings."""

    def __init__(
        self,
        config: Optional[HeaderAnalysisConfig] = None,
        checks: Optional[Sequence[HeaderCheck]] = None,
    ) -> None:
        self.config = config if config is not None else HeaderAnalysisConfig()
        self.checks: tuple[HeaderCheck, ...] = (
            tuple(checks) if checks is not None else _default_checks()
        )

    @property
    def name(self) -> str:
        return "header"

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        findings: list[Finding] = []
        for check in self.checks:
            findings.extend(check.check(token.header, self.config))
        return findings


def analyze_header(
    token: ParsedJWT,
    config: Optional[HeaderAnalysisConfig] = None,
) -> list[Finding]:
    """Analyze a parsed JWT header with the default check chain."""
    return HeaderAnalyzer(config).analyze(token)


def _default_checks() -> tuple[HeaderCheck, ...]:
    return (
        AlgorithmCheck(),
        TypCheck(),
        KidCheck(),
        ExternalUriCheck("jku"),
        ExternalUriCheck("x5u"),
        KeySourceConsistencyCheck(),
    )


def _missing_alg(detail: str) -> Finding:
    return Finding(
        id="JWT-ALG-002",
        title="Missing alg parameter",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="A JWT signature algorithm cannot be selected safely without alg.",
        evidence=f"alg={detail}",
        impact="Verifiers may fall back to an implicit or attacker-controlled algorithm.",
        remediation="Require a header alg from an explicit allowlist and reject tokens that omit it.",
        references=(RFC_7515, RFC_8725),
    )


def _none_finding(alg: str) -> Finding:
    return Finding(
        id="JWT-ALG-001",
        title='Algorithm "none" detected',
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="The token declares the unsecured JWS algorithm none, so the signature is not protecting integrity.",
        evidence=f"alg={_preview(alg)}",
        impact="Anyone can forge the payload if the verifier accepts alg none.",
        remediation="Reject alg none, including case variants. Allowlist the algorithms the issuer actually uses.",
        references=(
            "https://www.rfc-editor.org/rfc/rfc7518#section-3.6",
            "https://www.rfc-editor.org/rfc/rfc8725#section-3.2",
        ),
    )


def _weak_alg(alg: str, canonical: str) -> Finding:
    return Finding(
        id="JWT-ALG-004",
        title="Deprecated or weak algorithm detected",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=f"{canonical} uses SHA-1, which is deprecated for JWS signatures.",
        evidence=f"alg={_preview(alg)}; canonical={canonical}",
        impact="Collision attacks against SHA-1 can undermine signature guarantees.",
        remediation="Use a SHA-256 algorithm or stronger, such as RS256, ES256, or EdDSA.",
        references=(RFC_7518, RFC_8725),
    )


def _unrecognized_alg(alg: str) -> Finding:
    return Finding(
        id="JWT-ALG-005",
        title="Unrecognized algorithm",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="The alg value is not a registered JWS algorithm name known to this analyzer.",
        evidence=f"alg={_preview(alg)}",
        impact="An unknown algorithm may be unsupported, deprecated, or attacker-defined.",
        remediation="Allowlist registered algorithms and reject everything else.",
        references=(RFC_7518,),
    )


def _non_canonical_alg(alg: str, canonical: str) -> Finding:
    return Finding(
        id="JWT-ALG-006",
        title="Non-canonical algorithm name",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="JWS algorithm names are case-sensitive. This value only matches after case folding.",
        evidence=f"alg={_preview(alg)}; canonical={canonical}",
        impact="Some verifiers normalize case and can be steered into a different algorithm.",
        remediation=f"Emit the registered spelling {canonical} and reject other casings.",
        references=(RFC_7518,),
    )


def _family_mismatch(alg: str, family: str, expected: str) -> Finding:
    if expected == "asymmetric":
        title = "Symmetric algorithm used where an asymmetric algorithm was expected"
        impact = (
            "An attacker can switch a public-key token to HMAC and sign it with "
            "the public key treated as an HMAC secret."
        )
    else:
        title = "Asymmetric algorithm used where a symmetric algorithm was expected"
        impact = "The token is not using the symmetric algorithm this service is configured to accept."
    return Finding(
        id="JWT-ALG-003",
        title=title,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=f"Header alg is {family}, but the configured expectation is {expected}.",
        evidence=f"alg={_preview(alg)}; family={family}; expected={expected}",
        impact=impact,
        remediation="Ignore alg from the token and verify with the key type configured for the issuer.",
        references=(RFC_8725,),
    )


def _allowlist_mismatch(alg: str, allowed: frozenset[str]) -> Finding:
    rendered = ",".join(sorted(allowed))
    return Finding(
        id="JWT-ALG-007",
        title="Algorithm does not match the expected algorithm",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="The header alg is outside the caller's algorithm allowlist.",
        evidence=f"alg={_preview(alg)}; allowed={rendered}",
        impact="The token may have been re-signed with an algorithm the service did not intend to trust.",
        remediation="Verify using only the algorithms configured for this issuer.",
        references=(RFC_8725,),
    )


def _kid_categories(kid: str) -> list[str]:
    categories: list[str] = []
    if _PATH_TRAVERSAL_RE.search(kid):
        categories.append("path_traversal")
    if "\\" in kid:
        categories.append("suspicious_separator")
    if _SQL_META_RE.search(kid):
        categories.append("sql_metacharacter")
    if _SUSPICIOUS_ENCODING_RE.search(kid):
        categories.append("suspicious_encoding")
    return categories


def _classify_key_url(value: str) -> tuple[Severity, list[str], Optional[str], str]:
    """Return severity, issue tags, hostname, and scheme for a key URL."""
    raw = value.strip()
    if any(char.isspace() for char in raw):
        return Severity.MEDIUM, ["invalid_format"], None, ""

    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else None
    issues: list[str] = []

    if not scheme and not parsed.netloc:
        return Severity.MEDIUM, ["invalid_format"], None, ""

    if parsed.username or parsed.password:
        issues.append("embedded_credentials")
    if scheme == "https" and host:
        issues.append("external_source")
    elif scheme == "http":
        issues.append("cleartext_http")
        issues.append("external_source")
    elif scheme in _DANGEROUS_SCHEMES:
        issues.append("dangerous_scheme")
    elif scheme == "" and host:
        issues.append("missing_scheme")
        issues.append("external_source")
    elif not host:
        issues.append("invalid_format")
    else:
        issues.append("unexpected_scheme")
        issues.append("external_source")

    if "dangerous_scheme" in issues or "cleartext_http" in issues or "embedded_credentials" in issues:
        severity = Severity.HIGH
    elif "invalid_format" in issues or "missing_scheme" in issues or "unexpected_scheme" in issues:
        severity = Severity.MEDIUM
    else:
        severity = Severity.MEDIUM
    return severity, issues, host, scheme


def _fetch_status(
    url: str,
    host: Optional[str],
    scheme: str,
    issues: Sequence[str],
    config: HeaderAnalysisConfig,
) -> str:
    if "invalid_format" in issues:
        return "fetch=not_attempted; reason=invalid_url"
    if not config.assessment_mode:
        return "fetch=not_attempted; reason=passive_mode"
    if scheme != "https" or not host:
        return "fetch=blocked; reason=insecure_or_invalid_url"
    if "embedded_credentials" in issues:
        return "fetch=blocked; reason=url_credentials"
    if host not in config.allowed_key_hosts:
        return "fetch=blocked; reason=host_not_allowlisted"
    if config.key_fetcher is None:
        return "fetch=blocked; reason=no_fetcher"

    try:
        result = config.key_fetcher(url)
    except Exception as exc:
        return f"fetch=error; error_type={type(exc).__name__}"
    if not isinstance(result, (bytes, bytearray)):
        return "fetch=error; error_type=invalid_fetcher_result"
    return f"fetch=performed; bytes={len(result)}"


def _hostname(value: str) -> Optional[str]:
    parsed = urlsplit(value.strip())
    if parsed.hostname:
        return parsed.hostname.lower()
    return None


def _redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.username and not parts.password:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    user = parts.username or ""
    netloc = f"{user}:***@{host}" if user else f"***@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _preview(value: str, limit: int = 120) -> str:
    collapsed = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "...(truncated)"


def _article_resource(resource: str) -> str:
    return resource[:1].lower() + resource[1:]
