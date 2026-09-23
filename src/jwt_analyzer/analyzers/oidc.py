"""OIDC discovery and OAuth/OIDC token analysis.

Discovery fetches ``/.well-known/openid-configuration`` only when the
caller passes an issuer URL. Token checks are a strategy chain on the
decoded payload. They separate an ID token from an access token and
validate the OIDC claims ``nonce``, ``auth_time``, ``acr``, ``amr``,
and ``azp``.

When a discovery document is supplied, the token ``iss`` is compared
with the published issuer and ``alg`` is compared with
``id_token_signing_alg_values_supported``.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from jwt_analyzer.analyzers.base import BaseAnalyzer
from jwt_analyzer.exceptions import OidcError, RemoteFetchError
from jwt_analyzer.findings import Confidence, Finding, Severity
from jwt_analyzer.http_client import DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS, read_remote
from jwt_analyzer.parser import ParsedJWT

OIDC_DISCOVERY = "https://openid.net/specs/openid-connect-discovery-1_0.html"
OIDC_CORE = "https://openid.net/specs/openid-connect-core-1_0.html"
RFC_9068 = "https://www.rfc-editor.org/rfc/rfc9068"

_WELL_KNOWN = "/.well-known/openid-configuration"
_ID_MARKERS = ("nonce", "at_hash", "c_hash")
_ACCESS_MARKERS = ("scope", "scp", "client_id")
_SOFT_ID_MARKERS = ("auth_time", "acr", "amr")
_ID_REQUIRED = ("iss", "sub", "aud", "exp", "iat")
_ACCESS_TYP = frozenset({"at+jwt", "application/at+jwt"})


class TokenRole(str, Enum):
    """How the token presents itself to an OAuth/OIDC verifier."""

    ID_TOKEN = "id_token"
    ACCESS_TOKEN = "access_token"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OidcProvider:
    """OpenID Provider metadata that this stage inspects."""

    issuer: Optional[str]
    jwks_uri: Optional[str]
    id_token_signing_algs: tuple[str, ...]
    response_types: tuple[str, ...]
    grant_types: tuple[str, ...]
    scopes: tuple[str, ...]
    claims: tuple[str, ...]
    requested_issuer: str
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class OidcTokenReport:
    """Role, passed checks, and findings for one OAuth/OIDC token."""

    role: TokenRole
    passed: tuple[str, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class OidcAnalysisConfig:
    """Optional provider metadata and audience expectation.

    ``discovery`` is already-parsed metadata. This stage does not fetch
    it. ``require_nonce`` raises a missing ID-token nonce from low to medium.
    """

    discovery: Optional[OidcProvider] = None
    expected_audience: Optional[str] = None
    require_nonce: bool = False


class OidcCheck(ABC):
    """Strategy that inspects one OAuth/OIDC aspect of a token."""

    @abstractmethod
    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        """Return findings. Do not raise for a weak claim."""


class TokenRoleCheck(OidcCheck):
    """Report a token that carries both ID-token and access-token signals."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        role, conflict = classify_token(token)
        if not conflict:
            return []
        return [
            _finding(
                "JWT-OIDC-021",
                "Conflicting token role signals",
                Severity.MEDIUM,
                "The token carries both access-token and ID-token markers.",
                f"role={role.value}; typ={_typ(token) or '-'}",
                "A resource server and a client may treat the token as different credentials.",
                "Issue ID tokens and access tokens separately, and set typ to at+jwt for access tokens.",
                references=(OIDC_CORE, RFC_9068),
            )
        ]


class IdTokenClaimCheck(OidcCheck):
    """Require the ID Token claims defined by OpenID Connect Core."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        role, _conflict = classify_token(token)
        if role is not TokenRole.ID_TOKEN:
            return []
        findings: list[Finding] = []
        for claim in _ID_REQUIRED:
            if _claim_satisfied(token.payload, claim):
                continue
            findings.append(
                _finding(
                    "JWT-OIDC-020",
                    "ID token is missing a required claim",
                    Severity.HIGH if claim == "exp" else Severity.MEDIUM,
                    f"An ID Token must include {claim}.",
                    f"claim={claim}; role=id_token",
                    "The client cannot validate who issued the token or when it expires.",
                    f"Configure the provider to include {claim} on ID tokens.",
                )
            )
        return findings


class AccessTokenTypCheck(OidcCheck):
    """RFC 9068 asks access tokens that are JWTs to use typ at+jwt."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        role, _conflict = classify_token(token)
        if role is not TokenRole.ACCESS_TOKEN:
            return []
        if _typ(token) in _ACCESS_TYP:
            return []
        return [
            _finding(
                "JWT-OIDC-019",
                "Access token typ is not at+jwt",
                Severity.LOW,
                "A JWT access token should declare typ at+jwt so it is not accepted as an ID token.",
                f"typ={_typ(token) or '-'}; role=access_token",
                "A client may confuse this access token with an ID token.",
                "Set the header typ to at+jwt for JWT access tokens.",
                references=(RFC_9068,),
            )
        ]


class AudienceCheck(OidcCheck):
    """Warn on multiple audiences and enforce azp membership."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        payload = token.payload
        findings: list[Finding] = []
        audiences = _audiences(payload.get("aud"))
        role, _conflict = classify_token(token)
        if isinstance(payload.get("aud"), list) and len(audiences) > 1:
            findings.append(
                _finding(
                    "JWT-OIDC-011",
                    "Multiple audiences detected",
                    Severity.MEDIUM,
                    "The aud claim lists more than one audience.",
                    f"audiences={len(audiences)}; role={role.value}",
                    "A token accepted by several audiences is useful in more places if it is stolen.",
                    "Prefer a single audience. When several are required, require azp and check it.",
                )
            )
            if role is TokenRole.ID_TOKEN and not _present(payload, "azp"):
                findings.append(
                    _finding(
                        "JWT-OIDC-012",
                        "azp is required when the ID token has multiple audiences",
                        Severity.MEDIUM,
                        "OpenID Connect requires azp when an ID Token aud contains more than one value.",
                        f"audiences={len(audiences)}; claim=azp",
                        "The client cannot tell which party the token was issued for.",
                        "Set azp to the client id that requested the token and require it when aud is an array.",
                    )
                )
        azp = payload.get("azp")
        if "azp" in payload and azp is not None:
            if not isinstance(azp, str) or not azp.strip():
                findings.append(
                    _finding(
                        "JWT-OIDC-024",
                        "Invalid azp",
                        Severity.MEDIUM,
                        "azp must be a non-empty string.",
                        f"azp_type={type(azp).__name__}",
                        "The authorized party cannot be checked against the audience.",
                        "Set azp to the client identifier string.",
                    )
                )
            elif audiences and azp not in audiences:
                findings.append(
                    _finding(
                        "JWT-OIDC-013",
                        "azp is not a member of aud",
                        Severity.HIGH,
                        "The authorized party is not one of the token audiences.",
                        "claim=azp; member_of_aud=false",
                        "The token names a client that is not allowed to use it.",
                        "Set azp to a value that is also present in aud.",
                    )
                )
        expected = config.expected_audience
        if expected and audiences and expected not in audiences:
            findings.append(
                _finding(
                    "JWT-OIDC-025",
                    "Audience does not match",
                    Severity.HIGH,
                    "aud does not contain the audience configured for this check.",
                    "claim=aud; match=false",
                    "The token was issued for a different recipient.",
                    "Reject tokens whose aud does not contain this resource or client.",
                )
            )
        return findings


class NonceCheck(OidcCheck):
    """Validate ``nonce`` and note when an ID token omits it."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        role, _conflict = classify_token(token)
        payload = token.payload
        if "nonce" not in payload or payload.get("nonce") is None:
            if role is TokenRole.ID_TOKEN:
                severity = Severity.MEDIUM if config.require_nonce else Severity.LOW
                return [
                    _finding(
                        "JWT-OIDC-015",
                        "ID token has no nonce",
                        severity,
                        "ID tokens should echo the nonce from the authentication request when one was sent.",
                        "claim=nonce; role=id_token",
                        "Without a nonce, a stolen ID token can be replayed in another login.",
                        "Send nonce on the authentication request and reject ID tokens that omit it.",
                    )
                ]
            return []
        nonce = payload.get("nonce")
        if isinstance(nonce, str) and nonce.strip():
            return []
        return [
            _finding(
                "JWT-OIDC-014",
                "Invalid nonce",
                Severity.MEDIUM,
                "nonce must be a non-empty string when it is present.",
                f"nonce_type={type(nonce).__name__}",
                "The login transaction cannot be bound to this token.",
                "Copy the authentication-request nonce into the ID token as a string.",
            )
        ]


class AuthTimeCheck(OidcCheck):
    """Require ``auth_time`` to be a numeric date when it is present."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        if "auth_time" not in token.payload or token.payload.get("auth_time") is None:
            return []
        if _numeric(token.payload.get("auth_time")) is None:
            return [
                _finding(
                    "JWT-OIDC-016",
                    "Invalid auth_time",
                    Severity.MEDIUM,
                    "auth_time must be a NumericDate.",
                    f"auth_time_type={type(token.payload.get('auth_time')).__name__}",
                    "The client cannot tell when the user actually authenticated.",
                    "Set auth_time to the number of seconds since the Unix epoch.",
                )
            ]
        return []


class AcrCheck(OidcCheck):
    """Require ``acr`` to be a non-empty string when it is present."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        if "acr" not in token.payload or token.payload.get("acr") is None:
            return []
        acr = token.payload.get("acr")
        if isinstance(acr, str) and acr.strip():
            return []
        return [
            _finding(
                "JWT-OIDC-017",
                "Invalid acr",
                Severity.MEDIUM,
                "acr must be a non-empty string when it is present.",
                f"acr_type={type(acr).__name__}",
                "The authentication context cannot be evaluated.",
                "Set acr to the authentication context class reference agreed with the client.",
            )
        ]


class AmrCheck(OidcCheck):
    """Require ``amr`` to be an array of non-empty strings when it is present."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        if "amr" not in token.payload or token.payload.get("amr") is None:
            return []
        amr = token.payload.get("amr")
        valid = isinstance(amr, list) and bool(amr) and all(isinstance(item, str) and item.strip() for item in amr)
        if valid:
            return []
        return [
            _finding(
                "JWT-OIDC-018",
                "Invalid amr",
                Severity.MEDIUM,
                "amr must be an array of non-empty strings.",
                f"amr_type={type(amr).__name__}",
                "The authentication methods used for this login cannot be read safely.",
                "Publish amr as an array of method reference strings.",
            )
        ]


class ScopeCheck(OidcCheck):
    """Require the OAuth ``scope`` claim to be a string when it is present."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        del config
        if "scope" not in token.payload or token.payload.get("scope") is None:
            return []
        scope = token.payload.get("scope")
        if isinstance(scope, str):
            return []
        return [
            _finding(
                "JWT-OIDC-022",
                "Invalid scope",
                Severity.MEDIUM,
                "The scope claim must be a space-delimited string.",
                f"scope_type={type(scope).__name__}",
                "Resource servers may ignore the scope or grant the wrong one.",
                "Encode scope as a single string of space-separated scope tokens.",
            )
        ]


class DiscoveryConsistencyCheck(OidcCheck):
    """Compare the token with OpenID Provider metadata when it was loaded."""

    def check(self, token: ParsedJWT, config: OidcAnalysisConfig) -> list[Finding]:
        provider = config.discovery
        if provider is None:
            return []
        findings: list[Finding] = []
        iss = token.payload.get("iss")
        if isinstance(iss, str) and provider.issuer and iss != provider.issuer:
            findings.append(
                _finding(
                    "JWT-OIDC-008",
                    "Token issuer does not match the OpenID Provider",
                    Severity.HIGH,
                    "The iss claim must be identical to the issuer in the discovery document.",
                    f"claim=iss; match=false; token_iss={_preview(iss)}; provider_iss={_preview(provider.issuer)}",
                    "The token may come from a different provider than the one that was queried.",
                    "Reject tokens whose iss is not an exact match for the discovery issuer.",
                    references=(OIDC_CORE, OIDC_DISCOVERY),
                )
            )
        alg = token.header.get("alg")
        supported = provider.id_token_signing_algs
        if isinstance(alg, str) and supported and alg not in supported:
            rendered = ",".join(supported)
            findings.append(
                _finding(
                    "JWT-OIDC-009",
                    "Token algorithm is not advertised by the provider",
                    Severity.HIGH,
                    "alg is outside id_token_signing_alg_values_supported.",
                    f"alg={alg}; supported={rendered}",
                    "The token may have been signed with an algorithm the provider did not agree to.",
                    "Accept only the signing algorithms published in the discovery document.",
                    references=(OIDC_DISCOVERY,),
                )
            )
        return findings


class OidcTokenAnalyzer(BaseAnalyzer):
    """Classify an OAuth/OIDC token and validate its specific claims."""

    def __init__(
        self,
        config: Optional[OidcAnalysisConfig] = None,
        checks: Optional[Sequence[OidcCheck]] = None,
    ) -> None:
        self.config = config if config is not None else OidcAnalysisConfig()
        self.checks: tuple[OidcCheck, ...] = tuple(checks) if checks is not None else _default_checks()

    @property
    def name(self) -> str:
        return "oidc"

    def analyze(self, token: ParsedJWT) -> list[Finding]:
        return list(self.inspect(token).findings)

    def inspect(self, token: ParsedJWT) -> OidcTokenReport:
        """Run the OIDC claim chain and record which checks passed."""
        findings: list[Finding] = []
        for check in self.checks:
            findings.extend(check.check(token, self.config))
        role, _conflict = classify_token(token)
        frozen = tuple(findings)
        return OidcTokenReport(role=role, passed=passed_checks(token, role, frozen), findings=frozen)


def discovery_url(issuer: str) -> str:
    """Return the OpenID Connect discovery URL for an issuer identifier."""
    text = issuer.strip() if isinstance(issuer, str) else ""
    if not text:
        raise OidcError("Issuer URL is empty", code="EMPTY_ISSUER")
    trimmed = text[:-1] if text.endswith("/") else text
    if trimmed.endswith(_WELL_KNOWN):
        target = trimmed
    else:
        parts = urlsplit(trimmed)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise OidcError("Issuer must be an HTTP(S) URL", code="INVALID_ISSUER")
        if parts.username or parts.password:
            raise OidcError("Issuer URL must not contain credentials", code="INVALID_ISSUER")
        target = trimmed + _WELL_KNOWN
    return target


def load_oidc_provider(
    issuer: str,
    *,
    fetcher: Optional[Callable[[str], bytes]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> OidcProvider:
    """Fetch and parse ``/.well-known/openid-configuration`` for ``issuer``."""
    url = discovery_url(issuer)
    try:
        data = read_remote(url, fetcher=fetcher, timeout=timeout, max_bytes=max_bytes)
    except RemoteFetchError as exc:
        raise OidcError(exc.message, code=exc.code) from exc
    return parse_oidc_provider(data, requested_issuer=normalize_issuer(issuer))


def parse_oidc_provider(data: bytes, *, requested_issuer: str) -> OidcProvider:
    """Parse discovery JSON and evaluate the provider configuration."""
    parsed = _load_json_object(data)
    findings: list[Finding] = []
    issuer = _metadata_string(parsed, "issuer", findings)
    jwks_uri = _metadata_string(parsed, "jwks_uri", findings)
    algs = _string_list(parsed, "id_token_signing_alg_values_supported", findings)
    provider = OidcProvider(
        issuer=issuer,
        jwks_uri=jwks_uri,
        id_token_signing_algs=algs,
        response_types=_string_list(parsed, "response_types_supported", findings),
        grant_types=_string_list(parsed, "grant_types_supported", findings),
        scopes=_string_list(parsed, "scopes_supported", findings),
        claims=_string_list(parsed, "claims_supported", findings),
        requested_issuer=requested_issuer,
        findings=(),
    )
    findings.extend(_provider_findings(provider, findings))
    return OidcProvider(
        issuer=provider.issuer,
        jwks_uri=provider.jwks_uri,
        id_token_signing_algs=provider.id_token_signing_algs,
        response_types=provider.response_types,
        grant_types=provider.grant_types,
        scopes=provider.scopes,
        claims=provider.claims,
        requested_issuer=provider.requested_issuer,
        findings=tuple(findings),
    )


def normalize_issuer(issuer: str) -> str:
    """Strip a trailing slash and a discovery suffix from a user-supplied issuer."""
    text = issuer.strip()
    if text.endswith("/"):
        text = text[:-1]
    if text.endswith(_WELL_KNOWN):
        text = text[: -len(_WELL_KNOWN)]
    if text.endswith("/"):
        text = text[:-1]
    return text


def classify_token(token: ParsedJWT) -> tuple[TokenRole, bool]:
    """Return the token role and whether ID-token and access-token signals conflict."""
    payload = token.payload
    access_typ = _typ(token) in _ACCESS_TYP
    id_claims = _marker_names(payload, _ID_MARKERS)
    access_claims = _marker_names(payload, _ACCESS_MARKERS)
    soft_id = _marker_names(payload, _SOFT_ID_MARKERS)
    conflict = bool((access_typ and id_claims) or (id_claims and access_claims))
    if access_typ and not id_claims:
        return TokenRole.ACCESS_TOKEN, conflict
    if id_claims:
        return TokenRole.ID_TOKEN, conflict
    if access_typ:
        return TokenRole.ACCESS_TOKEN, conflict
    if soft_id and not access_claims:
        return TokenRole.ID_TOKEN, False
    if access_claims:
        return TokenRole.ACCESS_TOKEN, bool(soft_id)
    return TokenRole.UNKNOWN, False


def passed_checks(token: ParsedJWT, role: TokenRole, findings: Sequence[Finding]) -> tuple[str, ...]:
    """Return the labels the text report can mark as passed."""
    payload = token.payload
    blocked = {item.id for item in findings}
    labels: list[str] = []
    iss = payload.get("iss")
    if isinstance(iss, str) and iss.strip() and "JWT-OIDC-008" not in blocked and "JWT-OIDC-020" not in _ids_for_claim(findings, "iss"):
        labels.append("issuer")
    audiences = _audiences(payload.get("aud"))
    audience_ok = bool(audiences) and all(item.strip() for item in audiences) and "JWT-OIDC-025" not in blocked
    if audience_ok and "JWT-OIDC-020" not in _ids_for_claim(findings, "aud"):
        labels.append("audience")
    if _numeric(payload.get("exp")) is not None and "JWT-OIDC-020" not in _ids_for_claim(findings, "exp"):
        labels.append("expiration")
    nonce = payload.get("nonce")
    if isinstance(nonce, str) and nonce.strip() and "JWT-OIDC-014" not in blocked:
        labels.append("nonce")
    if _numeric(payload.get("auth_time")) is not None and "JWT-OIDC-016" not in blocked:
        labels.append("auth_time")
    acr = payload.get("acr")
    if isinstance(acr, str) and acr.strip() and "JWT-OIDC-017" not in blocked:
        labels.append("acr")
    amr = payload.get("amr")
    if (
        isinstance(amr, list)
        and amr
        and all(isinstance(item, str) and item.strip() for item in amr)
        and "JWT-OIDC-018" not in blocked
    ):
        labels.append("amr")
    azp = payload.get("azp")
    if isinstance(azp, str) and azp.strip() and "JWT-OIDC-013" not in blocked and "JWT-OIDC-024" not in blocked:
        if not audiences or azp in audiences:
            labels.append("azp")
    scope = payload.get("scope")
    if isinstance(scope, str) and scope.strip() and "JWT-OIDC-022" not in blocked and role is TokenRole.ACCESS_TOKEN:
        labels.append("scope")
    return tuple(labels)


def format_oidc_discovery(provider: OidcProvider) -> str:
    """Render provider metadata and configuration findings."""
    lines = [
        "OIDC Discovery",
        "──────────────────────",
        f"issuer : {provider.issuer or '-'}",
        f"jwks_uri : {provider.jwks_uri or '-'}",
        f"id_token_signing_alg_values_supported : {_join(provider.id_token_signing_algs)}",
        f"response_types_supported : {_join(provider.response_types)}",
        f"grant_types_supported : {_join(provider.grant_types)}",
        f"scopes_supported : {_join(provider.scopes)}",
        f"claims_supported : {_join(provider.claims)}",
    ]
    if provider.findings:
        lines.append("")
        lines.append("Findings")
        lines.append("──────────────────────")
        for item in provider.findings:
            lines.append(f"[{item.severity.value}] {item.id} {item.title}")
            lines.append(item.evidence)
    else:
        lines.append("")
        lines.append("Findings : none")
    return "\n".join(lines)


def format_oidc_token(report: OidcTokenReport) -> str:
    """Render the token role, passed checks, and warnings."""
    lines = [
        "OIDC Analysis",
        "────────────────────────",
        "",
        f"Role : {_role_label(report.role)}",
        "",
    ]
    if report.passed:
        for label in report.passed:
            lines.append(f"[✓] {label}")
    else:
        lines.append("(no passed checks)")
    warnings = [item for item in report.findings if item.severity is not Severity.INFO]
    if warnings:
        lines.append("")
        for item in warnings:
            prefix = "[WARNING]" if item.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} else "[LOW]"
            lines.append(f"{prefix} {item.title}")
    return "\n".join(lines)


def _default_checks() -> tuple[OidcCheck, ...]:
    return (
        TokenRoleCheck(),
        IdTokenClaimCheck(),
        AccessTokenTypCheck(),
        AudienceCheck(),
        NonceCheck(),
        AuthTimeCheck(),
        AcrCheck(),
        AmrCheck(),
        ScopeCheck(),
        DiscoveryConsistencyCheck(),
    )


def _provider_findings(provider: OidcProvider, preliminary: Sequence[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    if not provider.issuer:
        if not _type_error(preliminary, "issuer"):
            findings.append(
                _finding(
                    "JWT-OIDC-001",
                    "Discovery document has no issuer",
                    Severity.HIGH,
                    "OpenID Connect discovery must publish an issuer identifier.",
                    "field=issuer",
                    "Tokens cannot be checked against a provider identity.",
                    "Publish the issuer URL in the discovery document.",
                    references=(OIDC_DISCOVERY,),
                )
            )
    else:
        parts = urlsplit(provider.issuer)
        if parts.query or parts.fragment:
            findings.append(
                _finding(
                    "JWT-OIDC-032",
                    "Issuer identifier contains a query or fragment",
                    Severity.HIGH,
                    "An issuer identifier must be a URL without a query or fragment.",
                    "field=issuer",
                    "Exact issuer comparison with iss becomes ambiguous.",
                    "Publish the issuer without a query string or fragment.",
                    references=(OIDC_DISCOVERY,),
                )
            )
        if parts.scheme.lower() != "https":
            findings.append(
                _finding(
                    "JWT-OIDC-033",
                    "Issuer identifier is not HTTPS",
                    Severity.MEDIUM,
                    "The published issuer does not use HTTPS.",
                    f"scheme={parts.scheme or '-'}",
                    "Clients may accept provider metadata that was not authenticated in transit.",
                    "Serve the issuer and its discovery document over HTTPS.",
                    references=(OIDC_DISCOVERY,),
                )
            )
        if provider.issuer.endswith("/"):
            findings.append(
                _finding(
                    "JWT-OIDC-031",
                    "Issuer identifier has a trailing slash",
                    Severity.LOW,
                    "The published issuer has a trailing slash. iss comparison is exact.",
                    "field=issuer",
                    "A token whose iss omits the slash will not match this provider.",
                    "Publish the issuer without a trailing slash.",
                    references=(OIDC_CORE,),
                )
            )
        if provider.requested_issuer and provider.issuer.rstrip("/") != provider.requested_issuer.rstrip("/"):
            findings.append(
                _finding(
                    "JWT-OIDC-002",
                    "Discovery issuer does not match the requested URL",
                    Severity.HIGH,
                    "The issuer in the document is not the issuer that was requested.",
                    f"field=issuer; match=false; published={_preview(provider.issuer)}; requested={_preview(provider.requested_issuer)}",
                    "The discovery document may belong to a different provider.",
                    "Request discovery from the issuer that appears in the token iss claim.",
                    references=(OIDC_DISCOVERY,),
                )
            )
    if not provider.jwks_uri and not _type_error(preliminary, "jwks_uri"):
        findings.append(
            _finding(
                "JWT-OIDC-003",
                "Discovery document has no jwks_uri",
                Severity.HIGH,
                "The provider did not publish a JWKS endpoint.",
                "field=jwks_uri",
                "Signature keys cannot be discovered from this document.",
                "Publish jwks_uri as an HTTPS URL.",
                references=(OIDC_DISCOVERY,),
            )
        )
    else:
        jwks_parts = urlsplit(provider.jwks_uri)
        if jwks_parts.scheme.lower() == "http":
            findings.append(
                _finding(
                    "JWT-OIDC-004",
                    "jwks_uri uses cleartext HTTP",
                    Severity.HIGH,
                    "The provider publishes its keys over HTTP.",
                    f"jwks_uri_scheme=http",
                    "A network attacker can replace the verification keys.",
                    "Set jwks_uri to an HTTPS URL.",
                    references=(OIDC_DISCOVERY,),
                )
            )
        elif jwks_parts.scheme.lower() != "https" or not jwks_parts.hostname:
            findings.append(
                _finding(
                    "JWT-OIDC-004",
                    "jwks_uri is not an HTTPS URL",
                    Severity.HIGH,
                    "jwks_uri must be an absolute HTTPS URL.",
                    f"jwks_uri_scheme={jwks_parts.scheme or '-'}",
                    "The key endpoint cannot be fetched safely.",
                    "Set jwks_uri to an absolute HTTPS URL.",
                    references=(OIDC_DISCOVERY,),
                )
            )
        issuer_host = urlsplit(provider.issuer).hostname if provider.issuer else None
        jwks_host = jwks_parts.hostname
        if issuer_host and jwks_host and issuer_host.lower() != jwks_host.lower():
            findings.append(
                _finding(
                    "JWT-OIDC-005",
                    "jwks_uri host differs from the issuer",
                    Severity.MEDIUM,
                    "Signing keys are published on a different host than the issuer.",
                    f"issuer_host={issuer_host.lower()}; jwks_host={jwks_host.lower()}",
                    "Key material is being taken from a second origin.",
                    "Serve the JWKS on the issuer host, or document why the hosts differ.",
                    references=(OIDC_DISCOVERY,),
                )
            )
    if not provider.id_token_signing_algs and not _type_error(preliminary, "id_token_signing_alg_values_supported"):
        findings.append(
            _finding(
                "JWT-OIDC-006",
                "No ID token signing algorithms advertised",
                Severity.MEDIUM,
                "id_token_signing_alg_values_supported is absent or empty.",
                "field=id_token_signing_alg_values_supported",
                "Clients cannot tell which signature algorithms the provider will use.",
                "Publish the signing algorithms the provider actually uses.",
                references=(OIDC_DISCOVERY,),
            )
        )
    elif any(alg.lower() == "none" for alg in provider.id_token_signing_algs):
        findings.append(
            _finding(
                "JWT-OIDC-007",
                'Provider advertises algorithm "none"',
                Severity.HIGH,
                "The discovery document lists none as an ID token signing algorithm.",
                "field=id_token_signing_alg_values_supported; alg=none",
                "Clients that trust this list may accept unsigned ID tokens.",
                "Remove none from the advertised signing algorithms.",
                references=(OIDC_DISCOVERY,),
            )
        )
    return findings


def _metadata_string(data: Mapping[str, Any], field_name: str, findings: list[Finding]) -> Optional[str]:
    if field_name not in data or data.get(field_name) is None:
        return None
    value = data.get(field_name)
    if isinstance(value, str) and value.strip():
        return value
    findings.append(
        _finding(
            "JWT-OIDC-030",
            "Invalid discovery metadata type",
            Severity.MEDIUM,
            f"{field_name} must be a non-empty string.",
            f"field={field_name}; value_type={type(value).__name__}",
            "The provider field cannot be compared or fetched.",
            f"Publish {field_name} as a string.",
            references=(OIDC_DISCOVERY,),
        )
    )
    return None


def _string_list(data: Mapping[str, Any], field_name: str, findings: list[Finding]) -> tuple[str, ...]:
    if field_name not in data or data.get(field_name) is None:
        return ()
    value = data.get(field_name)
    if not isinstance(value, list):
        findings.append(
            _finding(
                "JWT-OIDC-030",
                "Invalid discovery metadata type",
                Severity.MEDIUM,
                f"{field_name} must be an array of strings.",
                f"field={field_name}; value_type={type(value).__name__}",
                "The provider field cannot be used as an allowlist.",
                f"Publish {field_name} as an array of strings.",
                references=(OIDC_DISCOVERY,),
            )
        )
        return ()
    clean = tuple(item for item in value if isinstance(item, str) and item.strip())
    if len(clean) != len(value):
        findings.append(
            _finding(
                "JWT-OIDC-030",
                "Invalid discovery metadata type",
                Severity.MEDIUM,
                f"Every value in {field_name} must be a non-empty string.",
                f"field={field_name}",
                "Part of the provider allowlist was ignored.",
                f"Publish {field_name} as an array of strings.",
                references=(OIDC_DISCOVERY,),
            )
        )
    return clean


def _ids_for_claim(findings: Sequence[Finding], claim: str) -> set[str]:
    return {item.id for item in findings if f"claim={claim}" in item.evidence}


def _audiences(value: Any) -> tuple[str, ...]:
    if isinstance(value, str) and value.strip():
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _marker_names(payload: Mapping[str, Any], names: Sequence[str]) -> tuple[str, ...]:
    return tuple(name for name in names if name in payload and payload.get(name) is not None)


def _typ(token: ParsedJWT) -> str:
    typ = token.header.get("typ")
    if not isinstance(typ, str):
        return ""
    return typ.strip().lower()


def _claim_satisfied(payload: Mapping[str, Any], claim: str) -> bool:
    if not _present(payload, claim):
        return False
    value = payload.get(claim)
    if claim in {"iss", "sub"}:
        return isinstance(value, str) and bool(value.strip())
    if claim == "aud":
        audiences = _audiences(value)
        return bool(audiences) and all(item.strip() for item in audiences)
    if claim in {"exp", "iat"}:
        return _numeric(value) is not None
    return True


def _type_error(findings: Sequence[Finding], field_name: str) -> bool:
    return any(item.id == "JWT-OIDC-030" and f"field={field_name}" in item.evidence for item in findings)


def _preview(value: Any, limit: int = 120) -> str:
    text = value if isinstance(value, str) else repr(value)
    collapsed = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "...(truncated)"


def _present(payload: Mapping[str, Any], claim: str) -> bool:
    return claim in payload and payload.get(claim) is not None


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "-"


def _role_label(role: TokenRole) -> str:
    labels = {
        TokenRole.ID_TOKEN: "ID Token",
        TokenRole.ACCESS_TOKEN: "Access Token",
        TokenRole.UNKNOWN: "Unclassified",
    }
    return labels[role]


def _load_json_object(data: bytes) -> dict[str, Any]:
    if not data:
        raise OidcError("Discovery document is empty", code="INVALID_OIDC")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise OidcError("Discovery document is not valid UTF-8", code="INVALID_OIDC") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise OidcError(f"Discovery document is not valid JSON: {exc.msg}", code="INVALID_OIDC") from exc
    if not isinstance(parsed, dict):
        raise OidcError("Discovery document must be a JSON object", code="INVALID_OIDC")
    return parsed


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: tuple[str, ...] = (OIDC_CORE,),
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
