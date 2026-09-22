"""JWT parser and compact JWS structure validation.

Implements the foundation of the analysis pipeline:

    Input -> Parser -> StructureCheck -> (later analyzers)

Malformed tokens raise ``JWTParseError`` so the chain of responsibility
stops before header/payload analyzers receive dirty data.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Union

from jwt_analyzer.exceptions import JWTParseError

REGISTERED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "nbf", "iat", "jti"})
JWS_SEGMENT_COUNT = 3
JWE_SEGMENT_COUNT = 5

# RFC 7515 base64url alphabet (padding is omitted in compact serialization).
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")

Audience = Union[str, list[str]]


@dataclass(frozen=True)
class JWTMetadata:
    """Standard header parameters and registered payload claims."""

    alg: Optional[str] = None
    typ: Optional[str] = None
    kid: Optional[str] = None
    cty: Optional[str] = None
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[Audience] = None
    exp: Optional[Union[int, float]] = None
    iat: Optional[Union[int, float]] = None
    nbf: Optional[Union[int, float]] = None
    jti: Optional[str] = None


@dataclass(frozen=True)
class ParsedJWT:
    """Decoded compact JWS JWT with extracted metadata and custom claims."""

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    header_segment: str
    payload_segment: str
    signature_segment: str
    metadata: JWTMetadata
    custom_claims: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the parsed token."""
        return {
            "header": self.header,
            "payload": self.payload,
            "signature": {
                "raw": self.signature_segment,
                "empty": len(self.signature) == 0,
                "byte_length": len(self.signature),
            },
            "metadata": {
                "alg": self.metadata.alg,
                "typ": self.metadata.typ,
                "kid": self.metadata.kid,
                "cty": self.metadata.cty,
                "iss": self.metadata.iss,
                "sub": self.metadata.sub,
                "aud": self.metadata.aud,
                "exp": self.metadata.exp,
                "iat": self.metadata.iat,
                "nbf": self.metadata.nbf,
                "jti": self.metadata.jti,
            },
            "custom_claims": self.custom_claims,
        }

    def to_readable(self) -> str:
        """Return human-readable metadata for CLI/decode output."""
        meta = self.metadata
        signature_state = "empty" if not self.signature else "present"
        lines = [
            "JWT Parser Result",
            "─────────────────",
            f"Type       : {_display(meta.typ)}",
            f"Algorithm  : {_display(meta.alg)}",
            f"Key ID     : {_display(meta.kid)}",
            f"Issuer     : {_display(meta.iss)}",
            f"Subject    : {_display(meta.sub)}",
            f"Audience   : {_display_aud(meta.aud)}",
            f"Expiration : {_display(meta.exp)}",
            f"Issued At  : {_display(meta.iat)}",
            f"Not Before : {_display(meta.nbf)}",
            f"JWT ID     : {_display(meta.jti)}",
            "Segments   : 3",
            f"Signature  : {signature_state}",
        ]
        if self.custom_claims:
            lines.append("Custom Claims:")
            for key, value in self.custom_claims.items():
                lines.append(f"  {key}: {value}")
        return "\n".join(lines)


class JWTParser:
    """Parse compact JWS JWTs and validate their structural integrity."""

    def parse(self, token: str) -> ParsedJWT:
        raw = self._normalize(token)
        header_b64, payload_b64, signature_b64 = self._split_segments(raw)

        header_bytes = decode_base64url(header_b64, "header")
        payload_bytes = decode_base64url(payload_b64, "payload")
        signature = decode_base64url(signature_b64, "signature")

        header = decode_json_object(header_bytes, "header")
        payload = decode_json_object(payload_bytes, "payload")

        return ParsedJWT(
            raw=raw,
            header=header,
            payload=payload,
            signature=signature,
            header_segment=header_b64,
            payload_segment=payload_b64,
            signature_segment=signature_b64,
            metadata=_extract_metadata(header, payload),
            custom_claims=_extract_custom_claims(payload),
        )

    def _normalize(self, token: Any) -> str:
        if token is None:
            raise JWTParseError("Token is empty", code="EMPTY_TOKEN")
        if not isinstance(token, str):
            raise JWTParseError(
                f"Token must be a string, got {type(token).__name__}",
                code="INVALID_TYPE",
            )
        raw = token.strip()
        if not raw:
            raise JWTParseError("Token is empty", code="EMPTY_TOKEN")
        return raw

    def _split_segments(self, token: str) -> tuple[str, str, str]:
        segments = token.split(".")
        count = len(segments)
        if count == JWE_SEGMENT_COUNT:
            raise JWTParseError(
                "JWE compact serialization is out of scope. "
                f"Expected {JWS_SEGMENT_COUNT} segments, found {count}",
                code="JWE_UNSUPPORTED",
            )
        if count != JWS_SEGMENT_COUNT:
            raise JWTParseError(
                f"Expected {JWS_SEGMENT_COUNT} segments, found {count}",
                code="INVALID_SEGMENT_COUNT",
            )
        return segments[0], segments[1], segments[2]


def parse_jwt(token: str) -> ParsedJWT:
    """Parse a compact JWS JWT using the default parser."""
    return JWTParser().parse(token)


def decode_base64url(segment: str, name: str) -> bytes:
    """Decode an RFC 7515 base64url segment, restoring omitted padding."""
    if not _B64URL_RE.fullmatch(segment):
        raise JWTParseError(
            f"Invalid base64url encoding in {name} segment",
            code="INVALID_BASE64URL",
        )

    remainder = len(segment) % 4
    if remainder == 1:
        raise JWTParseError(
            f"Invalid base64url encoding in {name} segment",
            code="INVALID_BASE64URL",
        )
    padded = segment + ("=" * ((4 - remainder) % 4))
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error) as exc:
        raise JWTParseError(
            f"Invalid base64url encoding in {name} segment",
            code="INVALID_BASE64URL",
        ) from exc


def decode_json_object(raw: bytes, name: str) -> dict[str, Any]:
    """Decode UTF-8 JSON and require a JSON object."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JWTParseError(
            f"{name.capitalize()} is not valid UTF-8",
            code="INVALID_UTF8",
        ) from exc

    if not text:
        raise JWTParseError(
            f"Invalid JSON in {name}: segment is empty",
            code="INVALID_JSON",
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JWTParseError(
            f"Invalid JSON in {name}: {exc.msg}",
            code="INVALID_JSON",
        ) from exc

    if not isinstance(data, dict):
        raise JWTParseError(
            f"{name.capitalize()} must be a JSON object",
            code="INVALID_JSON_TYPE",
        )
    return data


def _extract_metadata(
    header: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> JWTMetadata:
    return JWTMetadata(
        alg=_optional_str(header.get("alg")),
        typ=_optional_str(header.get("typ")),
        kid=_optional_str(header.get("kid")),
        cty=_optional_str(header.get("cty")),
        iss=_optional_str(payload.get("iss")),
        sub=_optional_str(payload.get("sub")),
        aud=_normalize_audience(payload.get("aud")),
        exp=_optional_number(payload.get("exp")),
        iat=_optional_number(payload.get("iat")),
        nbf=_optional_number(payload.get("nbf")),
        jti=_optional_str(payload.get("jti")),
    )


def _extract_custom_claims(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key not in REGISTERED_CLAIMS}


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _optional_number(value: Any) -> Optional[Union[int, float]]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def _normalize_audience(value: Any) -> Optional[Audience]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _display(value: Any) -> str:
    return "-" if value is None else str(value)


def _display_aud(value: Optional[Audience]) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(value) if value else "-"
    return value

