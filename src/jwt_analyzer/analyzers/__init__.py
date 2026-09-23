"""Security analyzers executed after the JWT parser."""

from jwt_analyzer.analyzers.crypto import CryptoAnalysisConfig, CryptoAnalyzer, SignatureStatus
from jwt_analyzer.analyzers.header import HeaderAnalysisConfig, HeaderAnalyzer
from jwt_analyzer.analyzers.jwks import JwksAnalysisConfig, JwksAnalyzer, load_jwks, match_token, parse_jwks
from jwt_analyzer.analyzers.oidc import (
    OidcAnalysisConfig,
    OidcTokenAnalyzer,
    TokenRole,
    discovery_url,
    load_oidc_provider,
)
from jwt_analyzer.analyzers.payload import PayloadAnalysisConfig, PayloadAnalyzer

__all__ = [
    "CryptoAnalysisConfig",
    "CryptoAnalyzer",
    "HeaderAnalysisConfig",
    "HeaderAnalyzer",
    "JwksAnalysisConfig",
    "JwksAnalyzer",
    "OidcAnalysisConfig",
    "OidcTokenAnalyzer",
    "PayloadAnalysisConfig",
    "PayloadAnalyzer",
    "SignatureStatus",
    "TokenRole",
    "discovery_url",
    "load_jwks",
    "load_oidc_provider",
    "match_token",
    "parse_jwks",
]
